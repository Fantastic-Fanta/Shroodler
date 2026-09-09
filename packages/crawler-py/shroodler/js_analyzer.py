"""Harvest attack surface from JavaScript bundles the HTML crawler collected.

Regex-only: fetch/axios/XHR/ajax URLs, hardcoded secrets, client-side JWT
decode, GraphQL operation names, and sourceMappingURL recovery. Mutates
ProgramState (endpoints, extra_graphql_operations, source_map_urls) and
returns findings for the agent to merge. Never stores full secret values.
"""

from __future__ import annotations

import math
import re
from urllib.parse import urljoin

from shroodler import program
from shroodler.extractors.sourcemap import (
    decode_data_url,
    parse_source_map,
    source_mapping_url,
)
from shroodler.models import Finding
from shroodler.program import ProgramState

_TEMPLATE_INTERP = re.compile(r"\$\{[^}]*\}")

_FETCH_URL = re.compile(
    r"""\bfetch\s*\(\s*(?:'([^']*)'|"([^"]*)"|`([^`]*)`)""",
    re.I,
)
_AXIOS_METHOD_URL = re.compile(
    r"""\baxios\s*\.\s*(?:get|post|put|patch|delete|head|options)\s*\(\s*(?:'([^']*)'|"([^"]*)"|`([^`]*)`)""",
    re.I,
)
_AXIOS_BARE_URL = re.compile(
    r"""\baxios\s*\(\s*(?:'([^']*)'|"([^"]*)"|`([^`]*)`)""",
    re.I,
)
_AXIOS_OBJ_URL = re.compile(
    r"""\baxios\s*\(\s*\{[^}]{0,800}?url\s*:\s*(?:'([^']*)'|"([^"]*)"|`([^`]*)`)""",
    re.I | re.S,
)
_AJAX_BARE_URL = re.compile(
    r"""\$\.ajax\s*\(\s*(?:'([^']*)'|"([^"]*)"|`([^`]*)`)""",
    re.I,
)
_AJAX_OBJ_URL = re.compile(
    r"""\$\.ajax\s*\(\s*\{[^}]{0,800}?url\s*:\s*(?:'([^']*)'|"([^"]*)"|`([^`]*)`)""",
    re.I | re.S,
)
_XHR_OPEN_URL = re.compile(
    r"""\.open\s*\(\s*['"]\w+['"]\s*,\s*(?:'([^']*)'|"([^"]*)"|`([^`]*)`)""",
    re.I,
)
_CONCAT = re.compile(
    r"""(['"])(https?://[^'"]+|/(?!/)[^'"]*)\1((?:\s*\+\s*(?:['"][^'"]*['"]|[A-Za-z_$][\w$]*))+)"""
)
_CONCAT_LIT = re.compile(r"""\+\s*(?:(['"])(.*?)\1|([A-Za-z_$][\w$]*))""")

_SECRET_ASSIGN = re.compile(
    r"(apikey|api_key|secret|token|password|passwd|auth|bearer|"
    r"private_key|access_key|client_secret|app_secret)\s*[:=]\s*['\"`]([^'\"`\s]{8,})['\"`]",
    re.I,
)
_AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")

_SECRET_BLOCKLIST = {
    "construction",
    "unstable",
    "undefined",
    "development",
    "production",
    "application",
    "description",
    "information",
    "localhost",
    "placeholder",
    "changeme",
    "example",
    "test",
    "default",
    "replace",
    "string",
    "secret123",
    "password123",
    "your-secret",
    "your-key",
    "your-token",
    "insert",
    "enter",
    "password",
    "secret",
    "token",
    "null",
    "none",
    "true",
    "false",
    "admin",
    "root",
    "user",
    "username",
    "passwd",
    "bearer",
    "sample",
    "demo",
    "dummy",
    "fake",
    "temp",
    "staging",
    "todo",
    "fixme",
    "xxx",
    "your_secret",
    "your_key",
    "your_token",
    "notasecret",
    "changeme123",
    "letmein",
    "qwerty",
}
_HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{3,8}$")
_ALL_HEX = re.compile(r"^[0-9a-fA-F]+$")


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits/char: -sum(p * log2(p)) over character frequencies."""
    if not value:
        return 0.0
    n = len(value)
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def secret_value_verdict(value: str) -> str:
    """Classify a candidate secret value: 'ok', 'weak', or 'drop'."""
    if not value:
        return "drop"
    lowered = value.lower()
    if lowered in _SECRET_BLOCKLIST:
        return "drop"
    if len(set(value)) == 1:
        return "drop"
    if "://" in value:
        return "drop"
    if value.startswith("/") or value.startswith("./"):
        return "drop"
    if _HEX_COLOR.match(value):
        return "drop"
    if _ALL_HEX.match(value) and len(value) in {32, 40}:
        return "drop"
    if len(value) < 16:
        return "weak"
    if shannon_entropy(value) < 3.5:
        return "weak"
    return "ok"

_ATOB_SPLIT = re.compile(r"atob.{0,80}\.split\(\s*['\"][.]['\"]", re.I | re.S)
_JWT_CALL = re.compile(
    r"\b(?:jwt\s*\.\s*(?:decode|verify)|jwtDecode|parseJwt)\s*\(",
    re.I,
)
_B64URL_TOKEN = re.compile(
    r"\bbase64url\b.{0,60}\b(?:token|jwt|id_token|idToken|accessToken)\b"
    r"|\b(?:token|jwt|id_token|idToken|accessToken)\b.{0,60}\bbase64url\b",
    re.I | re.S,
)

_GQL_OP = re.compile(
    r"(?:query|mutation|subscription)\s+(\w+)\s*[({]",
    re.I,
)

_CALL_PATTERNS = (
    _FETCH_URL,
    _AXIOS_METHOD_URL,
    _AXIOS_BARE_URL,
    _AXIOS_OBJ_URL,
    _AJAX_BARE_URL,
    _AJAX_OBJ_URL,
    _XHR_OPEN_URL,
)


def _quoted_url(match: re.Match[str]) -> tuple[str, bool]:
    if match.group(3) is not None:
        return match.group(3), True
    if match.group(1) is not None:
        return match.group(1), False
    if match.group(2) is not None:
        return match.group(2), False
    return "", False


def _normalize_url_arg(raw: str, *, is_template: bool) -> str:
    text = (raw or "").strip()
    if is_template:
        text = _TEMPLATE_INTERP.sub("{param}", text)
    return text.strip()


def _is_capture_path(path: str) -> bool:
    if not path or len(path) > 400:
        return False
    if path.startswith(("http://", "https://")):
        return True
    if path.startswith("/") and not path.startswith("//"):
        return path != "/"
    return False


def _flatten_concat(head: str, rest: str) -> str:
    out = head
    for match in _CONCAT_LIT.finditer(rest or ""):
        lit = match.group(2)
        if lit is not None:
            out += lit
    return out


def _resolve_url(source_url: str, path: str) -> str:
    if path.startswith(("http://", "https://")):
        return path
    if source_url and "://" in source_url:
        return urljoin(source_url, path)
    return path


def _endpoint_known(state: ProgramState, path: str, resolved: str) -> bool:
    keys = state.endpoints
    if not keys:
        return False
    if resolved in keys or path in keys:
        return True
    try:
        ep_key = program._endpoint_key(resolved)
    except Exception:  # noqa: BLE001
        ep_key = resolved
    if ep_key and ep_key in keys:
        return True
    return False


def _redact_secret(value: str) -> str:
    prefix = (value or "")[:4]
    return f"{prefix}****"


def _line_at(text: str, index: int, limit: int = 200) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end < 0:
        end = len(text)
    return text[start:end].strip()[:limit]


def _append_unique(bucket: list[str], value: str) -> None:
    if value and value not in bucket:
        bucket.append(value)


class JSAnalyzer:
    """Run every JS sub-analyzer and return a flat finding list."""

    def analyze(
        self, js_text: str, source_url: str, state: ProgramState
    ) -> list[Finding]:
        if not js_text:
            return []
        findings: list[Finding] = []
        findings.extend(self._extract_api_endpoints(js_text, source_url, state))
        findings.extend(self._find_secrets(js_text, source_url))
        findings.extend(self._find_jwt(js_text, source_url))
        findings.extend(self._find_graphql(js_text, source_url, state))
        findings.extend(
            self._find_sourcemaps(js_text, source_url, state, nested=False)
        )
        return findings

    def _extract_api_endpoints(
        self, js_text: str, source_url: str, state: ProgramState
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        def add(raw: str, *, is_template: bool = False) -> None:
            path = _normalize_url_arg(raw, is_template=is_template)
            if not _is_capture_path(path) or path in seen:
                return
            seen.add(path)
            resolved = _resolve_url(source_url, path)
            if _endpoint_known(state, path, resolved):
                return
            program._upsert_endpoint(
                state, resolved, program._now(), source="js-analysis"
            )
            findings.append(
                Finding(
                    id="js-api-endpoint-found",
                    severity="info",
                    category="js-endpoint",
                    url=source_url or resolved,
                    description=f"JS bundle references API endpoint {path}",
                    evidence=path,
                    confidence="confirmed",
                )
            )

        for pat in _CALL_PATTERNS:
            for match in pat.finditer(js_text):
                raw, is_template = _quoted_url(match)
                if raw:
                    add(raw, is_template=is_template)

        for match in _CONCAT.finditer(js_text):
            flattened = _flatten_concat(match.group(2), match.group(3) or "")
            add(flattened, is_template=False)

        return findings

    def _find_secrets(self, js_text: str, source_url: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        def emit(key_name: str, value: str, *, aws: bool = False) -> None:
            redacted = _redact_secret(value)
            evidence = f"{key_name}={redacted}"
            severity: str = "high"
            confidence: str = "confirmed"
            if not aws:
                verdict = secret_value_verdict(value)
                if verdict == "drop":
                    return
                if verdict == "weak":
                    severity = "medium"
                    confidence = "heuristic"
                    evidence = f"[entropy-check-failed] {evidence}"
            if evidence in seen:
                return
            seen.add(evidence)
            findings.append(
                Finding(
                    id="js-hardcoded-secret",
                    severity=severity,  # type: ignore[arg-type]
                    category="secret",
                    url=source_url,
                    description=f"Hardcoded secret assigned to {key_name}",
                    evidence=evidence,
                    confidence=confidence,  # type: ignore[arg-type]
                )
            )

        for match in _SECRET_ASSIGN.finditer(js_text):
            emit(match.group(1), match.group(2))
        for match in _AWS_KEY.finditer(js_text):
            emit("aws_access_key", match.group(0), aws=True)
        return findings

    def _find_jwt(self, js_text: str, source_url: str) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[int] = set()

        def emit_at(index: int) -> None:
            line_start = js_text.rfind("\n", 0, index) + 1
            if line_start in seen:
                return
            seen.add(line_start)
            findings.append(
                Finding(
                    id="js-client-side-jwt-decode",
                    severity="medium",
                    category="secret",
                    url=source_url,
                    description="Client-side JWT decode/verify touchpoint in JS",
                    evidence=_line_at(js_text, index),
                    confidence="confirmed",
                )
            )

        for pat in (_ATOB_SPLIT, _JWT_CALL, _B64URL_TOKEN):
            for match in pat.finditer(js_text):
                emit_at(match.start())
        return findings

    def _find_graphql(
        self, js_text: str, source_url: str, state: ProgramState
    ) -> list[Finding]:
        findings: list[Finding] = []
        existing = list(getattr(state, "extra_graphql_operations", None) or [])
        seen = {name.lower() for name in existing}
        for match in _GQL_OP.finditer(js_text):
            name = match.group(1)
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            _append_unique(existing, name)
            findings.append(
                Finding(
                    id="js-graphql-operation",
                    severity="info",
                    category="js-endpoint",
                    url=source_url,
                    description=f"JS references GraphQL operation {name}",
                    evidence=name,
                    confidence="confirmed",
                )
            )
        state.extra_graphql_operations = existing
        return findings

    def _find_sourcemaps(
        self,
        js_text: str,
        source_url: str,
        state: ProgramState,
        *,
        nested: bool,
    ) -> list[Finding]:
        if nested:
            return []
        spec = source_mapping_url(js_text)
        if not spec:
            return []
        if spec.lower().startswith("data:"):
            return self._analyze_inline_map(spec, source_url, state)
        findings = [
            Finding(
                id="js-source-map-found",
                severity="medium",
                category="js-endpoint",
                url=source_url,
                description=f"JS bundle references source map {spec}",
                evidence=spec,
                confidence="confirmed",
            )
        ]
        stored = spec
        if source_url and "://" in source_url and not spec.startswith(("http://", "https://")):
            stored = urljoin(source_url, spec)
        bucket = list(getattr(state, "source_map_urls", None) or [])
        _append_unique(bucket, stored)
        if stored != spec:
            _append_unique(bucket, spec)
        state.source_map_urls = bucket
        return findings

    def _analyze_inline_map(
        self, spec: str, source_url: str, state: ProgramState
    ) -> list[Finding]:
        raw = decode_data_url(spec)
        if raw is None:
            return []
        obj = parse_source_map(raw)
        if not obj:
            return []
        sources = obj.get("sources") or []
        contents = obj.get("sourcesContent") or []
        findings: list[Finding] = []
        for i, text in enumerate(contents):
            if not isinstance(text, str) or not text:
                continue
            original = ""
            if i < len(sources) and sources[i]:
                original = str(sources[i])
            nested_url = f"{source_url}#{original}" if original else f"{source_url}#source[{i}]"
            findings.extend(self._extract_api_endpoints(text, nested_url, state))
            findings.extend(self._find_secrets(text, nested_url))
            findings.extend(self._find_jwt(text, nested_url))
            findings.extend(self._find_graphql(text, nested_url, state))
        return findings
