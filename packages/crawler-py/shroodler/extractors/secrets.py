from __future__ import annotations

import math
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import yaml

from shroodler.models import Finding

SEVERITY = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def rules_dir() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "packages" / "secret-patterns" / "rules"
        if candidate.is_dir():
            return candidate
        # installed layout: repo/packages/secret-patterns/rules
        alt = parent / "secret-patterns" / "rules"
        if alt.is_dir():
            return alt
    raise FileNotFoundError("secret-patterns/rules not found")


@lru_cache(maxsize=1)
def load_rules() -> list[dict]:
    rules: list[dict] = []
    for path in sorted(rules_dir().glob("*.yaml")):
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        rules.extend(loaded)
    return rules


def redact(value: str) -> str:
    if len(value) <= 8:
        return value[0:2] + "****"
    return value[:4] + "************" + value[-4:]


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


_ENTROPY_TOKEN = re.compile(r"\b[A-Za-z0-9_\-/+=]{32,64}\b")

# UUID format: 8-4-4-4-12 hex groups — deployment IDs, build IDs, resource
# identifiers. High entropy but never secrets; filtering them here prevents the
# URL-path UUID false positive pattern (CDN paths like /static/<uuid>/_next/...).
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Structured named identifiers (e.g. Salesforce component DevNames like
# "EmbeddedServiceLiveAgent_Parent...") start with a capitalized English
# word (8+ lowercase letters following the initial capital). Real secrets
# use short prefixes ("sk", "pk", "gh") or start with random characters.
_CAMEL_WORD_START = re.compile(r"^[A-Z][a-z]{7,}")

# Feature flag / config key identifiers (e.g. LaunchDarkly flag names like
# "CopyRestrictionCheckAsFirstPriorityEnabled", "disableReviewProfileButton...").
# They are structured camelCase with many words — real secrets have random
# characters and cannot parse as 4+ consecutive CamelCase word segments.
# Both PascalCase (caps-first) and lowerCamelCase (lower-first) are detected.
_CAMEL_WORDS = re.compile(r"[A-Z][a-z]+")

# ASP.NET WebForms' own postback plumbing (__VIEWSTATE, __EVENTVALIDATION,
# __VIEWSTATEGENERATOR) is a long base64 blob by design -- naturally high
# entropy, but it's serialized page state round-tripped to the same client,
# not a secret. Every classic ASP.NET site (still common in enterprise/
# government targets) would otherwise spam a "possible API key" finding on
# nearly every page. Matched by the field's own value= attribute span
# specifically (not a flat lookbehind window), so a real secret sitting in
# nearby markup shortly after a ViewState field still fires normally.
_ASPNET_STATE_VALUE = re.compile(
    r'(?:name|id)=["\']__(?:VIEWSTATE|EVENTVALIDATION)\w*["\'][^>]*?'
    r'value=["\']([^"\']*)["\']'
)

# Query-param names that routinely carry long opaque values which are
# not secrets (map bookmarks, pagination cursors, click-ids). A token
# that appears ONLY as a value of these names is not reported as
# generic-api-key. High-signal names (api_key, secret, ...) still fire
# even when they live in a URL -- a leaked key in a query string is a
# real finding.
_BENIGN_QUERY_NAMES = {
    "bookmark",
    "cursor",
    "page",
    "offset",
    "ref",
    "referrer",
    "fbclid",
    "gclid",
    "msclkid",
    "dclid",
    "twclid",
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "session",
    "sessionid",
    "session_id",
    "nonce",
    "state",
    "hash",
    "next",
    "prev",
    "start",
    "end",
    "cb",
    "cachebust",
    "cache_bust",
    "ver",
    "version",
    "qid",
    "rid",
    "nid",
    "cid",
}
_HIGH_SIGNAL_QUERY_NAMES = {
    "api_key",
    "apikey",
    "access_token",
    "accesstoken",
    "secret",
    "password",
    "private_key",
    "privatekey",
    "authorization",
    "auth_token",
    "authtoken",
    "client_secret",
    "secret_key",
    "secretkey",
    "aws_secret_access_key",
}


def _normalize_param(name: str) -> str:
    return name.lower().replace("-", "_")


def _is_high_signal_param(name: str) -> bool:
    n = _normalize_param(name)
    if n in _HIGH_SIGNAL_QUERY_NAMES:
        return True
    if n.endswith("_key") or n.endswith("_secret"):
        return True
    return False


def _aspnet_state_spans(text: str) -> list[tuple[int, int]]:
    return [m.span(1) for m in _ASPNET_STATE_VALUE.finditer(text)]



def _entropy_hits(text: str, url: str = "") -> list[str]:
    hits = []
    state_spans = _aspnet_state_spans(text)
    for m in _ENTROPY_TOKEN.finditer(text):
        token = m.group(0)
        if token.startswith("eyJ"):
            continue
        if token.startswith("AKIA"):
            continue
        # Radix UI / React hydration element IDs — auto-generated by the Radix
        # UI library for aria-controls/id pairs; never secrets.
        if token.startswith("radix-"):
            continue
        # Next.js internal chunk/route identifiers: _ngcXXXeNav, _nxt..., etc.
        # They are build-time JS module hashes injected into every Next.js page,
        # not secrets.
        if token.startswith("_ngc") or token.startswith("_nxt"):
            continue
        if _UUID_RE.match(token):
            continue
        # Real API/secret tokens don't contain forward slashes; those are URL
        # path separators or base64 (caught by dedicated rules). Skip to avoid
        # CDN path hashes firing as generic-api-key wherever they appear.
        if "/" in token:
            continue
        # CSS module class names (webpack CSS modules use `__` as the
        # component/hash separator) and structured platform identifiers like
        # Salesforce DevNames use double-underscore. Real secrets don't.
        if "__" in token:
            continue
        # Google OAuth Client IDs are intentionally embedded in public pages.
        # They are always followed by ".apps.googleusercontent.com".
        if text[m.end() : m.end() + 25].startswith(".apps.googleusercontent"):
            continue
        # Named structured identifiers (Salesforce DevNames, internal component
        # names) start with a long CamelCase English word. Real API keys use
        # short uppercase prefixes or fully random characters.
        if _CAMEL_WORD_START.match(token):
            continue
        # Feature flag / config key names (e.g. LaunchDarkly, LaunchDarkly-style
        # keys like "CopyRestrictionCheckAsFirstPriorityEnabled") have 4+ distinct
        # CamelCase word segments. Real secrets are random and cannot parse as
        # multi-word human-readable identifiers.
        if len(_CAMEL_WORDS.findall(token)) >= 4:
            continue
        # URL-encoded path fragment: the entropy regex word-boundary fires after
        # a %-character, so "%2Fpage..." matches as token "2Fpage...". A real
        # token is never preceded by % in the source text.
        if m.start() > 0 and text[m.start() - 1] == "%":
            continue
        if any(start <= m.start() and m.end() <= end for start, end in state_spans):
            continue
        if _shannon(token) >= 4.2 and len(set(token)) >= 16:
            if _looks_like_benign_query_assignment(token):
                continue
            if _token_only_in_benign_query(text, url, token):
                continue
            hits.append(token)
    return hits


def _looks_like_benign_query_assignment(token: str) -> bool:
    """The entropy regex's character class includes `=`, so `bookmark=VALUE`
    often matches as one token. Treat that as the query-param case.
    """
    if "=" not in token:
        return False
    name, _, rest = token.partition("=")
    if not rest or not name or len(name) > 40:
        return False
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_\-]*", name):
        return False
    if _is_high_signal_param(name):
        return False
    if _normalize_param(name) in _BENIGN_QUERY_NAMES:
        return True
    # name=UUID — the UUID is a structured identifier, not a secret, regardless
    # of the param name (as long as it's not a high-signal name checked above).
    if _UUID_RE.match(rest):
        return True
    return False


def _query_params_holding_token(text: str, url: str, token: str) -> set[str]:
    names: set[str] = set()
    for k, v in parse_qsl(urlparse(url or "").query, keep_blank_values=True):
        if v == token:
            names.add(_normalize_param(k))
    for m in re.finditer(
        r"[?&]([A-Za-z][A-Za-z0-9_\-]{0,40})=" + re.escape(token),
        (url or "") + "\n" + (text or ""),
    ):
        names.add(_normalize_param(m.group(1)))
    return names


def _token_only_in_benign_query(text: str, url: str, token: str) -> bool:
    """True when every occurrence of `token` is a query-string value of a
    known-benign param name (bookmark, cursor, tracking ids, ...), and
    none of those names is high-signal (api_key, secret, ...).
    """
    params = _query_params_holding_token(text, url, token)
    if not params:
        return False
    if any(_is_high_signal_param(p) for p in params):
        return False
    if not params <= _BENIGN_QUERY_NAMES:
        return False
    haystack = (url or "") + "\n" + (text or "")
    assigned = len(
        re.findall(r"[?&][A-Za-z][A-Za-z0-9_\-]{0,40}=" + re.escape(token), haystack)
    )
    if assigned == 0:
        return False
    return haystack.count(token) <= assigned


def scan_text(
    text: str, url: str, extra_rules: list[dict] | None = None
) -> list[Finding]:
    if not text:
        return []
    findings: list[Finding] = []
    rules = list(load_rules())
    if extra_rules:
        rules.extend(extra_rules)
    for rule in rules:
        rid = rule["id"]
        pattern = rule["pattern"]
        severity = SEVERITY.get(str(rule.get("severity", "medium")), "medium")
        desc = rule.get("description", rid)
        if pattern == "__ENTROPY__":
            for token in _entropy_hits(text, url):
                findings.append(
                    Finding(
                        id=rid,
                        severity=severity,  # type: ignore[arg-type]
                        category="secret",
                        url=url,
                        description=desc,
                        evidence=redact(token),
                    )
                )
            continue
        try:
            regex = re.compile(pattern)
        except re.error:
            continue
        for m in regex.finditer(text):
            raw = m.group(0)
            findings.append(
                Finding(
                    id=rid,
                    severity=severity,  # type: ignore[arg-type]
                    category="secret",
                    url=url,
                    description=desc,
                    evidence=redact(raw),
                )
            )
    return findings
