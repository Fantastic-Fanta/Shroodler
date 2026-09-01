from __future__ import annotations

import json
import re
from base64 import b64decode
from urllib.parse import unquote_to_bytes

from shroodler.extractors.js_endpoints import extract_js_endpoints
from shroodler.extractors.secrets import scan_text
from shroodler.models import Finding, JsEndpoint

_SM = re.compile(r"(?:\/\/[#@]|\/\*)\s*sourceMappingURL=(\S+)")


def source_mapping_url(js_text: str) -> str | None:
    if not js_text:
        return None
    matches = _SM.findall(js_text)
    if not matches:
        return None
    spec = matches[-1].rstrip("*/").strip()
    return spec or None


def decode_data_url(spec: str) -> bytes | None:
    if not spec.startswith("data:"):
        return None
    _, _, rest = spec.partition(",")
    if rest == spec:
        return None
    header = spec[5 : spec.index(",")]
    if ";base64" in header.lower():
        try:
            return b64decode(rest)
        except ValueError:
            return None
    return unquote_to_bytes(rest)


def parse_source_map(raw: str | bytes) -> dict | None:
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    return obj


def annotate_original(findings: list[Finding], original: str) -> None:
    for f in findings:
        f.description = f"{f.description} (original {original})"
        if f.evidence:
            f.evidence = f"{f.evidence} @ {original}"
        else:
            f.evidence = original


def extract_from_source_map(js_url: str, map_obj: dict) -> tuple[list[JsEndpoint], list[Finding]]:
    sources = map_obj.get("sources") or []
    contents = map_obj.get("sourcesContent") or []
    endpoints: list[JsEndpoint] = []
    findings: list[Finding] = []
    for i, src in enumerate(sources):
        if i >= len(contents) or not contents[i]:
            continue
        original = src or f"source[{i}]"
        text = contents[i]
        if not isinstance(text, str):
            continue
        eps, ep_findings = extract_js_endpoints(js_url, text)
        annotate_original(ep_findings, original)
        secrets = scan_text(text, js_url)
        annotate_original(secrets, original)
        endpoints.extend(eps)
        findings.extend(ep_findings)
        findings.extend(secrets)
    return endpoints, findings
