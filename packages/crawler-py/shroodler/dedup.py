"""Finding deduplication: param-level, host-level, and operational noise."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from shroodler.urls import origin as origin_of

_CONF_RANK = {"confirmed": 3, "probable": 2, "heuristic": 1}
_PARAM_RE = re.compile(r"param=([^\s]+)")
_HOST_LEVEL_CATEGORIES = {"header", "tls"}
_HOST_LEVEL_PREFIXES = (
    "tls-",
    "cors-",
    "missing-csp",
    "missing-hsts",
    "missing-x-",
    "cookie-missing-",
)
_OPERATIONAL_IDS = {
    "session-reauthenticated",
    "session-died",
    "robots-blocked-crawl",
    "peer-account-registered",
    "openapi-spec-found",
    "graphql-endpoint-found",
}


def _as_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return dict(item)
    dump = getattr(item, "model_dump", None)
    if callable(dump):
        return dump(exclude_none=False)
    return {
        "id": str(getattr(item, "id", "") or ""),
        "severity": getattr(item, "severity", "info"),
        "category": getattr(item, "category", "scan-note"),
        "url": str(getattr(item, "url", "") or ""),
        "description": str(getattr(item, "description", "") or ""),
        "evidence": getattr(item, "evidence", None),
        "confidence": getattr(item, "confidence", None),
    }


def _param_name(finding: dict[str, Any]) -> str:
    for key in ("param_name", "param", "parameter"):
        value = finding.get(key)
        if value:
            return str(value)
    evidence = str(finding.get("evidence") or "")
    match = _PARAM_RE.search(evidence)
    if match:
        return match.group(1)
    return ""


def _origin(url: str) -> str:
    try:
        return origin_of(url)
    except Exception:  # noqa: BLE001
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else url


def _hostname(url: str) -> str:
    parsed = urlparse(url or "")
    host = (parsed.netloc or parsed.hostname or "").lower()
    return host or _origin(url)


_AFFECTS_PAGES = re.compile(r"Affects\s+(\d+)\s+pages", re.I)


def pages_in_evidence(finding: dict[str, Any] | Any) -> int:
    """Parse 'Affects N pages' from evidence; uncollapsed findings count as 1."""
    if isinstance(finding, dict):
        evidence = str(finding.get("evidence") or "")
    else:
        evidence = str(getattr(finding, "evidence", None) or "")
    match = _AFFECTS_PAGES.search(evidence)
    if match:
        try:
            return int(match.group(1))
        except (TypeError, ValueError):
            return 1
    return 1


def _is_host_level(finding: dict[str, Any]) -> bool:
    category = str(finding.get("category") or "")
    if category in _HOST_LEVEL_CATEGORIES:
        return True
    fid = str(finding.get("id") or "")
    return any(
        fid.startswith(prefix) or fid == prefix.rstrip("-")
        for prefix in _HOST_LEVEL_PREFIXES
    )


def _is_operational(finding: dict[str, Any]) -> bool:
    fid = str(finding.get("id") or "")
    if fid in _OPERATIONAL_IDS:
        return True
    return str(finding.get("category") or "") == "scan-note" and fid.startswith("session-")


def _rank(finding: dict[str, Any]) -> int:
    return _CONF_RANK.get(str(finding.get("confidence") or ""), 0)


def _key(finding: dict[str, Any]) -> tuple:
    fid = str(finding.get("id") or "")
    url = str(finding.get("url") or "")
    if _is_operational(finding):
        return ("op", fid)
    if _is_host_level(finding):
        return ("host", fid, _hostname(url))
    return ("param", fid, url, _param_name(finding))


def deduplicate(findings: list) -> list[dict[str, Any]]:
    """Keep the highest-confidence duplicate per (id, url, param) / origin / op-id."""
    best: dict[tuple, dict[str, Any]] = {}
    order: list[tuple] = []
    for raw in findings or []:
        item = _as_dict(raw)
        key = _key(item)
        existing = best.get(key)
        if existing is None:
            best[key] = item
            order.append(key)
            continue
        if _is_host_level(item):
            item_pages = pages_in_evidence(item)
            exist_pages = pages_in_evidence(existing)
            if item_pages > exist_pages:
                best[key] = item
                continue
            if item_pages < exist_pages:
                continue
        if _rank(item) > _rank(existing):
            best[key] = item
    return [best[key] for key in order]
