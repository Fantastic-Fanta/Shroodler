"""Active probes against endpoints parsed from an OpenAPI/Swagger spec."""

from __future__ import annotations

import re
from typing import Any

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.auth_bypass import probe_auth_bypass
from shroodler.probes.common import dedupe, request
from shroodler.probes.crlf import probe_crlf
from shroodler.probes.enum_id import probe_enumerable_id
from shroodler.probes.idor import probe_idor
from shroodler.probes.open_redirect import probe_open_redirect
from shroodler.probes.path_traversal import probe_path_traversal
from shroodler.probes.rate_limit import probe_rate_limit_bypass
from shroodler.probes.sqli import probe_sqli
from shroodler.probes.unauth_exposure import probe_unauth_exposure
from shroodler.probes.xss import probe_xss

_PATH_PARAM = re.compile(r"\{([^}]+)\}")
_NUMERIC_TYPES = frozenset({"integer", "number", "int", "long", "int32", "int64"})


def probe_openapi_endpoints(
    endpoints: list[Any],
    *,
    cookie_header: str = "",
    peer_cookie: str = "",
    pacer: Pacer | None = None,
    client: httpx.Client | None = None,
) -> list[Finding]:
    """Fill spec placeholders and reuse SQLi/XSS/path-traversal/IDOR probes."""
    findings: list[Finding] = []
    for raw in endpoints or []:
        row = _as_row(raw)
        if not row or row.get("tested_payload"):
            continue
        try:
            findings.extend(
                _probe_one(
                    row,
                    cookie_header=cookie_header,
                    peer_cookie=peer_cookie,
                    pacer=pacer,
                    client=client,
                )
            )
        except Exception:  # noqa: BLE001 - fail closed per endpoint
            continue
    return dedupe(findings)


def fill_path_params(url: str, params: list[dict] | None) -> str:
    """Replace `{name}` path params with example or type defaults."""
    by_name = {
        str(item.get("name") or ""): item
        for item in (params or [])
        if isinstance(item, dict) and item.get("in") == "path"
    }

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        return _default_value(by_name.get(name) or {})

    return _PATH_PARAM.sub(repl, url or "")


def _as_row(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    url = getattr(raw, "url", None)
    if not url:
        return {}
    return {
        "url": str(url),
        "method": str(getattr(raw, "method", None) or "GET"),
        "params": list(getattr(raw, "params", None) or []),
        "auth_required": bool(getattr(raw, "auth_required", False)),
        "tested_payload": bool(getattr(raw, "tested_payload", False)),
    }


def _default_value(item: dict) -> str:
    example = item.get("example")
    if example is not None and str(example) != "":
        return str(example)
    value = item.get("value")
    if value is not None and str(value) != "":
        return str(value)
    ptype = str(item.get("type") or "").lower()
    if ptype in _NUMERIC_TYPES:
        return "1"
    return "test"


def _injectable_params(params: list[dict]) -> list[dict]:
    out: list[dict] = []
    for item in params or []:
        if not isinstance(item, dict):
            continue
        loc = str(item.get("in") or "query")
        if loc in {"query", "body", "formData"}:
            out.append(item)
    return out


def _has_numeric_path_param(params: list[dict], filled_url: str) -> bool:
    for item in params or []:
        if not isinstance(item, dict) or item.get("in") != "path":
            continue
        ptype = str(item.get("type") or "").lower()
        if ptype in _NUMERIC_TYPES:
            return True
    return bool(re.search(r"/\d+", filled_url or ""))


def _probe_one(
    row: dict[str, Any],
    *,
    cookie_header: str,
    peer_cookie: str,
    pacer: Pacer | None,
    client: httpx.Client | None,
) -> list[Finding]:
    url = str(row.get("url") or "")
    method = str(row.get("method") or "GET").upper() or "GET"
    params = list(row.get("params") or [])
    filled = fill_path_params(url, params)
    if not filled or _PATH_PARAM.search(filled):
        return []
    findings: list[Finding] = []
    injectable = _injectable_params(params)
    if injectable and method in {"GET", "POST"}:
        findings.extend(
            probe_sqli(
                filled, method, injectable, cookie_header, client=client, pacer=pacer
            )
        )
        findings.extend(
            probe_xss(
                filled, method, injectable, cookie_header, client=client, pacer=pacer
            )
        )
        findings.extend(
            probe_path_traversal(filled, injectable, cookie_header, client=client, pacer=pacer)
        )
        findings.extend(
            probe_open_redirect(
                filled, method, injectable, cookie_header, client=client, pacer=pacer
            )
        )
        findings.extend(
            probe_crlf(filled, method, injectable, cookie_header, client=client, pacer=pacer)
        )
    if method in {"POST", "PUT"} and injectable:
        findings.extend(
            probe_auth_bypass(filled, method, injectable, cookie_header, client=client, pacer=pacer)
        )
    if peer_cookie and _has_numeric_path_param(params, filled):
        findings.extend(
            probe_idor(filled, cookie_header, peer_cookie, client=client, pacer=pacer)
        )
    if row.get("auth_required"):
        hit = _unauthenticated_access(
            method, filled, client=client, pacer=pacer
        )
        if hit is not None:
            findings.append(hit)
    # Path-heuristic checks (self-gating), independent of whether the spec
    # declares a security scheme — most FastAPI apps enforce auth via a
    # dependency and never emit `security`, so `auth_required` stays false.
    findings.extend(
        probe_unauth_exposure(filled, method, client=client, pacer=pacer)
    )
    findings.extend(
        probe_enumerable_id(filled, method, cookie_header, client=client, pacer=pacer)
    )
    findings.extend(
        probe_rate_limit_bypass(filled, method, cookie_header, client=client, pacer=pacer)
    )
    return findings


def _unauthenticated_access(
    method: str,
    url: str,
    *,
    client: httpx.Client | None,
    pacer: Pacer | None,
) -> Finding | None:
    resp = request(method, url, cookie_header="", client=client, pacer=pacer)
    status = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
    if status != 200:
        return None
    return Finding(
        id="openapi-unauthenticated",
        severity="high",
        category="auth",
        url=url,
        description=(
            f"{method} {url} returned 200 without credentials on an "
            "operation the spec marks as authenticated."
        ),
        evidence=f"status=200 method={method} unauthenticated=true",
        confidence="confirmed",
    )
