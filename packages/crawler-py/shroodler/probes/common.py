"""Shared HTTP helpers for active probes."""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from urllib.parse import parse_qsl, urlparse

import httpx

from shroodler.authz_diff import headers_from_auth_line
from shroodler.models import Finding
from shroodler.paced_fetch import pace
from shroodler.pacer import Pacer


def request(
    method: str,
    url: str,
    *,
    cookie_header: str = "",
    extra_headers: dict[str, str] | None = None,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    **kwargs: Any,
) -> httpx.Response | None:
    """Rate-limited httpx request. Returns None on transport errors."""
    pace(pacer)
    headers = {**headers_from_auth_line(cookie_header), **dict(extra_headers or {})}
    own = client is None
    http = client or httpx.Client(timeout=8.0, follow_redirects=False)
    try:
        return http.request(method.upper(), url, headers=headers, **kwargs)
    except Exception:  # noqa: BLE001 - fail closed; probe must not crash the loop
        return None
    finally:
        if own:
            http.close()


def response_elapsed(resp: Any, fallback: float = 0.0) -> float:
    elapsed = getattr(resp, "elapsed", None)
    if elapsed is None:
        return fallback
    if isinstance(elapsed, timedelta):
        return elapsed.total_seconds()
    try:
        return float(elapsed)
    except (TypeError, ValueError):
        return fallback


def normalize_params(params: list | None) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in params or []:
        if isinstance(item, str):
            name = item.strip()
            if name and name not in seen:
                seen.add(name)
                out.append({"name": name, "value": "", "in": "query"})
            continue
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("key") or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(
            {
                "name": name,
                "value": str(item.get("value") or ""),
                "in": str(item.get("in") or "query"),
            }
        )
    return out


def params_from_url(url: str) -> list[dict[str, str]]:
    parsed = urlparse(url)
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": key, "value": value, "in": "query"})
    return out


def url_without_query(url: str) -> str:
    parsed = urlparse(url)
    return parsed._replace(query="", fragment="").geturl()


def body_text(resp: Any) -> str:
    if resp is None:
        return ""
    text = getattr(resp, "text", None)
    if isinstance(text, str):
        return text
    content = getattr(resp, "content", b"")
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    return str(content or "")


def inject(
    url: str,
    method: str,
    params: list[dict[str, str]],
    name: str,
    payload: str,
    *,
    cookie_header: str = "",
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
) -> httpx.Response | None:
    """Replay the endpoint with one param replaced by `payload`."""
    values = {item["name"]: item["value"] for item in params}
    values[name] = payload
    path = url_without_query(url)
    method_u = (method or "GET").upper()
    if method_u == "GET":
        return request(
            "GET",
            path,
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
            params=values,
        )
    return request(
        method_u,
        path,
        cookie_header=cookie_header,
        client=client,
        pacer=pacer,
        data=values,
    )


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str]] = set()
    out: list[Finding] = []
    for finding in findings:
        key = (finding.id, finding.url)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out
