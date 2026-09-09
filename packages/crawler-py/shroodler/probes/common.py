"""Shared HTTP helpers for active probes."""

from __future__ import annotations

import re
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import timedelta
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlparse

import httpx

from shroodler.authz_diff import headers_from_auth_line
from shroodler.models import Finding
from shroodler.paced_fetch import pace
from shroodler.pacer import Pacer

_probe_http_ctx: ContextVar[dict[str, Any] | None] = ContextVar(
    "shroodler_probe_http", default=None
)


@contextmanager
def probe_http_session(
    *,
    extra_headers: dict[str, str] | None = None,
    extra_cookies: dict[str, str] | None = None,
    reauth: Any | None = None,
    owner_cookie_header: str = "",
) -> Iterator[dict[str, Any]]:
    """Bind login session extras onto subsequent request() calls (owner only)."""
    ctx: dict[str, Any] = {
        "extra_headers": dict(extra_headers or {}),
        "extra_cookies": dict(extra_cookies or {}),
        "reauth": reauth,
        "owner_cookie_header": (owner_cookie_header or "").strip(),
        "reauth_in_flight": False,
    }
    token = _probe_http_ctx.set(ctx)
    try:
        yield ctx
    finally:
        _probe_http_ctx.reset(token)


def update_probe_http_session(
    *,
    extra_headers: dict[str, str] | None = None,
    extra_cookies: dict[str, str] | None = None,
    owner_cookie_header: str | None = None,
) -> None:
    ctx = _probe_http_ctx.get()
    if not ctx:
        return
    if extra_headers:
        merged = dict(ctx.get("extra_headers") or {})
        merged.update(extra_headers)
        ctx["extra_headers"] = merged
    if extra_cookies:
        merged_c = dict(ctx.get("extra_cookies") or {})
        merged_c.update(extra_cookies)
        ctx["extra_cookies"] = merged_c
    if owner_cookie_header is not None:
        ctx["owner_cookie_header"] = owner_cookie_header.strip()


def _is_owner_request(cookie_header: str, ctx: dict[str, Any]) -> bool:
    owner = str(ctx.get("owner_cookie_header") or "").strip()
    got = (cookie_header or "").strip()
    if not owner:
        return False
    return got == owner


def request(
    method: str,
    url: str,
    *,
    cookie_header: str = "",
    extra_headers: dict[str, str] | None = None,
    extra_cookies: dict[str, str] | None = None,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    reauth: Any | None = None,
    _reauth_done: bool = False,
    **kwargs: Any,
) -> httpx.Response | None:
    """Rate-limited httpx request. Returns None on transport errors.

    Optional extra_headers / extra_cookies / reauth are backward-compatible
    kwargs. A probe_http_session() context (set by the agent) merges the
    owner login session only when cookie_header matches the owner session.
    """
    pace(pacer)
    ctx = _probe_http_ctx.get() or {}
    explicit_reauth = reauth is not None
    is_owner = _is_owner_request(cookie_header, ctx)
    headers = {**headers_from_auth_line(cookie_header)}
    cookies = dict(kwargs.pop("cookies", None) or {})
    cookies.update(dict(extra_cookies or {}))
    if is_owner:
        headers = {**dict(ctx.get("extra_headers") or {}), **headers}
        cookies = {**dict(ctx.get("extra_cookies") or {}), **cookies}
    headers = {**headers, **dict(extra_headers or {})}
    if cookies:
        extra = "; ".join(f"{k}={v}" for k, v in cookies.items() if k)
        if extra:
            existing = headers.get("Cookie") or ""
            headers["Cookie"] = f"{existing}; {extra}" if existing else extra

    own = client is None
    http = client or httpx.Client(timeout=8.0, follow_redirects=False)
    try:
        resp = http.request(method.upper(), url, headers=headers, **kwargs)
    except Exception:  # noqa: BLE001 - fail closed; probe must not crash the loop
        return None
    finally:
        if own:
            http.close()

    reauth_fn = reauth if explicit_reauth else ctx.get("reauth")
    allow_reauth = explicit_reauth or is_owner
    if (
        not _reauth_done
        and allow_reauth
        and reauth_fn
        and resp is not None
        and int(resp.status_code) in {401, 403}
        and not ctx.get("reauth_in_flight")
    ):
        ctx["reauth_in_flight"] = True
        try:
            recovered = bool(reauth_fn())
        except Exception:  # noqa: BLE001 - fail closed
            recovered = False
        finally:
            ctx["reauth_in_flight"] = False
        if recovered:
            return request(
                method,
                url,
                cookie_header=cookie_header,
                extra_headers=extra_headers,
                extra_cookies=extra_cookies,
                client=client,
                pacer=pacer,
                reauth=reauth if explicit_reauth else None,
                _reauth_done=True,
                **kwargs,
            )
    return resp


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


_UUID_SEG_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}$"
)
_BRACE_SEG_RE = re.compile(r"^\{([^{}]+)\}$")
_VERSION_SEG_RE = re.compile(r"^v\d+$", re.I)


def _next_id_name(seen: set[str], numeric_n: int) -> tuple[str, int]:
    """Return a unique id / id2 / id3 name and the updated counter."""
    while True:
        name = "id" if numeric_n <= 1 else f"id{numeric_n}"
        if name not in seen:
            return name, max(numeric_n, 1)
        numeric_n += 1


def params_from_path(url: str) -> list[dict[str, str]]:
    """Extract `{name}` placeholders, UUIDs, and all-digit path segments.

    Digit segments become integer path params named ``id`` / ``id2`` / ...
    Version tokens like ``v2`` are skipped. ``/guilds/1`` still yields ``id``.
    """
    if not url:
        return []
    path = urlparse(url).path or ""
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    numeric_n = 0
    prev = ""
    for seg in path.split("/"):
        if not seg:
            continue
        brace = _BRACE_SEG_RE.fullmatch(seg)
        if brace:
            name = brace.group(1).strip()
            if name and name not in seen:
                seen.add(name)
                out.append({"name": name, "value": "", "in": "path"})
            prev = seg
            continue
        if _VERSION_SEG_RE.fullmatch(seg):
            prev = seg
            continue
        if _UUID_SEG_RE.fullmatch(seg):
            numeric_n += 1
            name, numeric_n = _next_id_name(seen, numeric_n)
            seen.add(name)
            out.append(
                {"name": name, "value": seg, "in": "path", "type": "string"}
            )
            prev = seg
            continue
        if seg.isdigit() and not (prev.lower() == "v" and len(seg) <= 2):
            numeric_n += 1
            name, numeric_n = _next_id_name(seen, numeric_n)
            seen.add(name)
            out.append(
                {"name": name, "value": seg, "in": "path", "type": "integer"}
            )
        prev = seg
    return out


def normalize_params(
    params: list | None, url: str | None = None
) -> list[dict[str, str]]:
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
        row: dict[str, str] = {
            "name": name,
            "value": str(item.get("value") or ""),
            "in": str(item.get("in") or "query"),
        }
        if item.get("type"):
            row["type"] = str(item["type"])
        out.append(row)
    if url:
        for item in params_from_path(url):
            if item["name"] not in seen:
                out.append(item)
                seen.add(item["name"])
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


def _apply_path_params(
    url: str, params: list[dict[str, str]], values: dict[str, str]
) -> tuple[str, set[str]]:
    """Replace `{name}` / stored path values. Returns (url, substituted names)."""
    path = url
    substituted: set[str] = set()
    for item in params:
        if str(item.get("in") or "") != "path":
            continue
        pname = str(item.get("name") or "")
        if not pname:
            continue
        pval = str(values.get(pname, ""))
        brace = "{" + pname + "}"
        if brace in path:
            path = path.replace(brace, pval)
            substituted.add(pname)
            continue
        old = str(item.get("value") or "")
        if old and f"/{old}" in path:
            path = path.replace(f"/{old}", f"/{pval}", 1)
            substituted.add(pname)
    return path, substituted


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
    extra_headers: dict[str, str] | None = None,
    extra_cookies: dict[str, str] | None = None,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    reauth: Any | None = None,
) -> httpx.Response | None:
    """Replay the endpoint with one param replaced by `payload`."""
    values = {item["name"]: item["value"] for item in params}
    values[name] = payload
    path = url_without_query(url)
    path, substituted = _apply_path_params(path, params, values)
    query_values = {
        key: val for key, val in values.items() if key not in substituted
    }
    method_u = (method or "GET").upper()
    if method_u == "GET":
        return request(
            "GET",
            path,
            cookie_header=cookie_header,
            extra_headers=extra_headers,
            extra_cookies=extra_cookies,
            client=client,
            pacer=pacer,
            reauth=reauth,
            params=query_values,
        )
    return request(
        method_u,
        path,
        cookie_header=cookie_header,
        extra_headers=extra_headers,
        extra_cookies=extra_cookies,
        client=client,
        pacer=pacer,
        reauth=reauth,
        data=query_values,
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
