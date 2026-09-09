"""Lightweight same-origin crawler that follows JSON, not HTML."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from shroodler.auth import _access_token_from_payload
from shroodler.authz_diff import headers_from_auth_line
from shroodler.paced_fetch import pace
from shroodler.pacer import Pacer
from shroodler.program import (
    ProgramState,
    _store_api_sample,
    _upsert_endpoint,
    extract_object_ids,
    url_to_pattern,
)
from shroodler.urls import canonical_key, normalize_url, same_origin

_HATEOAS_KEYS = frozenset({"href", "url", "uri"})
_HATEOAS_CONTAINERS = frozenset({"_links", "links", "_embedded"})
_STATIC_SUFFIX = (
    ".css",
    ".js",
    ".mjs",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".map",
)
_PLACEHOLDER = re.compile(r"\{[^{}]+\}")
_ABS_URL = re.compile(r"^https?://", re.I)


@dataclass
class RestCrawlResult:
    start_url: str
    pages: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    object_ids: dict[str, list[str]] = field(default_factory=dict)
    bearer_token: str = ""
    errors: list[str] = field(default_factory=list)


def crawl_rest(
    start_url: str,
    *,
    cookie_header: str = "",
    bearer_token: str = "",
    max_pages: int = 30,
    pacer: Pacer | None = None,
    client: httpx.Client | None = None,
) -> RestCrawlResult:
    """BFS over JSON API responses. Same-origin only. Fail closed."""
    result = RestCrawlResult(start_url=start_url, bearer_token=(bearer_token or "").strip())
    if not start_url:
        return result
    cap = max(0, int(max_pages))
    headers = _request_headers(cookie_header, result.bearer_token)
    own = client is None
    http = client or httpx.Client(timeout=8.0, follow_redirects=True)
    queue: list[str] = [start_url]
    queued: set[str] = {canonical_key(start_url)}
    seen: set[str] = set()
    try:
        while queue and len(result.pages) < cap:
            url = queue.pop(0)
            key = canonical_key(url)
            if key in seen:
                continue
            if not same_origin(url, start_url):
                continue
            seen.add(key)
            pace(pacer)
            try:
                resp = http.request("GET", url, headers=headers)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"{url}: {type(exc).__name__}: {exc}")
                continue
            status = int(getattr(resp, "status_code", 0) or 0)
            text = _response_text(resp)
            token = _token_from_response(resp, text)
            if token and not result.bearer_token:
                result.bearer_token = token
                headers = _request_headers(cookie_header, token)
            if status != 200 or not _is_json_content_type(resp):
                continue
            data = _parse_json(text)
            if data is None:
                continue
            params = _params_from_json(data)
            result.pages.append({"url": url, "status_code": status, "params": params})
            result.endpoints.append(
                {
                    "url": url,
                    "method": "GET",
                    "params": params,
                    "source": "rest-crawl",
                }
            )
            for oid in extract_object_ids(text):
                pattern = url_to_pattern(url)
                bucket = result.object_ids.setdefault(pattern, [])
                if oid not in bucket:
                    bucket.append(oid)
            for nxt in extract_rest_urls(url, data):
                nxt_key = canonical_key(nxt)
                if nxt_key in queued or nxt_key in seen:
                    continue
                if not same_origin(nxt, start_url):
                    continue
                queued.add(nxt_key)
                queue.append(nxt)
    finally:
        if own:
            http.close()
    return result


def merge_rest_into_state(state: ProgramState, result: RestCrawlResult) -> dict[str, Any]:
    """Upsert REST endpoints, object IDs, and a discovered bearer token."""
    from shroodler.program import _now

    last_seen = _now()
    new_endpoints = 0
    for ep in result.endpoints:
        url = str(ep.get("url") or "")
        if not url:
            continue
        status = _upsert_endpoint(
            state,
            url,
            last_seen,
            method=str(ep.get("method") or "GET"),
            params=ep.get("params") or [],
            source="rest-crawl",
        )
        if status == "new":
            new_endpoints += 1
        sample = ""
        for page in result.pages:
            if page.get("url") == url:
                sample = str(page.get("body") or page.get("text") or "")
                break
        if sample:
            _store_api_sample(state, url, sample)
    for pattern, ids in result.object_ids.items():
        bucket = state.object_ids.setdefault(str(pattern), [])
        for oid in ids:
            text = str(oid)
            if text and text not in bucket:
                bucket.append(text)
    if result.bearer_token and not (state.bearer_token or "").strip():
        state.bearer_token = result.bearer_token
    return {
        "new_endpoints": new_endpoints,
        "object_id_values": sum(len(v) for v in state.object_ids.values()),
        "bearer_token": bool(state.bearer_token),
    }


def extract_rest_urls(base_url: str, data: Any) -> list[str]:
    """URL-like strings and HATEOAS href/url/uri values, same-origin only."""
    found: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        href = (raw or "").strip()
        if not href or _PLACEHOLDER.search(href):
            return
        joined = normalize_url(base_url, href)
        if not joined or not same_origin(joined, base_url):
            return
        path = joined.split("?", 1)[0].lower()
        if any(path.endswith(sfx) for sfx in _STATIC_SUFFIX):
            return
        if joined not in seen:
            seen.add(joined)
            found.append(joined)

    def walk(obj: Any, parent_key: str = "") -> None:
        if isinstance(obj, dict):
            for key, val in obj.items():
                ks = str(key)
                if ks.lower() in _HATEOAS_KEYS and isinstance(val, str):
                    add(val)
                elif isinstance(val, dict) and "href" in val:
                    href = val.get("href")
                    if isinstance(href, str):
                        add(href)
                walk(val, ks)
        elif isinstance(obj, list):
            for item in obj:
                walk(item, parent_key)
        elif isinstance(obj, str):
            if parent_key.lower() in _HATEOAS_KEYS:
                add(obj)
            elif _looks_like_url(obj):
                add(obj)

    walk(data)
    return found


def _looks_like_url(value: str) -> bool:
    text = (value or "").strip()
    if not text or " " in text:
        return False
    if _ABS_URL.match(text):
        return True
    if text.startswith("/") and not text.startswith("//") and len(text) > 1:
        return True
    return False


def _is_json_content_type(resp: Any) -> bool:
    headers = getattr(resp, "headers", None) or {}
    try:
        ct = headers.get("content-type") or headers.get("Content-Type") or ""
    except Exception:  # noqa: BLE001
        ct = ""
    return "json" in str(ct).lower()


def _parse_json(text: str) -> Any | None:
    if not (text or "").strip():
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(data, (dict, list)):
        return data
    return None


def _params_from_json(data: Any) -> list[dict[str, str]]:
    keys: list[str] = []
    seen: set[str] = set()

    def take(obj: Any) -> None:
        if isinstance(obj, dict):
            for key in obj:
                name = str(key).strip()
                if not name or name in seen:
                    continue
                if name.lower() in _HATEOAS_CONTAINERS or name.lower() in _HATEOAS_KEYS:
                    continue
                seen.add(name)
                keys.append(name)
        elif isinstance(obj, list):
            for item in obj[:20]:
                take(item)

    take(data)
    return [{"name": name, "value": "", "in": "body"} for name in keys]


def _request_headers(cookie_header: str, bearer_token: str) -> dict[str, str]:
    headers = dict(headers_from_auth_line(cookie_header))
    token = (bearer_token or "").strip()
    if token and not any(k.lower() == "authorization" for k in headers):
        if token.lower().startswith("bearer "):
            token = token.split(None, 1)[1].strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    headers.setdefault("Accept", "application/json")
    return headers


def _response_text(resp: Any) -> str:
    text = getattr(resp, "text", None)
    if isinstance(text, str):
        return text
    content = getattr(resp, "content", b"") or b""
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    return str(content)


def _token_from_response(resp: Any, text: str) -> str:
    headers = getattr(resp, "headers", None) or {}
    try:
        auth = headers.get("Authorization") or headers.get("authorization") or ""
    except Exception:  # noqa: BLE001
        auth = ""
    if isinstance(auth, str) and auth.lower().startswith("bearer "):
        token = auth.split(None, 1)[1].strip()
        if token:
            return token
    data = _parse_json(text)
    if data is not None:
        return (_access_token_from_payload(data) or "").strip()
    return ""
