"""Load a Cookie header from the session formats a hunt already has.

A two-account write replay should not require a full crawl. Operators
already have Playwright `storageState`, a Netscape jar, captured proxy
JSONL, a HAR, or a handful of `name=value` pairs. This module turns
those into one Cookie header (and, for HAR/JSONL, a list of session
dicts the write extractor can read).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from shroodler.auth import (
    CookieSpec,
    cookies_from_json,
    cookies_from_netscape,
    parse_cookie_pairs,
)
from shroodler.sessions import cookie_header as cookie_header_from_sessions
from shroodler.sessions import load_sessions


def cookie_header_from_specs(specs: list[CookieSpec]) -> str:
    jar: dict[str, str] = {}
    for spec in specs:
        if spec.name:
            jar[spec.name] = spec.value
    return "; ".join(f"{k}={v}" for k, v in jar.items())


def merge_cookie_headers(*headers: str) -> str:
    jar: dict[str, str] = {}
    for raw in headers:
        for part in (raw or "").split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip()
            if name:
                jar[name] = value.strip()
    return "; ".join(f"{k}={v}" for k, v in jar.items())


def cookie_header_from_pairs(pairs: list[str] | None) -> str:
    return cookie_header_from_specs(parse_cookie_pairs(pairs))


def _looks_like_har(data: object) -> bool:
    return isinstance(data, dict) and isinstance(data.get("log"), dict)


def _looks_like_storage_state(data: object) -> bool:
    if isinstance(data, list):
        return bool(data) and all(isinstance(x, dict) and "name" in x for x in data[:3])
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("cookies"), list):
        return True
    return False


def _header_map(items: object) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(items, list):
        return out
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not name:
            continue
        key = str(name)
        value = str(item.get("value") or "")
        if key in out:
            out[key] = out[key] + ", " + value
        else:
            out[key] = value
    return out


def _cookie_header_from_list(items: object) -> str:
    parts: list[str] = []
    if not isinstance(items, list):
        return ""
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name:
            continue
        parts.append(f"{name}={item.get('value') or ''}")
    return "; ".join(parts)


def _har_body(payload: dict[str, Any] | None, *, text_key: str = "text") -> dict[str, str]:
    """HAR postData / response.content → the session body shape ingest uses."""
    if not payload:
        return {"encoding": "utf8", "content": ""}
    text = str(payload.get(text_key) or "")
    encoding = str(payload.get("encoding") or "utf8").lower()
    if encoding != "base64":
        encoding = "utf8"
    if not text:
        params = payload.get("params")
        if isinstance(params, list):
            from urllib.parse import urlencode

            pairs: list[tuple[str, str]] = []
            for item in params:
                if not isinstance(item, dict) or not item.get("name"):
                    continue
                pairs.append((str(item["name"]), str(item.get("value") or "")))
            if pairs:
                text = urlencode(pairs)
    return {"encoding": encoding, "content": text}


def _http_url(url: str) -> bool:
    lower = url.lower()
    return lower.startswith("http://") or lower.startswith("https://")


def sessions_from_har(doc: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    entries = (doc.get("log") or {}).get("entries") or []
    if not isinstance(entries, list):
        return out
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        if not isinstance(req, dict):
            continue
        url = str(req.get("url") or "")
        if not _http_url(url):
            continue
        post = req.get("postData") if isinstance(req.get("postData"), dict) else None
        headers = _header_map(req.get("headers"))
        if not any(k.lower() == "cookie" for k in headers):
            cookie = _cookie_header_from_list(req.get("cookies"))
            if cookie:
                headers["Cookie"] = cookie
        status = 0
        resp_headers: dict[str, str] = {}
        resp_body = {"encoding": "utf8", "content": ""}
        if isinstance(resp, dict):
            try:
                status = int(resp.get("status") or 0)
            except (TypeError, ValueError):
                status = 0
            resp_headers = _header_map(resp.get("headers"))
            content = resp.get("content") if isinstance(resp.get("content"), dict) else None
            resp_body = _har_body(content)
            mime = str((content or {}).get("mimeType") or "")
            if mime and not any(k.lower() == "content-type" for k in resp_headers):
                resp_headers["Content-Type"] = mime
        out.append(
            {
                "request": {
                    "method": str(req.get("method") or "GET"),
                    "url": url,
                    "headers": headers,
                    "body": _har_body(post),
                },
                "response": {
                    "status_code": status,
                    "headers": resp_headers,
                    "body": resp_body,
                },
            }
        )
    return out


def load_captured_sessions(path: str | Path) -> list[dict[str, Any]]:
    """HAR or proxy JSONL → the session-dict shape `sessions.py` already uses."""
    raw = Path(path).read_text(encoding="utf-8")
    stripped = raw.lstrip()
    if stripped.startswith("{"):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return load_sessions(path)
        if _looks_like_har(data):
            return sessions_from_har(data)
        if isinstance(data, dict) and "request" in data:
            return load_sessions(path)
        raise ValueError(f"{path}: JSON file is not a HAR (missing log.entries)")
    return load_sessions(path)


def load_cookie_header(path: str | Path, origin_url: str = "") -> str:
    """Auto-detect storageState / cookie JSON, Netscape, HAR, or sessions JSONL."""
    text = Path(path).read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return cookie_header_from_sessions(load_sessions(path), origin_url)
        if _looks_like_har(data):
            sessions = sessions_from_har(data)
            return cookie_header_from_sessions(sessions, origin_url)
        if _looks_like_storage_state(data):
            host = urlparse(origin_url).hostname or ""
            return cookie_header_from_specs(cookies_from_json(data, host))
        if isinstance(data, dict) and "request" in data:
            return cookie_header_from_sessions(load_sessions(path), origin_url)
        raise ValueError(f"{path}: unrecognized JSON cookie source")
    # JSONL sessions start with `{` per line; a Netscape jar starts with `#` or a domain.
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    if first.startswith("{"):
        return cookie_header_from_sessions(load_sessions(path), origin_url)
    host = urlparse(origin_url).hostname or ""
    return cookie_header_from_specs(cookies_from_netscape(text, host))


def resolve_cookie_header(
    *,
    pairs: list[str] | None = None,
    path: str | Path | None = None,
    origin_url: str = "",
) -> str:
    parts = [cookie_header_from_pairs(pairs)]
    if path:
        parts.append(load_cookie_header(path, origin_url))
    return merge_cookie_headers(*parts)
