"""Write a Playwright storageState JSON from the jars a hunt already has.

HttpOnly cookies never appear in document.cookie. This command dumps a
real browser via CDP, or converts HAR / proxy JSONL / Netscape / an
existing storageState into one file peer-write already accepts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from shroodler.auth import CookieSpec, cookies_from_json, cookies_from_netscape, parse_cookie_pairs
from shroodler.cookie_source import load_captured_sessions, sessions_from_har
from shroodler.sessions import cookie_header as cookie_header_from_sessions


def _cookie_matches_origin(spec: CookieSpec, origin: str) -> bool:
    if not origin:
        return True
    host = (urlparse(origin).hostname or "").lower()
    if not host:
        return True
    domain = (spec.domain or "").lstrip(".").lower()
    if not domain:
        return True
    return host == domain or host.endswith("." + domain)


def specs_to_storage_state(specs: list[CookieSpec], origin: str = "") -> dict[str, Any]:
    cookies: list[dict[str, Any]] = []
    for spec in specs:
        if not spec.name:
            continue
        if not _cookie_matches_origin(spec, origin):
            continue
        domain = spec.domain or (urlparse(origin).hostname or "")
        same = spec.same_site
        if same:
            same = same[0].upper() + same[1:].lower() if len(same) > 1 else same
            if same.lower() == "none":
                same = "None"
        cookies.append(
            {
                "name": spec.name,
                "value": spec.value,
                "domain": domain,
                "path": spec.path or "/",
                "httpOnly": spec.http_only,
                "secure": spec.secure,
                "sameSite": same or "Lax",
            }
        )
    return {"cookies": cookies, "origins": []}


def _specs_from_set_cookie_headers(sessions: list[dict[str, Any]]) -> list[CookieSpec]:
    from shroodler.extractors.cookies import parse_set_cookie

    out: list[CookieSpec] = []
    for sess in sessions:
        req = sess.get("request") or {}
        resp = sess.get("response") or {}
        host = urlparse(str(req.get("url") or "")).hostname or ""
        headers = resp.get("headers") or {}
        raw_list: list[str] = []
        if isinstance(headers, dict):
            for key, value in headers.items():
                if str(key).lower() == "set-cookie":
                    raw_list.append(str(value))
        for raw in raw_list:
            cookie = parse_set_cookie(raw)
            if cookie is None:
                continue
            name_value = raw.split(";", 1)[0]
            value = name_value.split("=", 1)[1] if "=" in name_value else ""
            attrs = {
                p.split("=", 1)[0].strip().lower(): p.split("=", 1)[1].strip()
                for p in raw.split(";")[1:]
                if "=" in p
            }
            out.append(
                CookieSpec(
                    name=cookie.name,
                    value=value,
                    domain=(attrs.get("domain") or host or "").lstrip("."),
                    path=attrs.get("path") or "/",
                    secure=cookie.secure,
                    http_only=cookie.http_only,
                    same_site=cookie.same_site,
                )
            )
    return out


def export_from_path(path: str | Path, *, origin: str = "") -> dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        data = json.loads(text)
        if isinstance(data, dict) and isinstance(data.get("log"), dict):
            sessions = sessions_from_har(data)
            specs = _specs_from_set_cookie_headers(sessions)
            if not specs:
                header = cookie_header_from_sessions(sessions, origin)
                specs = parse_cookie_pairs(
                    [p.strip() for p in header.split(";") if "=" in p]
                )
            return specs_to_storage_state(specs, origin)
        specs = cookies_from_json(data, urlparse(origin).hostname or "")
        return specs_to_storage_state(specs, origin)
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    if first.startswith("{"):
        sessions = load_captured_sessions(path)
        specs = _specs_from_set_cookie_headers(sessions)
        if not specs:
            header = cookie_header_from_sessions(sessions, origin)
            specs = parse_cookie_pairs([p.strip() for p in header.split(";") if "=" in p])
        return specs_to_storage_state(specs, origin)
    specs = cookies_from_netscape(text, urlparse(origin).hostname or "")
    return specs_to_storage_state(specs, origin)


def export_from_cdp(cdp_url: str, *, origin: str = "") -> dict[str, Any]:
    """Attach to a Chrome/Edge instance started with --remote-debugging-port."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.connect_over_cdp(cdp_url)
        try:
            if not browser.contexts:
                raise ValueError(f"{cdp_url}: no browser context (open a tab first)")
            raw = browser.contexts[0].storage_state()
        finally:
            browser.close()
    specs = cookies_from_json(raw, urlparse(origin).hostname or "")
    return specs_to_storage_state(specs, origin)


def export_session(
    *,
    source: str | Path | None = None,
    cdp: str | None = None,
    origin: str = "",
    pairs: list[str] | None = None,
) -> dict[str, Any]:
    if cdp:
        return export_from_cdp(cdp, origin=origin)
    if source:
        return export_from_path(source, origin=origin)
    if pairs:
        return specs_to_storage_state(parse_cookie_pairs(pairs), origin)
    raise ValueError("session-export needs --from, --cdp, or --cookie")
