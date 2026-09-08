"""Write a Playwright storageState JSON from the jars a hunt already has.

HttpOnly cookies never appear in document.cookie. This command dumps a
real browser via CDP, or converts HAR / proxy JSONL / Netscape / an
existing storageState into one file peer-write already accepts.
"""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from shroodler.auth import CookieSpec, cookies_from_json, cookies_from_netscape, parse_cookie_pairs
from shroodler.cookie_source import load_captured_sessions, sessions_from_har
from shroodler.sessions import cookie_header as cookie_header_from_sessions

_MAX_SOURCE_BYTES = 20 * 1024 * 1024
_MAX_COOKIES = 5000
_COOKIE_NAME_OK = re.compile(r"^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$")
_REDIRECTS = {301, 302, 303, 307, 308}


def origin_host(origin: str) -> str:
    """Return the hostname, or raise if `origin` is set but not an http(s) URL."""
    if not origin:
        return ""
    parsed = urlparse(origin)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            "session-export --origin must be an absolute http(s) URL with a hostname "
            "(e.g. https://app.example/)"
        )
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError(
            "session-export --origin must be an absolute http(s) URL with a hostname "
            "(e.g. https://app.example/)"
        )
    return host


def cookie_field_ok(name: str, value: str) -> bool:
    if not name or not _COOKIE_NAME_OK.match(name):
        return False
    if len(name) > 256 or len(value) > 8192:
        return False
    if any(c in value for c in "\r\n\0;"):
        return False
    return True


def is_loopback_cdp_host(host: str) -> bool:
    """True loopback only — not *.local, not 0.0.0.0, not localhost.localdomain."""
    host = (host or "").strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _assert_cdp_http_url(cdp_url: str, *, allow_external: bool) -> None:
    parsed = urlparse(cdp_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("session-export --cdp only accepts http(s) DevTools URLs")
    if parsed.username or parsed.password:
        raise ValueError("session-export --cdp refuses URLs with userinfo")
    if not parsed.hostname:
        raise ValueError("session-export --cdp requires a hostname")
    if allow_external:
        return
    if not is_loopback_cdp_host(parsed.hostname):
        raise ValueError(
            "session-export --cdp refuses non-loopback DevTools URLs without "
            "--allow-external (a remote CDP endpoint can exfiltrate every cookie "
            "in that browser; *.local and 0.0.0.0 are not loopback)"
        )


def _endpoint_port(parsed, *, websocket: bool) -> int:
    if parsed.port:
        return parsed.port
    if websocket:
        return 443 if parsed.scheme == "wss" else 80
    return 443 if parsed.scheme == "https" else 80


def _assert_cdp_ws_url(ws_url: str, cdp_url: str, *, allow_external: bool) -> None:
    parsed = urlparse(ws_url)
    if parsed.scheme not in {"ws", "wss"}:
        raise ValueError("session-export --cdp webSocketDebuggerUrl must be ws(s)")
    if parsed.username or parsed.password:
        raise ValueError("session-export --cdp refuses URLs with userinfo")
    if not parsed.hostname:
        raise ValueError("session-export --cdp webSocketDebuggerUrl requires a hostname")
    http = urlparse(cdp_url)
    if _endpoint_port(parsed, websocket=True) != _endpoint_port(http, websocket=False):
        raise ValueError("session-export --cdp webSocketDebuggerUrl port must match DevTools")
    if allow_external:
        ws_host = (parsed.hostname or "").strip("[]").lower()
        http_host = (http.hostname or "").strip("[]").lower()
        if ws_host != http_host:
            raise ValueError("session-export --cdp webSocketDebuggerUrl host must match DevTools")
        return
    if not is_loopback_cdp_host(parsed.hostname):
        raise ValueError(
            "session-export --cdp refuses a non-loopback webSocketDebuggerUrl "
            "without --allow-external"
        )


def _cdp_websocket_url(cdp_url: str, *, allow_external: bool) -> str:
    """GET /json/version with redirects disabled, then pin the websocket URL."""
    _assert_cdp_http_url(cdp_url, allow_external=allow_external)
    parsed = urlparse(cdp_url)
    path = parsed.path or ""
    if path in {"", "/"}:
        version_url = cdp_url.rstrip("/") + "/json/version"
    else:
        version_url = cdp_url
    try:
        with httpx.Client(timeout=5.0, follow_redirects=False, trust_env=False) as client:
            resp = client.get(version_url)
    except httpx.HTTPError as exc:
        raise ValueError(f"session-export --cdp could not reach DevTools: {exc}") from exc
    if resp.status_code in _REDIRECTS:
        raise ValueError("session-export --cdp refuses HTTP redirects from DevTools")
    if resp.status_code != 200:
        raise ValueError(
            f"session-export --cdp /json/version returned HTTP {resp.status_code}"
        )
    try:
        data = resp.json()
    except Exception as exc:
        raise ValueError("session-export --cdp /json/version was not JSON") from exc
    ws = data.get("webSocketDebuggerUrl") if isinstance(data, dict) else None
    if not isinstance(ws, str) or not ws.strip():
        raise ValueError("session-export --cdp missing webSocketDebuggerUrl")
    _assert_cdp_ws_url(ws, cdp_url, allow_external=allow_external)
    return ws


def _cookie_matches_origin(spec: CookieSpec, origin: str) -> bool:
    if not origin:
        return True
    host = origin_host(origin)
    domain = (spec.domain or "").lstrip(".").lower()
    if not domain:
        return True
    if host == domain:
        return True
    if not host.endswith("." + domain):
        return False
    # Reject Public-Suffix-wide Domain=com (no dot) unless it is an IP.
    if "." in domain:
        return True
    try:
        ipaddress.ip_address(domain.strip("[]"))
        return True
    except ValueError:
        return False


def specs_to_storage_state(specs: list[CookieSpec], origin: str = "") -> dict[str, Any]:
    if origin:
        origin_host(origin)
    cookies: list[dict[str, Any]] = []
    for spec in specs:
        if not cookie_field_ok(spec.name, spec.value):
            continue
        if not _cookie_matches_origin(spec, origin):
            continue
        domain = spec.domain or origin_host(origin)
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
        if len(cookies) >= _MAX_COOKIES:
            break
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
    if origin:
        origin_host(origin)
    src = Path(path)
    try:
        with src.open("rb") as fh:
            raw = fh.read(_MAX_SOURCE_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"session-export --from could not read {path}: {exc}") from exc
    if len(raw) > _MAX_SOURCE_BYTES:
        raise ValueError(
            f"session-export --from refuses files larger than {_MAX_SOURCE_BYTES} bytes"
        )
    text = raw.decode("utf-8")
    stripped = text.lstrip()
    default_domain = origin_host(origin)

    def from_sessions(sessions: list[dict[str, Any]]) -> dict[str, Any]:
        specs = _specs_from_set_cookie_headers(sessions)
        if not specs:
            header = cookie_header_from_sessions(sessions, origin)
            specs = parse_cookie_pairs(
                [p.strip() for p in header.split(";") if "=" in p]
            )
        return specs_to_storage_state(specs, origin)

    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            sessions = load_captured_sessions(path)
            return from_sessions(sessions)
        if isinstance(data, dict) and isinstance(data.get("log"), dict):
            return from_sessions(sessions_from_har(data))
        specs = cookies_from_json(data, default_domain)
        return specs_to_storage_state(specs, origin)
    first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
    if first.startswith("{"):
        return from_sessions(load_captured_sessions(path))
    specs = cookies_from_netscape(text, default_domain)
    return specs_to_storage_state(specs, origin)


def export_from_cdp(
    cdp_url: str, *, origin: str = "", allow_external: bool = False
) -> dict[str, Any]:
    """Attach to a Chrome/Edge instance started with --remote-debugging-port."""
    if origin:
        origin_host(origin)
    ws = _cdp_websocket_url(cdp_url, allow_external=allow_external)
    from playwright.sync_api import sync_playwright

    with sync_playwright() as pw:
        browser = pw.chromium.connect_over_cdp(ws)
        try:
            if not browser.contexts:
                raise ValueError(f"{cdp_url}: no browser context (open a tab first)")
            raw = browser.contexts[0].storage_state()
        finally:
            browser.close()
    specs = cookies_from_json(raw, origin_host(origin))
    return specs_to_storage_state(specs, origin)


def export_session(
    *,
    source: str | Path | None = None,
    cdp: str | None = None,
    origin: str = "",
    pairs: list[str] | None = None,
    allow_external: bool = False,
) -> dict[str, Any]:
    if origin:
        origin_host(origin)
    if cdp:
        return export_from_cdp(cdp, origin=origin, allow_external=allow_external)
    if source:
        return export_from_path(source, origin=origin)
    if pairs:
        return specs_to_storage_state(parse_cookie_pairs(pairs), origin)
    raise ValueError("session-export needs --from, --cdp, or --cookie")
