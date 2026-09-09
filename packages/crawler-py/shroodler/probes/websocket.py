"""WebSocket endpoint discovery and basic authenticated probing."""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable
from typing import Any
from urllib.parse import urljoin, urlparse

from shroodler.models import Finding
from shroodler.paced_fetch import pace
from shroodler.pacer import Pacer
from shroodler.probes.common import dedupe

_WS_PATTERNS = (
    re.compile(r"""new\s+WebSocket\(\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""\bio\(\s*['"]([^'"]+)['"]""", re.I),
    re.compile(r"""socket\.connect\(\s*['"]([^'"]+)['"]""", re.I),
)
Connector = Callable[[str, dict[str, str]], Any]


def discover_websocket_urls(
    js_source: str = "",
    *,
    base_url: str = "",
    captured_headers: list[dict] | None = None,
) -> list[str]:
    """Extract WS URLs from JS (`new WebSocket`, `io(`, `socket.connect(`) and upgrades."""
    seen: set[str] = set()
    out: list[str] = []

    def add(raw: str) -> None:
        url = (raw or "").strip()
        if not url:
            return
        if url.startswith("/") and base_url:
            url = urljoin(base_url, url)
        if url.startswith("http://"):
            url = "ws://" + url[len("http://") :]
        elif url.startswith("https://"):
            url = "wss://" + url[len("https://") :]
        if url not in seen:
            seen.add(url)
            out.append(url)

    for pattern in _WS_PATTERNS:
        for match in pattern.finditer(js_source or ""):
            add(match.group(1))
    for row in captured_headers or []:
        headers = row.get("headers") if isinstance(row, dict) else None
        if not isinstance(headers, dict):
            continue
        upgrade = str(headers.get("upgrade") or headers.get("Upgrade") or "").lower()
        if upgrade != "websocket":
            continue
        add(str(row.get("url") or row.get("href") or ""))
    return out


def _recv(ws: Any) -> str:
    for name in ("recv", "receive"):
        fn = getattr(ws, name, None)
        if callable(fn):
            try:
                value = fn()
            except Exception:  # noqa: BLE001
                return ""
            if hasattr(value, "__await__"):
                return ""
            return str(value or "")
    return ""


def _send(ws: Any, payload: str) -> None:
    fn = getattr(ws, "send", None)
    if callable(fn):
        fn(payload)


def _close(ws: Any) -> None:
    fn = getattr(ws, "close", None)
    if callable(fn):
        try:
            fn()
        except Exception:  # noqa: BLE001
            pass


def _open_ws(url: str, headers: dict[str, str], connector: Connector | None) -> Any | None:
    if connector is not None:
        try:
            return connector(url, headers)
        except Exception:  # noqa: BLE001
            return None
    try:
        from websockets.sync.client import connect as ws_connect
    except ImportError:
        try:
            import websockets  # noqa: F401
        except ImportError:
            return None
        return None
    try:
        return ws_connect(url, additional_headers=headers)
    except Exception:  # noqa: BLE001
        return None


def _as_cm(ws: Any) -> Any:
    if hasattr(ws, "__enter__"):
        return ws
    class _Wrap:
        def __enter__(self):
            return ws
        def __exit__(self, *exc):
            _close(ws)
            return False
    return _Wrap()


def probe_websocket(
    url: str,
    cookie_header: str = "",
    *,
    connector: Connector | None = None,
    pacer: Pacer | None = None,
    js_source: str = "",
    captured_headers: list[dict] | None = None,
    base_url: str = "",
) -> tuple[list[Finding], list[str]]:
    """Probe discovered WebSocket endpoints. Returns (findings, discovered URLs)."""
    discovered = discover_websocket_urls(
        js_source, base_url=base_url or url, captured_headers=captured_headers
    )
    targets = list(discovered)
    parsed = urlparse(url)
    if parsed.scheme in {"ws", "wss"}:
        if url not in targets:
            targets.insert(0, url)
    elif not targets and parsed.scheme in {"http", "https"}:
        # Direct probe of a WS URL the caller already identified.
        pass

    findings: list[Finding] = []
    cookie = (cookie_header or "").strip()
    if cookie.lower().startswith("cookie:"):
        cookie = cookie.split(":", 1)[1].strip()
    headers = {"Cookie": cookie} if cookie else {}

    for ws_url in targets:
        pace(pacer)
        authed = _open_ws(ws_url, headers, connector)
        if authed is None and not cookie:
            continue
        if authed is not None:
            try:
                with _as_cm(authed) as ws:
                    nonce = secrets.token_hex(4)
                    ping = json.dumps({"type": "ping", "id": f"shroodler-{nonce}"})
                    _send(ws, ping)
                    echoed = _recv(ws)
                    if f"shroodler-{nonce}" in echoed:
                        findings.append(
                            Finding(
                                id="websocket-reflection",
                                severity="low",
                                category="payload",
                                url=ws_url,
                                description="The WebSocket echoed a nonce-tagged ping payload.",
                                evidence=f"nonce={nonce} echo={echoed[:200]}",
                                confidence="confirmed",
                            )
                        )
                    pp_nonce = secrets.token_hex(4)
                    _send(ws, json.dumps({"__proto__": {"shroodlerPP": pp_nonce}}))
                    later = _recv(ws)
                    if "shroodlerPP" in later or pp_nonce in later:
                        findings.append(
                            Finding(
                                id="websocket-prototype-pollution",
                                severity="high",
                                category="payload",
                                url=ws_url,
                                description=(
                                    "A subsequent WebSocket message reflected a "
                                    "prototype-pollution marker."
                                ),
                                evidence=f"nonce={pp_nonce} echo={later[:200]}",
                                confidence="confirmed",
                            )
                        )
            except Exception:  # noqa: BLE001
                pass

        if cookie:
            pace(pacer)
            anon = _open_ws(ws_url, {}, connector)
            if anon is not None:
                findings.append(
                    Finding(
                        id="websocket-missing-auth",
                        severity="high",
                        category="auth",
                        url=ws_url,
                        description="The WebSocket accepted a connection without a session cookie.",
                        evidence="connected without Cookie header",
                        confidence="confirmed",
                    )
                )
                _close(anon)

    return dedupe(findings), targets
