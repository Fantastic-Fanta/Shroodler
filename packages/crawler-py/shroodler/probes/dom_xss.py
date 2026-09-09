"""DOM XSS probes that only fire in a real browser (Playwright).

Skipped silently when Playwright is not importable. Unit tests inject a
mock page and never launch Chromium.
"""

from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from shroodler.models import Finding
from shroodler.paced_fetch import pace
from shroodler.pacer import Pacer
from shroodler.probes.common import dedupe, normalize_params, params_from_url

_SESSION_COOKIE_HINTS = (
    "session",
    "sess",
    "sid",
    "phpsessid",
    "jsessionid",
    "jwt",
    "token",
    "auth",
    "connect.sid",
)


def _payload(nonce: str) -> str:
    return f"<img src=x onerror=window.__shroodler_{nonce}=1>"


def _with_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = list(parse_qsl(parsed.query, keep_blank_values=True))
    replaced = False
    out: list[tuple[str, str]] = []
    for key, existing in pairs:
        if key == name and not replaced:
            out.append((key, value))
            replaced = True
        else:
            out.append((key, existing))
    if not replaced:
        out.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(out, safe="")))


def _looks_session_cookie(blob: str) -> bool:
    lowered = (blob or "").lower()
    return any(hint in lowered for hint in _SESSION_COOKIE_HINTS)


def _eval(page: Any, expression: str) -> Any:
    try:
        return page.evaluate(expression)
    except Exception:  # noqa: BLE001 - fail closed
        return None


def _payload_executed(page: Any, nonce: str) -> bool:
    value = _eval(page, f"window.__shroodler_{nonce}")
    if value == 1 or value == "1" or value is True:
        return True
    value = _eval(page, f"window.__shroodler_{nonce}==1")
    return value is True or value == 1 or value == "1"


def _cookie_blob(page: Any) -> str:
    value = _eval(page, "document.cookie")
    return str(value or "")


def _launch_page(cookie_header: str) -> tuple[Any, Any] | None:
    """Return (page, closer) or None if Playwright is unavailable."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    try:
        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context()
        header = (cookie_header or "").strip()
        if header.lower().startswith("cookie:"):
            header = header.split(":", 1)[1].strip()
        cookies = []
        for part in header.split(";"):
            item = part.strip()
            if "=" not in item:
                continue
            name, value = item.split("=", 1)
            cookies.append(
                {
                    "name": name.strip(),
                    "value": value.strip(),
                    "url": "http://127.0.0.1/",
                }
            )
        if cookies:
            try:
                context.add_cookies(cookies)
            except Exception:  # noqa: BLE001
                pass
        page = context.new_page()

        def closer() -> None:
            try:
                context.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                browser.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                pw.stop()
            except Exception:  # noqa: BLE001
                pass

        return page, closer
    except Exception:  # noqa: BLE001 - skip silently
        return None


def probe_dom_xss(
    url: str,
    method: str,
    params: list[dict],
    cookie_header: str,
    *,
    page: Any | None = None,
    pacer: Pacer | None = None,
) -> list[Finding]:
    """Inject an onerror img payload and eval it in a headless page."""
    method_u = (method or "GET").upper()
    if method_u not in {"GET", "POST"}:
        return []
    normalized = normalize_params(params) or params_from_url(url)
    if not normalized:
        return []

    own_page = page is None
    closer = None
    if page is None:
        launched = _launch_page(cookie_header)
        if launched is None:
            return []
        page, closer = launched

    findings: list[Finding] = []
    try:
        for item in normalized:
            name = item["name"]
            nonce = secrets.token_hex(4)
            marker = _payload(nonce)
            target = _with_param(url, name, marker)
            pace(pacer)
            try:
                page.goto(target, wait_until="load", timeout=8000)
            except Exception:  # noqa: BLE001 - fail closed
                continue
            if not _payload_executed(page, nonce):
                continue
            findings.append(
                Finding(
                    id="dom-xss",
                    severity="high",
                    category="payload",
                    url=url,
                    description=(
                        f"{method_u} parameter {name!r} executed a DOM XSS payload "
                        "in the page context."
                    ),
                    evidence=f"param={name} nonce={nonce}",
                    confidence="confirmed",
                )
            )
            cookies = _cookie_blob(page)
            if cookies and _looks_session_cookie(cookies):
                findings.append(
                    Finding(
                        id="dom-xss-cookie-accessible",
                        severity="critical",
                        category="payload",
                        url=url,
                        description=(
                            "DOM XSS executed and non-HttpOnly session cookies "
                            "were readable via document.cookie."
                        ),
                        evidence=f"param={name} nonce={nonce} cookies={cookies[:200]}",
                        confidence="confirmed",
                    )
                )
    finally:
        if own_page and closer is not None:
            closer()

    return dedupe(findings)
