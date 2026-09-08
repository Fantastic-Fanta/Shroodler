"""Harvest CSRF tokens and attach them to writes.

Modern cookie-auth APIs reject POST/PUT/PATCH without a token from a
hidden input, a meta tag, a cookie, or a JS global. peer-write and the
payload tester used to send the captured body as-is and record
write-failure. This module finds the token and puts it back.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode

from bs4 import BeautifulSoup

FIELD_NAMES = frozenset(
    {
        "csrf",
        "csrf_token",
        "csrftoken",
        "csrfmiddlewaretoken",
        "xsrf",
        "xsrf_token",
        "xsrf-token",
        "_token",
        "_csrf",
        "authenticity_token",
        "__requestverificationtoken",
        "anticsrf",
        "anti_csrf",
    }
)
META_NAMES = frozenset(
    {
        "csrf-token",
        "csrf_token",
        "xsrf-token",
        "xsrf_token",
        "_csrf",
        "csrf-param",
    }
)
COOKIE_NAMES = frozenset(
    {
        "csrftoken",
        "csrf_token",
        "csrf",
        "xsrf-token",
        "xsrf_token",
        "_csrf",
        "__requestverificationtoken",
    }
)
HEADER_CANDIDATES = (
    "X-CSRF-Token",
    "X-CSRFToken",
    "X-XSRF-TOKEN",
)

_JS_ASSIGN = re.compile(
    r"""(?:csrf[_-]?token|xsrf[_-]?token|authenticity_token)\s*[:=]\s*['"]([^'"]{8,})['"]""",
    re.I,
)
_JS_DOT = re.compile(
    r"""(?:window\.)?[A-Za-z_][\w.]*\.(?:csrf_token|csrfToken|xsrf_token)\s*=\s*['"]([^'"]{8,})['"]""",
    re.I,
)
_REJECT = re.compile(
    r"csrf|xsrf|authenticity.token|missing[_ ]token|token mismatch|invalid token",
    re.I,
)


@dataclass(frozen=True)
class CsrfToken:
    name: str
    value: str
    source: str  # "form" | "meta" | "cookie" | "js"


def is_csrf_field_name(name: str) -> bool:
    folded = (name or "").lower().replace("-", "_")
    return folded in FIELD_NAMES or "csrf" in folded or "xsrf" in folded


def _from_html(html: str) -> list[CsrfToken]:
    if not html or "<" not in html:
        return []
    soup = BeautifulSoup(html, "lxml")
    out: list[CsrfToken] = []
    for tag in soup.find_all("input"):
        name = str(tag.get("name") or "")
        value = str(tag.get("value") or "")
        if value and is_csrf_field_name(name):
            out.append(CsrfToken(name=name, value=value, source="form"))
    for tag in soup.find_all("meta"):
        name = str(tag.get("name") or tag.get("property") or "").lower()
        value = str(tag.get("content") or "")
        if value and name in META_NAMES:
            out.append(CsrfToken(name=name, value=value, source="meta"))
    return out


def _from_js(text: str) -> list[CsrfToken]:
    if not text:
        return []
    out: list[CsrfToken] = []
    for pat in (_JS_DOT, _JS_ASSIGN):
        for match in pat.finditer(text):
            out.append(CsrfToken(name="csrf_token", value=match.group(1), source="js"))
    return out


def _from_cookie_header(cookie_header: str) -> list[CsrfToken]:
    out: list[CsrfToken] = []
    for part in (cookie_header or "").split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        value = value.strip()
        if value and name.lower().replace("-", "_") in COOKIE_NAMES:
            out.append(CsrfToken(name=name, value=value, source="cookie"))
    return out


def extract_csrf_tokens(
    html: str = "",
    *,
    cookie_header: str = "",
) -> list[CsrfToken]:
    """Return tokens in preference order: form, meta, js, cookie."""
    found = _from_html(html) + _from_js(html) + _from_cookie_header(cookie_header)
    seen: set[tuple[str, str]] = set()
    out: list[CsrfToken] = []
    for token in found:
        key = (token.source, token.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(token)
    return out


def prefer_token(tokens: list[CsrfToken]) -> CsrfToken | None:
    if not tokens:
        return None
    rank = {"form": 0, "meta": 1, "js": 2, "cookie": 3}
    return sorted(tokens, key=lambda t: rank.get(t.source, 9))[0]


def looks_like_csrf_rejection(status: int, body: str) -> bool:
    if status not in (400, 403, 419, 422):
        if status != 200:
            return False
    text = body or ""
    if len(text) > 4000:
        text = text[:4000]
    return bool(_REJECT.search(text))


def apply_csrf(
    *,
    headers: dict[str, str],
    body: str,
    token: CsrfToken,
) -> tuple[dict[str, str], str]:
    """Inject the token into headers and, when the body looks like a form or JSON, the body."""
    out_headers = dict(headers)
    lower = {k.lower() for k in out_headers}
    for name in HEADER_CANDIDATES:
        if name.lower() not in lower:
            out_headers[name] = token.value
            lower.add(name.lower())

    stripped = (body or "").lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return out_headers, body
        if isinstance(data, dict):
            for key in ("csrf_token", "csrf", "_token", "authenticity_token"):
                if key not in data:
                    data[key] = token.value
                    break
            return out_headers, json.dumps(data, separators=(",", ":"))
        return out_headers, body

    if stripped and "=" in stripped and not stripped.startswith("<"):
        pairs = list(parse_qsl(body, keep_blank_values=True))
        names = {k.lower() for k, _ in pairs}
        # Cookie/meta/JS names are rarely the form field (Django's cookie is
        # csrftoken; the field is csrfmiddlewaretoken). Only form-sourced
        # tokens keep their original input name.
        field = (
            token.name
            if token.source == "form" and is_csrf_field_name(token.name)
            else "csrf_token"
        )
        if field.lower() not in names and "csrf" not in " ".join(names) and "xsrf" not in " ".join(
            names
        ):
            pairs.append((field, token.value))
        else:
            pairs = [
                (k, token.value if is_csrf_field_name(k) else v) for k, v in pairs
            ]
        return out_headers, urlencode(pairs)

    return out_headers, body


def refresh_csrf(
    http: Any,
    url: str,
    *,
    headers: dict[str, str] | None = None,
) -> CsrfToken | None:
    """GET `url` and harvest a token. `http` is an httpx.Client-like object."""
    if not url:
        return None
    try:
        resp = http.get(url, headers=headers or {})
    except Exception:
        return None
    cookie = ""
    if headers:
        cookie = headers.get("Cookie") or headers.get("cookie") or ""
    set_cookie = ""
    raw = getattr(resp, "headers", None)
    if raw is not None:
        set_cookie = raw.get("set-cookie") or ""
    tokens = extract_csrf_tokens(
        getattr(resp, "text", "") or "",
        cookie_header="; ".join(p for p in (cookie, set_cookie) if p),
    )
    return prefer_token(tokens)
