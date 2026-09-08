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
from urllib.parse import parse_qsl, urlencode, urlparse

from bs4 import BeautifulSoup

from shroodler.urls import is_loopback_or_local, same_origin

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
    "RequestVerificationToken",
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
    if "exempt" in folded:
        return False
    if folded in FIELD_NAMES:
        return True
    if folded == "requestverificationtoken":
        return True
    return "csrf" in folded or "xsrf" in folded


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
    for token in sorted(tokens, key=lambda t: rank.get(t.source, 9)):
        if token_value_ok(token.value):
            return token
    return None


def token_value_ok(value: str) -> bool:
    if not value or len(value) > 4096:
        return False
    if any(c in value for c in "\r\n\0;"):
        return False
    return True


def looks_like_csrf_rejection(status: int, body: str) -> bool:
    """Only error statuses. A 200 body that mentions csrf is usually success JSON."""
    if status not in (400, 403, 419, 422):
        return False
    text = body or ""
    if len(text) > 4000:
        text = text[:4000]
    return bool(_REJECT.search(text))


def _replace_csrf_in_json(value: Any, token: CsrfToken, depth: int = 0) -> tuple[Any, bool]:
    if depth > 32:
        return value, False
    if isinstance(value, dict):
        replaced = False
        out = {}
        for key, child in value.items():
            if is_csrf_field_name(str(key)) and not isinstance(child, (dict, list)):
                out[key] = token.value
                replaced = True
            else:
                new_child, child_replaced = _replace_csrf_in_json(child, token, depth + 1)
                out[key] = new_child
                replaced = replaced or child_replaced
        return out, replaced
    if isinstance(value, list):
        replaced = False
        out = []
        for item in value:
            new_item, item_replaced = _replace_csrf_in_json(item, token, depth + 1)
            out.append(new_item)
            replaced = replaced or item_replaced
        return out, replaced
    return value, False


def _json_has_csrf(value: Any, depth: int = 0) -> bool:
    if depth > 32:
        return False
    if isinstance(value, dict):
        for key, child in value.items():
            if is_csrf_field_name(str(key)):
                return True
            if _json_has_csrf(child, depth + 1):
                return True
        return False
    if isinstance(value, list):
        return any(_json_has_csrf(item, depth + 1) for item in value)
    return False


def apply_csrf(
    *,
    headers: dict[str, str],
    body: str,
    token: CsrfToken,
) -> tuple[dict[str, str], str]:
    """Inject the token into headers and, when the body looks like a form or JSON, the body."""
    if not token_value_ok(token.value):
        return dict(headers), body
    out_headers = dict(headers)
    for key in list(out_headers):
        folded = key.lower().replace("_", "-")
        if "csrf" in folded or "xsrf" in folded or folded == "requestverificationtoken":
            out_headers[key] = token.value
    lower = {k.lower() for k in out_headers}
    for name in HEADER_CANDIDATES:
        if name.lower() not in lower:
            out_headers[name] = token.value
            lower.add(name.lower())
    if token.source == "cookie":
        cookie = out_headers.pop("Cookie", None) or out_headers.pop("cookie", None) or ""
        if cookie:
            parts = []
            for part in cookie.split(";"):
                part = part.strip()
                if "=" not in part:
                    if part:
                        parts.append(part)
                    continue
                name, _value = part.split("=", 1)
                if name.strip().lower().replace("-", "_") in COOKIE_NAMES:
                    parts.append(f"{name.strip()}={token.value}")
                else:
                    parts.append(part)
            out_headers["Cookie"] = "; ".join(parts)

    content_type = ""
    for key, value in out_headers.items():
        if key.lower() == "content-type":
            content_type = value.lower()
            break
    stripped = (body or "").lstrip()
    if "multipart/" in content_type or (
        stripped.startswith("--") and "content-disposition" in stripped.lower()
    ):
        return out_headers, body
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return out_headers, body
        data, replaced = _replace_csrf_in_json(data, token)
        if not replaced and isinstance(data, dict):
            data["csrf_token"] = token.value
        return out_headers, json.dumps(data, separators=(",", ":"))

    if "json" in content_type:
        return out_headers, body

    if stripped and "=" in stripped and not stripped.startswith("<"):
        if "urlencoded" not in content_type and content_type and "form" not in content_type:
            return out_headers, body
        pairs = list(parse_qsl(body, keep_blank_values=True))
        names = {k.lower() for k, _ in pairs}
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
    allow_external: bool = False,
    same_origin_as: str = "",
    enforcer: Any = None,
) -> CsrfToken | None:
    """GET `url` and harvest a token. `http` is an httpx.Client-like object."""
    if not csrf_harvest_url_ok(url, allow_external=allow_external):
        return None
    if same_origin_as:
        try:
            if not same_origin(url, same_origin_as):
                return None
        except ValueError:
            return None
    if enforcer is not None:
        ok, _reason = enforcer.check(url)
        if not ok:
            return None
    send_headers = dict(headers or {})
    same = False
    if same_origin_as:
        try:
            same = same_origin(url, same_origin_as)
        except ValueError:
            same = False
    if not same:
        send_headers.pop("Cookie", None)
        send_headers.pop("cookie", None)
    try:
        resp = http.get(url, headers=send_headers, follow_redirects=False)
    except TypeError:
        try:
            resp = http.get(url, headers=send_headers)
        except Exception:
            return None
    except Exception:
        return None
    cookie = ""
    if send_headers:
        cookie = send_headers.get("Cookie") or send_headers.get("cookie") or ""
    set_cookie = ""
    raw = getattr(resp, "headers", None)
    if raw is not None:
        set_cookie = raw.get("set-cookie") or ""
    tokens = extract_csrf_tokens(
        getattr(resp, "text", "") or "",
        cookie_header="; ".join(p for p in (cookie, set_cookie) if p),
    )
    return prefer_token(tokens)


def captured_write_requires_csrf(body: str, headers: dict[str, str] | None = None) -> bool:
    """True when the captured request already carried a CSRF token.

    Fail closed: if the original write needed a token and we cannot harvest
    a fresh one, do not send a tokenless write that the server will reject
    (or worse, that looks like a false-negative IDOR miss).
    """
    if headers:
        for key, value in headers.items():
            folded = str(key).lower().replace("_", "-")
            if "csrf" in folded or "xsrf" in folded or folded == "requestverificationtoken":
                return True
            if folded == "cookie" and _from_cookie_header(str(value or "")):
                return True
    stripped = (body or "").lstrip()
    if not stripped:
        return False
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return False
        return _json_has_csrf(data)
    if "=" in stripped and not stripped.startswith("<"):
        return any(is_csrf_field_name(k) for k, _ in parse_qsl(body, keep_blank_values=True))
    return False


def header_has_csrf(headers: dict[str, str] | None) -> bool:
    if not headers:
        return False
    for key in headers:
        folded = str(key).lower().replace("_", "-")
        if "csrf" in folded or "xsrf" in folded:
            return True
    return False


def csrf_harvest_url_ok(url: str, *, allow_external: bool = False) -> bool:
    """CSRF harvest is a live GET — same local-only default as every other probe."""
    if not url:
        return False
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    if parsed.username or parsed.password:
        return False
    if not parsed.hostname:
        return False
    if not allow_external and not is_loopback_or_local(url):
        return False
    return True
