"""Register a peer account so AuthzDiff/IDOR can run with two sessions."""

from __future__ import annotations

import secrets
from typing import Any

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import normalize_params, request

_REGISTER_HINTS = (
    "register",
    "signup",
    "sign-up",
    "create-account",
    "new-user",
    "join",
)
_LOGIN_HINTS = ("login", "signin", "sign-in", "sign_in", "session")
_DEFAULT_FIELD_NAMES = ("email", "username", "password", "confirm")
_PEER_PASSWORD = "Shroodler1!Peer"


def detect_registration_url(state: Any) -> str | None:
    explicit = str(getattr(state, "registration_url", None) or "").strip()
    if explicit:
        return explicit
    for url, meta in (getattr(state, "endpoints", None) or {}).items():
        method = str((meta or {}).get("method") or "").upper()
        if method and method != "POST":
            continue
        lowered = str(url or "").lower()
        if any(hint in lowered for hint in _REGISTER_HINTS):
            return str(url)
    return None


def detect_login_url(state: Any, config: Any | None = None) -> str | None:
    recipe_path = str(getattr(config, "login_recipe", None) or "").strip() if config else ""
    if recipe_path:
        try:
            from shroodler.auth import load_login_recipe

            recipe = load_login_recipe(recipe_path)
            if recipe.url:
                return recipe.url
        except Exception:  # noqa: BLE001 - fail closed; fall through to endpoints
            pass
    for url, meta in (getattr(state, "endpoints", None) or {}).items():
        method = str((meta or {}).get("method") or "").upper()
        if method and method != "POST":
            continue
        lowered = str(url or "").lower()
        if any(hint in lowered for hint in _LOGIN_HINTS):
            return str(url)
    return None


def peer_cookie_from_state(state: Any) -> str:
    raw = getattr(state, "peer_session", None)
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    if isinstance(raw, dict):
        name = str(raw.get("name") or "").strip()
        value = str(raw.get("value") if raw.get("value") is not None else "")
        if name:
            return f"{name}={value}"
        header = str(raw.get("cookie") or raw.get("header") or "").strip()
        if header:
            return header
    return ""


def fill_register_params(
    params: list | None,
    username: str,
    password: str,
) -> dict[str, str]:
    names = [item["name"] for item in normalize_params(params)]
    if not names:
        names = list(_DEFAULT_FIELD_NAMES)
    return {name: _fill_value(name, username, password) for name in names}


def _fill_value(name: str, username: str, password: str) -> str:
    lowered = (name or "").lower()
    compact = lowered.replace("-", "").replace("_", "")
    if (
        lowered in {"pass", "passwd", "confirm", "password", "password2"}
        or "password" in compact
        or "passwd" in compact
        or compact in {"pass", "confirm", "password2"}
    ):
        return password
    if (
        lowered in {"email", "username", "user", "login"}
        or "email" in lowered
        or "username" in lowered
    ):
        return username
    return "shroodler-test"


def _cookie_pair_from_response(resp: httpx.Response | None) -> str:
    if resp is None:
        return ""
    headers = getattr(resp, "headers", None)
    if not headers:
        return ""
    raw = ""
    try:
        if hasattr(headers, "get_list"):
            items = headers.get_list("set-cookie") or []
            if items:
                raw = str(items[0] or "")
        if not raw:
            raw = str(headers.get("set-cookie") or headers.get("Set-Cookie") or "")
    except Exception:  # noqa: BLE001
        return ""
    pair = raw.split(";", 1)[0].strip()
    return pair if "=" in pair else ""


def _store_peer_session(state: Any, cookie_header: str) -> None:
    """Expose peer cookies on ProgramState so IDORScan can see them."""
    cookies = _session_from_cookie_header(cookie_header)
    if cookies.get("name"):
        state.peer_cookies = {str(cookies["name"]): str(cookies.get("value") or "")}
    if not getattr(state, "peer_headers", None):
        state.peer_headers = {}


def _session_from_cookie_header(header: str) -> dict[str, str]:
    pair = (header or "").split(";", 1)[0].strip()
    if "=" not in pair:
        return {}
    name, _, value = pair.partition("=")
    name = name.strip()
    if not name:
        return {}
    return {"name": name, "value": value}


def _recipe_field_names(config: Any) -> list[str]:
    path = str(getattr(config, "login_recipe", None) or "").strip()
    if not path:
        return []
    try:
        from shroodler.auth import load_login_recipe

        recipe = load_login_recipe(path)
        return list(recipe.fields.keys())
    except Exception:  # noqa: BLE001
        return []


def _post_form(
    url: str,
    data: dict[str, str],
    *,
    cookie_header: str = "",
    client: httpx.Client | None,
    pacer: Pacer | None,
) -> httpx.Response | None:
    return request(
        "POST",
        url,
        cookie_header=cookie_header,
        client=client,
        pacer=pacer,
        data=data,
    )


def auto_register_peer(
    state: Any,
    config: Any,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    nonce: str | None = None,
) -> list[Finding]:
    """Create a peer account, log in, and store the session on state/config."""
    existing = peer_cookie_from_state(state)
    if existing:
        config.peer_cookie = existing
        _store_peer_session(state, existing)
        return []

    register_url = detect_registration_url(state)
    if not register_url:
        return []

    token = nonce or secrets.token_hex(4)
    username = f"shroodler-peer-{token}@example.com"
    password = _PEER_PASSWORD
    meta = (getattr(state, "endpoints", None) or {}).get(register_url) or {}
    data = fill_register_params(meta.get("params") or [], username, password)
    register_resp = _post_form(
        register_url,
        data,
        client=client,
        pacer=pacer,
    )
    cookie = _cookie_pair_from_response(register_resp)

    login_url = detect_login_url(state, config)
    login_names = _recipe_field_names(config)
    login_meta = (getattr(state, "endpoints", None) or {}).get(login_url or "") or {}
    login_params = login_meta.get("params") or [{"name": n} for n in login_names]
    if login_url:
        login_data = fill_register_params(login_params, username, password)
        login_resp = _post_form(
            login_url,
            login_data,
            client=client,
            pacer=pacer,
        )
        login_cookie = _cookie_pair_from_response(login_resp)
        if login_cookie:
            cookie = login_cookie

    if not cookie:
        return []

    session = _session_from_cookie_header(cookie)
    if not session:
        return []
    state.peer_session = session
    state.registration_url = register_url
    config.peer_cookie = f"{session['name']}={session['value']}"
    _store_peer_session(state, config.peer_cookie)
    return [
        Finding(
            id="peer-account-registered",
            severity="info",
            category="scan-note",
            url=register_url,
            description=(
                f"Registered peer account {username} and stored a session "
                "cookie for authorization-diff."
            ),
            evidence=f"username={username} cookie={session['name']}",
            confidence="confirmed",
        )
    ]
