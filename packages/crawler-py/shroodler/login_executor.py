"""Login-recipe executor for the agent loop.

Wraps `shroodler.auth.LoginRecipe` (url/method/fields/content_type plus optional
credentials, extract, verify_url, verify_marker). Template tokens `{{VAR}}` are
filled from recipe credentials or the process environment.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx

from shroodler.auth import (
    LoginRecipe,
    _should_form_login,
    execute_recipe_steps,
    load_login_recipe,
    merge_hidden_fields,
    recipe_from_dict,
    resolve_recipe_url,
)
from shroodler.paced_fetch import pace
from shroodler.pacer import Pacer
from shroodler.program import ProgramState

_VAR_RE = re.compile(r"\{\{(\w+)\}\}")
_TOKEN_NAMES = frozenset({"access_token", "token", "id_token", "jwt", "bearer"})


@dataclass
class LoginResult:
    success: bool
    inject_headers: dict[str, str]
    inject_cookies: dict[str, str]
    extracted: dict[str, str]
    error: str | None = None


def apply_session(
    state: ProgramState,
    headers: dict[str, str] | None,
    cookies: dict[str, str] | list | None,
) -> None:
    """Write login_headers / login_cookies onto ProgramState (runtime, not persisted)."""
    state.login_headers = {str(k): str(v) for k, v in dict(headers or {}).items()}
    state.login_cookies = _cookies_to_dict(cookies)


def apply_peer_session(
    state: ProgramState,
    headers: dict[str, str] | None,
    cookies: dict[str, str] | list | None,
) -> None:
    """Write peer_headers / peer_cookies onto ProgramState (runtime, not persisted).

    Does not touch owner login_headers / login_cookies.
    """
    state.peer_headers = {str(k): str(v) for k, v in dict(headers or {}).items()}
    state.peer_cookies = _cookies_to_dict(cookies)


def _cookies_to_dict(cookies: dict[str, str] | list | None) -> dict[str, str]:
    if not cookies:
        return {}
    if isinstance(cookies, dict):
        return {str(k): str(v) for k, v in cookies.items() if k}
    out: dict[str, str] = {}
    for item in cookies:
        if isinstance(item, dict) and item.get("name"):
            out[str(item["name"])] = str(item.get("value") or "")
        else:
            name = getattr(item, "name", None)
            value = getattr(item, "value", None)
            if name:
                out[str(name)] = str(value or "")
    return out


def _lookup_var(name: str, credentials: dict[str, str], environ: dict[str, str] | None) -> str | None:
    if name in credentials:
        return str(credentials[name])
    env = environ if environ is not None else os.environ
    if name in env:
        return str(env[name])
    return None


def substitute_templates(
    text: str,
    credentials: dict[str, str] | None = None,
    environ: dict[str, str] | None = None,
) -> str:
    creds = dict(credentials or {})

    def repl(match: re.Match[str]) -> str:
        found = _lookup_var(match.group(1), creds, environ)
        return match.group(0) if found is None else found

    return _VAR_RE.sub(repl, text or "")


def _sub_map(values: dict[str, str], credentials: dict[str, str], environ: dict[str, str] | None) -> dict[str, str]:
    return {
        substitute_templates(str(k), credentials, environ): substitute_templates(
            str(v), credentials, environ
        )
        for k, v in values.items()
    }


def _json_path(payload: object, path: str) -> str | None:
    cur: object = payload
    for part in (path or "").split("."):
        if not part:
            continue
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
            continue
        if isinstance(cur, list) and part.isdigit():
            idx = int(part)
            if 0 <= idx < len(cur):
                cur = cur[idx]
                continue
        return None
    if cur is None:
        return None
    if isinstance(cur, (dict, list)):
        return None
    return str(cur)


def _header_value(resp: httpx.Response, name: str) -> str | None:
    if not name:
        return None
    for key, value in resp.headers.items():
        if key.lower() == name.lower():
            return str(value)
    return None


def _cookie_value(resp: httpx.Response, client: httpx.AsyncClient | httpx.Client, name: str) -> str | None:
    if not name:
        return None
    try:
        found = resp.cookies.get(name)
        if found:
            return str(found)
    except Exception:  # noqa: BLE001
        pass
    try:
        found = client.cookies.get(name)
        if found:
            return str(found)
    except Exception:  # noqa: BLE001
        pass
    return None


def _regex_value(body: str, pattern: str) -> str | None:
    if not pattern:
        return None
    try:
        match = re.search(pattern, body or "")
    except re.error:
        return None
    if not match:
        return None
    if match.lastindex:
        return str(match.group(1))
    return str(match.group(0))


def _client_cookies(client: httpx.AsyncClient | httpx.Client) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        for name, value in client.cookies.items():
            out[str(name)] = str(value)
    except Exception:  # noqa: BLE001
        jar = getattr(client.cookies, "jar", None)
        if jar is not None:
            for item in jar:
                if getattr(item, "name", None):
                    out[str(item.name)] = str(item.value or "")
    return out


def _extract_all(
    recipe: LoginRecipe,
    resp: httpx.Response,
    client: httpx.AsyncClient | httpx.Client,
) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    extracted: dict[str, str] = {}
    inject_headers: dict[str, str] = {}
    inject_cookies = _client_cookies(client)
    try:
        for name, value in resp.cookies.items():
            inject_cookies[str(name)] = str(value)
    except Exception:  # noqa: BLE001
        pass

    payload: object | None
    try:
        payload = resp.json()
    except Exception:  # noqa: BLE001
        payload = None
    body = resp.text or ""

    for spec in recipe.extract or []:
        if not isinstance(spec, dict):
            continue
        value: str | None = None
        if spec.get("json") and payload is not None:
            value = _json_path(payload, str(spec.get("json") or ""))
        if value is None and spec.get("cookie"):
            value = _cookie_value(resp, client, str(spec.get("cookie") or ""))
        if value is None and spec.get("header"):
            value = _header_value(resp, str(spec.get("header") or ""))
        if value is None and spec.get("regex"):
            value = _regex_value(body, str(spec.get("regex") or ""))
        if value is None:
            continue
        name = str(spec.get("as") or spec.get("name") or spec.get("json") or spec.get("cookie") or spec.get("header") or "value")
        extracted[name] = value
        dest_header = spec.get("inject_header")
        if dest_header:
            prefix = str(spec.get("inject_prefix") or "")
            inject_headers[str(dest_header)] = f"{prefix}{value}"
        dest_cookie = spec.get("inject_cookie") or (str(spec.get("cookie") or "") if spec.get("cookie") else "")
        if dest_cookie:
            inject_cookies[str(dest_cookie)] = value
        if name.lower() in _TOKEN_NAMES or str(spec.get("json") or "").lower().endswith("access_token"):
            inject_headers.setdefault("Authorization", f"Bearer {value}")

    for key, val in extracted.items():
        if key.lower() in _TOKEN_NAMES:
            inject_headers.setdefault("Authorization", f"Bearer {val}")

    auth = client.headers.get("Authorization")
    if auth:
        inject_headers.setdefault("Authorization", str(auth))
    return extracted, inject_headers, inject_cookies


def _apply_substituted(recipe: LoginRecipe, credentials: dict[str, str], environ: dict[str, str] | None) -> LoginRecipe:
    creds = {**dict(recipe.credentials), **dict(credentials)}
    creds = _sub_map(creds, creds, environ)
    return LoginRecipe(
        url=substitute_templates(recipe.url, creds, environ),
        method=recipe.method,
        fields=_sub_map(recipe.fields, creds, environ),
        include_hidden=recipe.include_hidden,
        logout_url=(
            substitute_templates(recipe.logout_url, creds, environ) if recipe.logout_url else None
        ),
        logout_method=recipe.logout_method,
        protected_url=(
            substitute_templates(recipe.protected_url, creds, environ)
            if recipe.protected_url
            else None
        ),
        content_type=recipe.content_type,
        local_storage=_sub_map(recipe.local_storage, creds, environ),
        auth_marker=(
            substitute_templates(recipe.auth_marker, creds, environ) if recipe.auth_marker else None
        ),
        steps=list(recipe.steps),
        credentials=creds,
        extract=[dict(item) for item in recipe.extract],
        verify_url=(
            substitute_templates(recipe.verify_url, creds, environ) if recipe.verify_url else None
        ),
        verify_marker=(
            substitute_templates(recipe.verify_marker, creds, environ)
            if recipe.verify_marker
            else None
        ),
    )


class LoginExecutor:
    """Run a login recipe over httpx.AsyncClient; sync wrappers for the agent."""

    def __init__(
        self,
        *,
        pacer: Pacer | None = None,
        transport: httpx.BaseTransport | httpx.AsyncBaseTransport | None = None,
        timeout: float = 8.0,
    ) -> None:
        self.pacer = pacer
        self.transport = transport
        self.timeout = timeout

    def _pace(self) -> None:
        pace(self.pacer)

    def _coerce(self, recipe: dict | LoginRecipe | str | Path, seed: str = "") -> LoginRecipe:
        if isinstance(recipe, LoginRecipe):
            loaded = recipe
        elif isinstance(recipe, (str, Path)):
            loaded = load_login_recipe(str(recipe))
        elif isinstance(recipe, dict):
            loaded = recipe_from_dict(recipe)
        else:
            raise TypeError(f"unsupported login recipe type {type(recipe)!r}")
        if seed:
            loaded = resolve_recipe_url(loaded, seed)
        return loaded

    def _client_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "timeout": self.timeout,
            "follow_redirects": True,
        }
        if self.transport is not None:
            kwargs["transport"] = self.transport
        return kwargs

    def _run_steps(self, recipe: LoginRecipe) -> tuple[dict[str, str], dict[str, str]]:
        if not recipe.steps:
            return {}, {}
        sync_kwargs: dict[str, Any] = {
            "timeout": self.timeout,
            "follow_redirects": True,
        }
        transport = self.transport
        if transport is not None and isinstance(transport, httpx.BaseTransport):
            sync_kwargs["transport"] = transport
        with httpx.Client(**sync_kwargs) as client:
            self._pace()
            execute_recipe_steps(client, recipe)
            headers = {str(k): str(v) for k, v in client.headers.items() if k and v}
            return headers, _client_cookies(client)

    async def run(
        self,
        recipe: dict | LoginRecipe | str | Path,
        *,
        seed: str = "",
        credentials: dict[str, str] | None = None,
        environ: dict[str, str] | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> LoginResult:
        try:
            loaded = self._coerce(recipe, seed)
        except Exception as exc:  # noqa: BLE001
            return LoginResult(
                success=False,
                inject_headers={},
                inject_cookies={},
                extracted={},
                error=str(exc),
            )
        loaded = _apply_substituted(loaded, dict(credentials or {}), environ)
        step_headers, step_cookies = {}, {}
        if loaded.steps:
            try:
                step_headers, step_cookies = await asyncio.to_thread(self._run_steps, loaded)
            except Exception as exc:  # noqa: BLE001
                return LoginResult(
                    success=False,
                    inject_headers={},
                    inject_cookies={},
                    extracted={},
                    error=str(exc),
                )

        own = client is None
        http = client or httpx.AsyncClient(**self._client_kwargs())
        try:
            for key, value in step_headers.items():
                if key.lower() in {"authorization", "cookie"} or key.lower().startswith("x-"):
                    http.headers[key] = value
            for name, value in step_cookies.items():
                http.cookies.set(name, value)

            resp: httpx.Response | None = None
            if _should_form_login(loaded):
                fields = dict(loaded.fields)
                use_json = loaded.content_type == "json"
                if loaded.include_hidden and not use_json:
                    self._pace()
                    try:
                        peek = await http.get(loaded.url)
                    except Exception as exc:  # noqa: BLE001
                        return LoginResult(
                            success=False,
                            inject_headers={},
                            inject_cookies=dict(step_cookies),
                            extracted={},
                            error=str(exc),
                        )
                    if peek.status_code < 400 and peek.text:
                        fields = merge_hidden_fields(peek.text, fields)
                method = (loaded.method or "POST").upper()
                self._pace()
                try:
                    if method == "GET":
                        resp = await http.get(loaded.url, params=fields)
                    elif use_json:
                        resp = await http.post(loaded.url, json=fields)
                    else:
                        resp = await http.post(loaded.url, data=fields)
                except Exception as exc:  # noqa: BLE001
                    return LoginResult(
                        success=False,
                        inject_headers={},
                        inject_cookies=dict(step_cookies),
                        extracted={},
                        error=str(exc),
                    )
            elif step_headers or step_cookies:
                extracted, inject_headers, inject_cookies = (
                    {},
                    {k: v for k, v in step_headers.items() if k.lower() == "authorization"},
                    dict(step_cookies),
                )
                return LoginResult(
                    success=True,
                    inject_headers=inject_headers,
                    inject_cookies=inject_cookies,
                    extracted=extracted,
                )
            else:
                return LoginResult(
                    success=False,
                    inject_headers={},
                    inject_cookies={},
                    extracted={},
                    error="login recipe has no form fields or auth steps",
                )

            assert resp is not None
            if resp.status_code in {401, 403} or resp.status_code >= 400:
                return LoginResult(
                    success=False,
                    inject_headers={},
                    inject_cookies=_client_cookies(http),
                    extracted={},
                    error=f"login HTTP {resp.status_code}",
                )

            extracted, inject_headers, inject_cookies = _extract_all(loaded, resp, http)
            for key, value in step_headers.items():
                if key.lower() == "authorization":
                    inject_headers.setdefault("Authorization", value)

            verify_url = loaded.verify_url or loaded.protected_url
            marker = loaded.verify_marker or loaded.auth_marker
            if verify_url:
                ok = await self.verify(
                    verify_url,
                    marker=marker,
                    headers=inject_headers,
                    cookies=inject_cookies,
                    client=http,
                )
                if not ok:
                    return LoginResult(
                        success=False,
                        inject_headers=inject_headers,
                        inject_cookies=inject_cookies,
                        extracted=extracted,
                        error="login verify failed",
                    )

            return LoginResult(
                success=True,
                inject_headers=inject_headers,
                inject_cookies=inject_cookies,
                extracted=extracted,
            )
        finally:
            if own:
                await http.aclose()

    async def verify(
        self,
        url: str,
        *,
        marker: str | None = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        client: httpx.AsyncClient | None = None,
        seed: str = "",
    ) -> bool:
        target = url
        if seed and "://" not in target:
            target = urljoin(seed if "://" in seed else "http://" + seed, target)
        own = client is None
        http = client or httpx.AsyncClient(**self._client_kwargs())
        try:
            req_headers = dict(headers or {})
            req_cookies = dict(cookies or {})
            if req_cookies:
                extra = "; ".join(f"{k}={v}" for k, v in req_cookies.items() if k)
                if extra:
                    existing = req_headers.get("Cookie") or ""
                    req_headers["Cookie"] = f"{existing}; {extra}" if existing else extra
            self._pace()
            try:
                resp = await http.get(target, headers=req_headers)
            except Exception:  # noqa: BLE001
                return False
            if resp.status_code in {401, 403} or resp.status_code >= 400:
                return False
            if marker:
                return str(marker) in (resp.text or "")
            return 200 <= resp.status_code < 400
        finally:
            if own:
                await http.aclose()

    def run_sync(
        self,
        recipe: dict | LoginRecipe | str | Path,
        **kwargs: Any,
    ) -> LoginResult:
        return asyncio.run(self.run(recipe, **kwargs))

    def verify_sync(self, url: str, **kwargs: Any) -> bool:
        return asyncio.run(self.verify(url, **kwargs))
