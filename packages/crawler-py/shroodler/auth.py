from __future__ import annotations

import base64
import hashlib
import json
import secrets
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse

from shroodler.urls import origin as origin_of


@dataclass
class CookieSpec:
    name: str
    value: str
    domain: str = ""
    path: str = "/"
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None


@dataclass
class RecipeStep:
    """One opt-in step in a login recipe (hook, oauth_pkce, or form)."""

    type: str
    command: str | list[str] | None = None
    token_url: str | None = None
    client_id: str | None = None
    scope: str | None = None
    client_secret: str | None = None
    code: str | None = None
    code_verifier: str | None = None
    redirect_uri: str | None = None
    header_from_file: str | None = None
    header_name: str | None = None


@dataclass
class LoginRecipe:
    url: str
    method: str = "POST"
    fields: dict[str, str] = field(default_factory=dict)
    include_hidden: bool = True
    logout_url: str | None = None
    logout_method: str = "GET"
    protected_url: str | None = None
    content_type: str = "form"  # "form" or "json"
    local_storage: dict[str, str] = field(default_factory=dict)
    # Text that must appear in protected_url body (after JS renders) to
    # confirm auth succeeded.  Handles SPA login overlays that return HTTP 200
    # even when the user is not authenticated.
    auth_marker: str | None = None
    steps: list[RecipeStep] = field(default_factory=list)
    credentials: dict[str, str] = field(default_factory=dict)
    extract: list[dict] = field(default_factory=list)
    verify_url: str | None = None
    verify_marker: str | None = None


def parse_header_lines(lines: list[str] | None) -> dict[str, str]:
    """Parse repeatable `--header 'Name: value'` flags. Last value for a name wins."""
    out: dict[str, str] = {}
    for raw in lines or []:
        if not raw or ":" not in raw:
            continue
        name, value = raw.split(":", 1)
        name = name.strip()
        if name:
            out[name] = value.strip()
    return out


def parse_cookie_pairs(pairs: list[str] | None) -> list[CookieSpec]:
    out: list[CookieSpec] = []
    for raw in pairs or []:
        if not raw or "=" not in raw:
            continue
        name, value = raw.split("=", 1)
        name = name.strip()
        if name:
            out.append(CookieSpec(name=name, value=value.strip()))
    return out


def load_cookie_jar(path: str, default_domain: str = "") -> list[CookieSpec]:
    text = Path(path).read_text(encoding="utf-8")
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return cookies_from_json(json.loads(text), default_domain)
    return cookies_from_netscape(text, default_domain)


def load_storage_state(path: str, default_domain: str = "") -> list[CookieSpec]:
    return cookies_from_json(json.loads(Path(path).read_text(encoding="utf-8")), default_domain)


def _parse_recipe_steps(data: dict) -> list[RecipeStep]:
    raw_steps = data.get("steps")
    steps: list[RecipeStep] = []
    if isinstance(raw_steps, list):
        for item in raw_steps:
            if not isinstance(item, dict) or not item.get("type"):
                continue
            steps.append(_step_from_dict(item))
    hook = data.get("hook")
    if hook:
        if isinstance(hook, dict):
            steps.insert(0, _step_from_dict({**hook, "type": "hook"}))
        else:
            steps.insert(0, _step_from_dict({"type": "hook", "command": hook}))
    if data.get("token_url") or str(data.get("type") or "") == "oauth_pkce":
        already = any(s.type == "oauth_pkce" for s in steps)
        if not already:
            steps.append(
                _step_from_dict(
                    {
                        "type": "oauth_pkce",
                        "token_url": data.get("token_url") or data.get("url"),
                        "client_id": data.get("client_id"),
                        "scope": data.get("scope"),
                        "client_secret": data.get("client_secret"),
                        "code": data.get("code"),
                        "code_verifier": data.get("code_verifier"),
                        "redirect_uri": data.get("redirect_uri"),
                    }
                )
            )
    return steps


def _step_from_dict(item: dict) -> RecipeStep:
    command = item.get("command")
    if isinstance(command, list):
        command = [str(c) for c in command]
    elif command is not None:
        command = str(command)
    return RecipeStep(
        type=str(item.get("type") or ""),
        command=command,
        token_url=str(item["token_url"]) if item.get("token_url") else None,
        client_id=str(item["client_id"]) if item.get("client_id") else None,
        scope=str(item["scope"]) if item.get("scope") else None,
        client_secret=str(item["client_secret"]) if item.get("client_secret") else None,
        code=str(item["code"]) if item.get("code") else None,
        code_verifier=str(item["code_verifier"]) if item.get("code_verifier") else None,
        redirect_uri=str(item["redirect_uri"]) if item.get("redirect_uri") else None,
        header_from_file=str(item["header_from_file"]) if item.get("header_from_file") else None,
        header_name=str(item["header_name"]) if item.get("header_name") else None,
    )


def _normalize_extract(raw: object) -> list[dict]:
    """Accept a list of specs, a name→spec map, or a single spec object."""
    if not raw:
        return []
    if isinstance(raw, list):
        return [dict(item) for item in raw if isinstance(item, dict)]
    if not isinstance(raw, dict):
        return []
    keys = {str(k).lower() for k in raw}
    spec_keys = {"json", "cookie", "header", "regex", "as", "name", "inject_header", "inject_cookie"}
    if keys & spec_keys:
        return [dict(raw)]
    out: list[dict] = []
    for name, spec in raw.items():
        if isinstance(spec, dict):
            row = dict(spec)
            row.setdefault("as", str(name))
            out.append(row)
        elif spec is not None:
            out.append({"as": str(name), "json": str(spec)})
    return out


def recipe_from_dict(data: dict) -> LoginRecipe:
    """Build a LoginRecipe from a JSON object (file contents or in-memory)."""
    if not isinstance(data, dict):
        raise ValueError("login recipe must be a JSON object with a url")
    steps = _parse_recipe_steps(data)
    url = data.get("url")
    if not url:
        for step in steps:
            if step.token_url:
                url = step.token_url
                break
    if not url:
        raise ValueError("login recipe must be a JSON object with a url")
    fields = data.get("fields") or {}
    if not isinstance(fields, dict):
        raise ValueError("login recipe fields must be an object")
    logout_url = data.get("logout_url")
    protected_url = data.get("protected_url")
    content_type = str(data.get("content_type") or "form").lower()
    if content_type not in {"form", "json"}:
        raise ValueError(
            f"login recipe content_type must be 'form' or 'json', got {content_type!r}"
        )
    local_storage = data.get("local_storage") or {}
    if not isinstance(local_storage, dict):
        raise ValueError("login recipe local_storage must be an object")
    auth_marker = data.get("auth_marker")
    credentials = data.get("credentials") or {}
    if not isinstance(credentials, dict):
        raise ValueError("login recipe credentials must be an object")
    verify_url = data.get("verify_url")
    verify_marker = data.get("verify_marker")
    return LoginRecipe(
        url=str(url),
        method=str(data.get("method") or "POST"),
        fields={str(k): str(v) for k, v in fields.items()},
        include_hidden=bool(data.get("include_hidden", True)),
        logout_url=str(logout_url) if logout_url else None,
        logout_method=str(data.get("logout_method") or "GET"),
        protected_url=str(protected_url) if protected_url else None,
        content_type=content_type,
        local_storage={str(k): str(v) for k, v in local_storage.items()},
        auth_marker=str(auth_marker) if auth_marker else None,
        steps=steps,
        credentials={str(k): str(v) for k, v in credentials.items()},
        extract=_normalize_extract(data.get("extract")),
        verify_url=str(verify_url) if verify_url else None,
        verify_marker=str(verify_marker) if verify_marker else None,
    )


def load_login_recipe(path: str) -> LoginRecipe:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("login recipe must be a JSON object with a url")
    return recipe_from_dict(data)


def _json_flag(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes"}
    if isinstance(value, (int, float)):
        return value != 0
    return False


def cookies_from_json(data: object, default_domain: str = "") -> list[CookieSpec]:
    items: object = data
    if isinstance(data, dict):
        items = data.get("cookies") or []
    if not isinstance(items, list):
        return []
    out: list[CookieSpec] = []
    for item in items:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        domain = str(item.get("domain") or default_domain)
        if domain.startswith("."):
            domain = domain[1:]
        same = item.get("sameSite") or item.get("same_site")
        out.append(
            CookieSpec(
                name=str(item["name"]),
                value=str(item.get("value") or ""),
                domain=domain,
                path=str(item.get("path") or "/"),
                secure=_json_flag(item.get("secure")),
                http_only=_json_flag(item.get("httpOnly") or item.get("http_only")),
                same_site=str(same) if same else None,
            )
        )
    return out


def cookies_from_netscape(text: str, default_domain: str = "") -> list[CookieSpec]:
    out: list[CookieSpec] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split("\t")
        if len(parts) < 7:
            parts = raw.split()
        if len(parts) < 7:
            continue
        domain, _flag, path, secure, _exp, name, value = parts[:7]
        domain = domain.lstrip(".") or default_domain
        out.append(
            CookieSpec(
                name=name,
                value=value,
                domain=domain,
                path=path or "/",
                secure=secure.upper() == "TRUE",
            )
        )
    return out


def _resolve_one(url: str | None, seed: str) -> str | None:
    if not url:
        return url
    if "://" not in url:
        return urljoin(seed if "://" in seed else "http://" + seed, url)
    return url


def resolve_recipe_url(recipe: LoginRecipe, seed: str) -> LoginRecipe:
    url = _resolve_one(recipe.url, seed) or recipe.url
    resolved_steps: list[RecipeStep] = []
    for step in recipe.steps:
        token_url = _resolve_one(step.token_url, seed) if step.token_url else step.token_url
        resolved_steps.append(
            RecipeStep(
                type=step.type,
                command=step.command if not isinstance(step.command, list) else list(step.command),
                token_url=token_url,
                client_id=step.client_id,
                scope=step.scope,
                client_secret=step.client_secret,
                code=step.code,
                code_verifier=step.code_verifier,
                redirect_uri=step.redirect_uri,
                header_from_file=step.header_from_file,
                header_name=step.header_name,
            )
        )
    return LoginRecipe(
        url=url,
        method=recipe.method,
        fields=dict(recipe.fields),
        include_hidden=recipe.include_hidden,
        content_type=recipe.content_type,
        logout_url=_resolve_one(recipe.logout_url, seed),
        logout_method=recipe.logout_method,
        protected_url=_resolve_one(recipe.protected_url, seed),
        local_storage=dict(recipe.local_storage),
        auth_marker=recipe.auth_marker,
        steps=resolved_steps,
        credentials=dict(recipe.credentials),
        extract=[dict(item) for item in recipe.extract],
        verify_url=_resolve_one(recipe.verify_url, seed),
        verify_marker=recipe.verify_marker,
    )


_LOGIN_PATH_HINTS = (
    "/login",
    "/signin",
    "/sign-in",
    "/log-in",
    "/auth/",
    "/sso",
    "/session/new",
)


def session_looks_expired(
    status: int,
    location: str | None,
    *,
    page_url: str,
    login_url: str,
) -> bool:
    """True when a mid-crawl response looks like the session died (401 or
    a redirect to the login recipe / a login-ish path). The login URL
    itself never counts -- that would re-auth in a loop on the login page.
    403 is left alone: that is usually authorization, not expiry.
    """
    page_path = (urlparse(page_url).path or "/").rstrip("/") or "/"
    login_path = (urlparse(login_url).path or "/login").rstrip("/") or "/"
    if page_path == login_path:
        return False
    if status == 401:
        return True
    if status in {301, 302, 303, 307, 308} and location:
        loc_path = (urlparse(location).path or "/").rstrip("/").lower() or "/"
        if loc_path == login_path.lower():
            return True
        loc = location.lower()
        return any(hint in loc for hint in _LOGIN_PATH_HINTS)
    return False


def host_of(url: str) -> str:
    return urlparse(url).hostname or "127.0.0.1"


def apply_httpx_cookies(client, cookies: list[CookieSpec], page_url: str) -> None:
    host = host_of(page_url)
    for spec in cookies:
        domain = spec.domain or host
        try:
            client.cookies.set(spec.name, spec.value, domain=domain, path=spec.path or "/")
        except Exception:
            client.cookies.set(spec.name, spec.value)


def playwright_cookie_payload(cookies: list[CookieSpec], page_url: str) -> list[dict]:
    origin = origin_of(page_url)
    out: list[dict] = []
    for spec in cookies:
        item: dict = {
            "name": spec.name,
            "value": spec.value,
            "secure": spec.secure,
            "httpOnly": spec.http_only,
        }
        if spec.domain:
            item["domain"] = spec.domain.lstrip(".")
            item["path"] = spec.path or "/"
        else:
            item["url"] = origin
        if spec.same_site:
            item["sameSite"] = spec.same_site
        out.append(item)
    return out


def merge_hidden_fields(html: str, fields: dict[str, str]) -> dict[str, str]:
    from bs4 import BeautifulSoup

    merged = dict(fields)
    soup = BeautifulSoup(html, "lxml")
    form = soup.find("form")
    if form is None:
        return merged
    for tag in form.find_all("input"):
        if (tag.get("type") or "").lower() != "hidden":
            continue
        name = tag.get("name")
        if name and name not in merged:
            merged[str(name)] = str(tag.get("value") or "")
    return merged


def pkce_pair(verifier: str | None = None) -> tuple[str, str]:
    """Return (code_verifier, S256 code_challenge)."""
    code_verifier = verifier or secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, challenge


def apply_bearer_token(client, token: str) -> None:
    if not token:
        return
    headers = getattr(client, "headers", None)
    if headers is not None:
        headers["Authorization"] = f"Bearer {token}"


def run_hook_step(client, step: RecipeStep) -> None:
    """Run an opt-in shell command from a trusted login recipe.

    A string command is executed via the shell; a list of args is passed
    directly to subprocess (no shell). This is intentional for fetching
    anti-fraud tokens (Castle.io, etc.) and must only be used with recipes
    you trust — it can run arbitrary commands as the current user.
    """
    if not step.command:
        raise ValueError("hook step requires 'command'")
    if isinstance(step.command, list):
        proc = subprocess.run(
            step.command,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    else:
        proc = subprocess.run(
            step.command,
            shell=True,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise ValueError(f"login recipe hook exited {proc.returncode}: {err}")
    value = ""
    if step.header_from_file:
        value = Path(step.header_from_file).read_text(encoding="utf-8").strip()
    elif step.header_name and (proc.stdout or "").strip():
        value = proc.stdout.strip().splitlines()[-1].strip()
    if step.header_name and value:
        headers = getattr(client, "headers", None)
        if headers is not None:
            headers[step.header_name] = value


def run_oauth_pkce_step(client, step: RecipeStep) -> str:
    """Hit a token endpoint (client-credentials or authorization-code+PKCE)
    and inject `Authorization: Bearer <token>` on the client.
    """
    token_url = step.token_url
    client_id = step.client_id
    if not token_url or not client_id:
        raise ValueError("oauth_pkce step requires token_url and client_id")
    data: dict[str, str] = {"client_id": client_id}
    if step.scope:
        data["scope"] = step.scope
    if step.code:
        verifier, _challenge = pkce_pair(step.code_verifier)
        data["grant_type"] = "authorization_code"
        data["code"] = step.code
        data["code_verifier"] = verifier
        data["redirect_uri"] = step.redirect_uri or "http://127.0.0.1/callback"
    else:
        data["grant_type"] = "client_credentials"
        if step.client_secret:
            data["client_secret"] = step.client_secret
        else:
            verifier, challenge = pkce_pair(step.code_verifier)
            data["code_verifier"] = verifier
            data["code_challenge"] = challenge
            data["code_challenge_method"] = "S256"
    res = client.post(token_url, data=data, follow_redirects=True)
    payload: object
    try:
        payload = res.json()
    except Exception as exc:
        raise ValueError(
            f"oauth_pkce token endpoint did not return JSON (status={res.status_code})"
        ) from exc
    token = _access_token_from_payload(payload)
    if not token:
        raise ValueError(
            f"oauth_pkce token endpoint returned no access_token (status={res.status_code})"
        )
    apply_bearer_token(client, token)
    return token


def _access_token_from_payload(payload: object) -> str:
    if isinstance(payload, dict):
        token = payload.get("access_token") or payload.get("token")
        if token:
            return str(token)
        nested = payload.get("data")
        if isinstance(nested, dict):
            token = nested.get("access_token") or nested.get("token")
            if token:
                return str(token)
    return ""


def execute_recipe_steps(client, recipe: LoginRecipe) -> None:
    """Run hook and oauth_pkce steps (not the form POST)."""
    for step in recipe.steps:
        if step.type == "hook":
            run_hook_step(client, step)
        elif step.type == "oauth_pkce":
            run_oauth_pkce_step(client, step)


def _should_form_login(recipe: LoginRecipe) -> bool:
    if recipe.fields or recipe.local_storage:
        return True
    step_types = {s.type for s in recipe.steps}
    if step_types and step_types <= {"hook", "oauth_pkce"}:
        return False
    return True


def run_login_httpx(client, recipe: LoginRecipe) -> None:
    execute_recipe_steps(client, recipe)
    if not _should_form_login(recipe):
        return
    fields = dict(recipe.fields)
    use_json = recipe.content_type == "json"
    if recipe.include_hidden and not use_json:
        res = client.get(recipe.url)
        if res.status_code < 400 and res.text:
            fields = merge_hidden_fields(res.text, fields)
    method = recipe.method.upper()
    if method == "GET":
        client.get(recipe.url, params=fields, follow_redirects=True)
    elif use_json:
        client.post(recipe.url, json=fields, follow_redirects=True)
    else:
        client.post(recipe.url, data=fields, follow_redirects=True)
