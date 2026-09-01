from __future__ import annotations

import json
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
class LoginRecipe:
    url: str
    method: str = "POST"
    fields: dict[str, str] = field(default_factory=dict)
    include_hidden: bool = True


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


def load_login_recipe(path: str) -> LoginRecipe:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not data.get("url"):
        raise ValueError("login recipe must be a JSON object with a url")
    fields = data.get("fields") or {}
    if not isinstance(fields, dict):
        raise ValueError("login recipe fields must be an object")
    return LoginRecipe(
        url=str(data["url"]),
        method=str(data.get("method") or "POST"),
        fields={str(k): str(v) for k, v in fields.items()},
        include_hidden=bool(data.get("include_hidden", True)),
    )


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
                secure=bool(item.get("secure")),
                http_only=bool(item.get("httpOnly") or item.get("http_only")),
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


def resolve_recipe_url(recipe: LoginRecipe, seed: str) -> LoginRecipe:
    url = recipe.url
    if "://" not in url:
        url = urljoin(seed if "://" in seed else "http://" + seed, url)
    return LoginRecipe(
        url=url,
        method=recipe.method,
        fields=dict(recipe.fields),
        include_hidden=recipe.include_hidden,
    )


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
            item["path"] = spec.path or "/"
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


def run_login_httpx(client, recipe: LoginRecipe) -> None:
    fields = dict(recipe.fields)
    if recipe.include_hidden:
        res = client.get(recipe.url)
        if res.status_code < 400 and res.text:
            fields = merge_hidden_fields(res.text, fields)
    method = recipe.method.upper()
    if method == "GET":
        client.get(recipe.url, params=fields, follow_redirects=True)
    else:
        client.post(recipe.url, data=fields, follow_redirects=True)
