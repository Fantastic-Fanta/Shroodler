"""WebGoat lesson-menu discovery and XHR capture helpers.

WebGoat's attack surface lives behind a JS lesson menu (hash routes on
``/WebGoat/start.mvc`` plus XHR to ``/WebGoat/<Lesson>/attack*``). Static
crawling never clicks those lessons, so ProbeAction had no real
endpoint+param pairs to replay. These helpers parse ``lessonmenu.mvc`` JSON
and turn intercepted browser requests into the shape ``state.endpoints``
stores for probes.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse

from shroodler.urls import origin as origin_of

_STATIC_EXT = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
    ".mp4",
    ".webm",
)
_SKIP_RESOURCE_TYPES = frozenset(
    {
        "stylesheet",
        "image",
        "font",
        "script",
        "media",
        "manifest",
        "websocket",
        "texttrack",
    }
)
_KEEP_RESOURCE_TYPES = frozenset({"xhr", "fetch", "document", "other"})


def is_webgoat_url(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    idx = path.find("/webgoat")
    if idx < 0:
        return False
    rest = path[idx + len("/webgoat") :]
    return rest == "" or rest.startswith("/")


def webgoat_prefix(url: str) -> str:
    """Origin + ``/WebGoat`` prefix (no trailing slash)."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    lower = path.lower()
    idx = lower.find("/webgoat")
    if idx < 0:
        return origin_of(url).rstrip("/")
    end = idx + len("/WebGoat")
    rest = path[end:]
    # "/WebGoatSomething" is not the app prefix.
    if rest and not rest.startswith("/"):
        return origin_of(url).rstrip("/")
    prefix_path = path[:end]
    return parsed._replace(path=prefix_path, query="", fragment="").geturl().rstrip("/")


def start_mvc_url(url: str) -> str:
    return webgoat_prefix(url) + "/start.mvc"


def lessonmenu_url(url: str) -> str:
    return webgoat_prefix(url) + "/service/lessonmenu.mvc"


def parse_lesson_menu(node: Any) -> list[str]:
    """Collect leaf ``link`` values from ``/service/lessonmenu.mvc`` JSON."""
    links: list[str] = []
    if isinstance(node, list):
        for item in node:
            links.extend(parse_lesson_menu(item))
        return links
    if not isinstance(node, dict):
        return links
    children = node.get("children") or node.get("lessons") or []
    if children:
        links.extend(parse_lesson_menu(children))
        return links
    for key in ("link", "url", "path", "nameAsUrl"):
        value = node.get(key)
        if isinstance(value, str) and value.strip():
            links.append(value.strip())
            break
    return links


def lesson_nav_url(webgoat_base: str, link: str) -> str:
    """Map a menu link to a URL Playwright can navigate."""
    raw = (link or "").strip()
    if not raw:
        return ""
    base = webgoat_base.rstrip("/")
    if raw.startswith(("http://", "https://")):
        return raw
    if raw.startswith("#"):
        slug = raw[1:].split(".lesson", 1)[0].strip("/")
        return f"{base}/start.mvc#{slug}" if slug else f"{base}/start.mvc"
    if raw.startswith("/"):
        origin = origin_of(base + "/")
        return urljoin(origin, raw)
    slug = raw
    if ".lesson" in slug:
        slug = slug.split(".lesson", 1)[0]
    if "/" in slug:
        slug = slug.rsplit("/", 1)[-1]
    slug = slug.strip("#")
    if not slug:
        return f"{base}/start.mvc"
    return f"{base}/start.mvc#{slug}"


def lesson_nav_urls(webgoat_base: str, links: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for link in links:
        url = lesson_nav_url(webgoat_base, link)
        if not url or url in seen:
            continue
        seen.add(url)
        out.append(url)
    return out


def endpoint_key(url: str) -> str:
    parsed = urlparse(url)
    return parsed._replace(query="", fragment="").geturl()


def params_from_request(
    url: str,
    method: str,
    post_data: str | None = None,
    content_type: str = "",
) -> list[dict[str, str]]:
    """Query + body params from a captured HTTP request."""
    parsed = urlparse(url)
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": key, "value": value, "in": "query"})
    body = post_data or ""
    if not body:
        return out
    ct = (content_type or "").lower()
    if "application/json" in ct:
        try:
            obj = json.loads(body)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict):
            for key, value in obj.items():
                name = str(key)
                if not name or name in seen:
                    continue
                seen.add(name)
                if isinstance(value, (dict, list)):
                    rendered = json.dumps(value)
                elif value is None:
                    rendered = ""
                else:
                    rendered = str(value)
                out.append({"name": name, "value": rendered, "in": "body"})
        return out
    for key, value in parse_qsl(body, keep_blank_values=True):
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": key, "value": value, "in": "body"})
    return out


def keep_captured(
    url: str,
    method: str,
    resource_type: str = "xhr",
) -> bool:
    """Drop static assets and the main-document GET navigation."""
    rtype = (resource_type or "").lower()
    if rtype in _SKIP_RESOURCE_TYPES:
        return False
    if rtype and rtype not in _KEEP_RESOURCE_TYPES:
        return False
    path = (urlparse(url).path or "").lower()
    if any(path.endswith(ext) for ext in _STATIC_EXT):
        return False
    method_u = (method or "GET").upper()
    if rtype == "document" and method_u == "GET":
        return False
    return True


def captured_endpoint(
    url: str,
    method: str,
    *,
    post_data: str | None = None,
    content_type: str = "",
    resource_type: str = "xhr",
) -> dict[str, Any] | None:
    if not keep_captured(url, method, resource_type):
        return None
    key = endpoint_key(url)
    if not key:
        return None
    return {
        "url": key,
        "method": (method or "GET").upper(),
        "params": params_from_request(url, method, post_data, content_type),
    }


def dedupe_captured(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        url = endpoint_key(str(item.get("url") or ""))
        method = str(item.get("method") or "GET").upper() or "GET"
        if not url:
            continue
        key = (method, url)
        existing = by_key.get(key)
        params = list(item.get("params") or [])
        if existing is None:
            by_key[key] = {"url": url, "method": method, "params": list(params)}
            order.append(key)
            continue
        seen = {str(p.get("name")) for p in existing["params"] if isinstance(p, dict)}
        for param in params:
            if not isinstance(param, dict):
                continue
            name = str(param.get("name") or "")
            if not name or name in seen:
                continue
            existing["params"].append(param)
            seen.add(name)
    return [by_key[k] for k in order]
