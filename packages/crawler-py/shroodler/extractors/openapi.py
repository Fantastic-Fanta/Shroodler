from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from shroodler.urls import origin, same_origin

PROBE_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/openapi.yaml",
    "/swagger.yaml",
)

_POSTMAN_VAR = re.compile(r"\{\{[^}]+\}\}")


def probe_urls(start: str) -> list[str]:
    base = origin(start).rstrip("/")
    return [base + path for path in PROBE_PATHS]


def is_probe_url(url: str) -> bool:
    from urllib.parse import urlparse

    return urlparse(url).path in PROBE_PATHS


def parse_spec_paths(text: str) -> list[str]:
    obj = _load_spec(text)
    if not obj:
        return []
    raw = obj.get("paths")
    if not isinstance(raw, dict):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for key in raw:
        if not isinstance(key, str):
            continue
        path = key.strip()
        if not path.startswith("/") or path in seen:
            continue
        seen.add(path)
        out.append(path)
    return out


def urls_from_spec(start: str, text: str) -> list[str]:
    base = origin(start).rstrip("/")
    urls: list[str] = []
    for path in parse_spec_paths(text):
        joined = base + path
        if same_origin(joined, start):
            urls.append(joined)
    return urls


def urls_from_seed_file(start: str, path: str | Path) -> list[str]:
    return urls_from_seed_text(start, Path(path).read_text(encoding="utf-8"))


def urls_from_seed_text(start: str, text: str) -> list[str]:
    """OpenAPI/Swagger *or* Postman collection → same-origin seed URLs."""
    obj = _parse_object(text)
    if not isinstance(obj, dict):
        return []
    if _is_openapi(obj):
        return urls_from_spec(start, text)
    if _is_postman(obj):
        return _urls_from_postman(start, obj)
    return []


def _is_postman(obj: dict) -> bool:
    info = obj.get("info")
    if not isinstance(info, dict):
        return False
    schema = str(info.get("schema") or info.get("_postman_id") or "")
    if "postman" in schema.lower():
        return True
    return isinstance(obj.get("item"), list) and "paths" not in obj


def _urls_from_postman(start: str, obj: dict) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()

    def walk(items: object) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            if "item" in item:
                walk(item.get("item"))
            raw = _postman_raw_url(item.get("request"))
            joined = _join_seed_url(start, raw) if raw else None
            if joined and same_origin(joined, start) and joined not in seen:
                seen.add(joined)
                found.append(joined)

    walk(obj.get("item") or [])
    return found


def _postman_raw_url(req: object) -> str:
    if isinstance(req, str):
        return req
    if not isinstance(req, dict):
        return ""
    url = req.get("url")
    if isinstance(url, str):
        return url
    if isinstance(url, dict):
        if url.get("raw"):
            return str(url["raw"])
        path = url.get("path") or []
        if isinstance(path, list):
            return "/" + "/".join(str(p).lstrip("/") for p in path if p is not None)
    return ""


def _join_seed_url(start: str, raw: str) -> str | None:
    cleaned = _POSTMAN_VAR.sub("", raw).strip()
    if not cleaned:
        return None
    if re.match(r"^https?://[^/]", cleaned):
        return cleaned
    # "{{baseUrl}}/users" → "/users"; a stripped var may leave "https:///users".
    cleaned = re.sub(r"^https?:/+", "/", cleaned)
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    while cleaned.startswith("//"):
        cleaned = cleaned[1:]
    return origin(start).rstrip("/") + cleaned


def _load_spec(text: str) -> dict | None:
    if not text or not text.strip():
        return None
    obj = _parse_object(text)
    if not isinstance(obj, dict):
        return None
    if not _is_openapi(obj):
        return None
    return obj


def _parse_object(text: str) -> object | None:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return None


def _is_openapi(obj: dict) -> bool:
    if not isinstance(obj.get("paths"), dict):
        return False
    if "openapi" in obj:
        return str(obj["openapi"]).startswith("3")
    if "swagger" in obj:
        return str(obj["swagger"]).startswith("2")
    return False
