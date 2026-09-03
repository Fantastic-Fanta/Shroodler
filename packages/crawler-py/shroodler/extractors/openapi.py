from __future__ import annotations

import json

import yaml

from shroodler.urls import origin, same_origin

PROBE_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/openapi.yaml",
    "/swagger.yaml",
)


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
