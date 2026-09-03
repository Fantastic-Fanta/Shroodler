from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from shroodler.models import Finding, JsEndpoint, Page
from shroodler.modes.static import StaticFetcher
from shroodler.urls import canonical_key, is_loopback_or_local, query_param_names

PROBE_PATHS = ("/graphql", "/api/graphql", "/query")
TYPENAME_QUERY = "{ __typename }"
INTROSPECTION_QUERY = "{ __schema { types { name } } }"
_MAX_TYPES = 8
_MAX_TYPE_CHARS = 200


def looks_like_graphql(text: str) -> bool:
    obj = _parse_json_object(text)
    if obj is None:
        return False
    data = obj.get("data")
    if isinstance(data, dict) and isinstance(data.get("__typename"), str):
        return True
    errors = obj.get("errors")
    if isinstance(errors, list) and errors:
        return all(isinstance(item, dict) and "message" in item for item in errors)
    return False


def parse_schema_types(text: str) -> list[str]:
    obj = _parse_json_object(text)
    if obj is None:
        return []
    data = obj.get("data")
    if not isinstance(data, dict):
        return []
    schema = data.get("__schema")
    if not isinstance(schema, dict):
        return []
    raw = schema.get("types")
    if not isinstance(raw, list):
        return []
    names: list[str] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if not isinstance(name, str) or not name or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def format_types(names: list[str]) -> str:
    if not names:
        return ""
    shown = names[:_MAX_TYPES]
    text = ", ".join(shown)
    extra = len(names) - len(shown)
    if extra > 0:
        text += f" (+{extra} more)"
    if len(text) > _MAX_TYPE_CHARS:
        text = text[: _MAX_TYPE_CHARS - 3] + "..."
    return text


def probe_graphql(
    origin: str,
    fetcher: StaticFetcher,
    already: set[str],
) -> tuple[list[Page], list[Finding], list[JsEndpoint]]:
    pages: list[Page] = []
    findings: list[Finding] = []
    endpoints: list[JsEndpoint] = []
    if not is_loopback_or_local(origin):
        return pages, findings, endpoints
    base = origin.rstrip("/")
    for path in PROBE_PATHS:
        url = base + path
        key = canonical_key(url)
        body = _probe_typename(fetcher, url)
        if not looks_like_graphql(body):
            continue
        if key not in already:
            already.add(key)
            pages.append(
                Page(
                    url=url,
                    status_code=200,
                    params=query_param_names(url),
                )
            )
        desc = f"GraphQL endpoint responds at {path}"
        types: list[str] = []
        if is_loopback_or_local(url):
            types = parse_schema_types(_probe_introspection(fetcher, url))
        shown = format_types(types)
        if shown:
            desc += f"; types: {shown}"
        findings.append(
            Finding(
                id="js-endpoint",
                severity="info",
                category="js-endpoint",
                url=url,
                description=desc,
                evidence=path,
            )
        )
        endpoints.append(JsEndpoint(source=url, endpoint=path))
    return pages, findings, endpoints


def _probe_typename(fetcher: StaticFetcher, url: str) -> str:
    posted = fetcher.post_json(url, {"query": TYPENAME_QUERY})
    if looks_like_graphql(posted.text):
        return posted.text
    got = fetcher.fetch(_with_query(url, TYPENAME_QUERY))
    if looks_like_graphql(got.text):
        return got.text
    return posted.text or got.text


def _probe_introspection(fetcher: StaticFetcher, url: str) -> str:
    posted = fetcher.post_json(url, {"query": INTROSPECTION_QUERY})
    if posted.text:
        return posted.text
    got = fetcher.fetch(_with_query(url, INTROSPECTION_QUERY))
    return got.text


def _with_query(url: str, query: str) -> str:
    parsed = urlparse(url)
    items = dict(parse_qsl(parsed.query, keep_blank_values=True))
    items["query"] = query
    return urlunparse(parsed._replace(query=urlencode(items)))


def _parse_json_object(text: str) -> dict | None:
    if not text or not text.strip():
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None
