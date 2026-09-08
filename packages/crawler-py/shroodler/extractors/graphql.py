from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from shroodler.models import Finding, JsEndpoint, Page
from shroodler.modes.static import StaticFetcher
from shroodler.urls import canonical_key, is_loopback_or_local, query_param_names

PROBE_PATHS = ("/graphql", "/api/graphql", "/query")
TYPENAME_QUERY = "{ __typename }"
INTROSPECTION_QUERY = "{ __schema { types { name } } }"
QUERY_FIELDS = '{ __type(name: "Query") { fields { name } } }'
FIELD_ENDPOINT_PREFIX = "graphql-field:"
_MAX_TYPES = 8
_MAX_TYPE_CHARS = 200
_MAX_FIELD_REPLAY = 12
_MAX_FIELD_REPLAY_SUPPLIED = 64


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


def parse_query_fields(text: str) -> list[str]:
    obj = _parse_json_object(text)
    if obj is None:
        return []
    data = obj.get("data")
    if not isinstance(data, dict):
        return []
    typ = data.get("__type")
    if not isinstance(typ, dict):
        return []
    raw = typ.get("fields")
    if not isinstance(raw, list):
        return []
    names: list[str] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if isinstance(name, str) and name and not name.startswith("_"):
            names.append(name)
    return names[:_MAX_FIELD_REPLAY]


def _clean_field_name(name: str) -> str | None:
    name = name.strip()
    if not name or name.startswith("#") or name.startswith("_"):
        return None
    if not name.isidentifier():
        return None
    return name


def _fields_from_type(typ: object) -> list[str]:
    if not isinstance(typ, dict):
        return []
    raw = typ.get("fields")
    if not isinstance(raw, list):
        return []
    names: list[str] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        cleaned = _clean_field_name(str(item.get("name") or ""))
        if cleaned:
            names.append(cleaned)
    return names


def _schema_object(obj: dict) -> dict | None:
    if isinstance(obj.get("__schema"), dict):
        return obj["__schema"]
    data = obj.get("data")
    if isinstance(data, dict) and isinstance(data.get("__schema"), dict):
        return data["__schema"]
    schema = obj.get("schema")
    if isinstance(schema, dict):
        if isinstance(schema.get("__schema"), dict):
            return schema["__schema"]
        if isinstance(schema.get("types"), list):
            return schema
    return None


def parse_clairvoyance_fields(obj: object) -> list[str]:
    """Query-type field names from a Clairvoyance / introspection JSON dump."""
    if isinstance(obj, list):
        names: list[str] = []
        for item in obj:
            if isinstance(item, str):
                cleaned = _clean_field_name(item)
                if cleaned:
                    names.append(cleaned)
        return names
    if not isinstance(obj, dict):
        return []
    schema = _schema_object(obj)
    if schema is not None:
        query_name = "Query"
        query_type = schema.get("queryType")
        if isinstance(query_type, dict) and isinstance(query_type.get("name"), str):
            query_name = query_type["name"]
        types = schema.get("types")
        if isinstance(types, list):
            for typ in types:
                if not isinstance(typ, dict):
                    continue
                if typ.get("name") == query_name:
                    return _fields_from_type(typ)
        return []
    if "Query" in obj:
        return parse_clairvoyance_fields(obj.get("Query"))
    return _fields_from_type(obj)


def load_graphql_field_names(paths: list[str | Path]) -> list[str]:
    """Load Query field names from Clairvoyance JSON and/or a plain wordlist.

    JSON is treated as Clairvoyance/introspection output (or a JSON string
    list). Anything else is a wordlist: one field name per line, `#` comments.
    """
    names: list[str] = []
    seen: set[str] = set()
    for path in paths:
        text = Path(path).read_text(encoding="utf-8")
        stripped = text.lstrip()
        loaded: list[str] = []
        parsed_json = False
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                loaded = parse_clairvoyance_fields(json.loads(text))
                parsed_json = True
            except json.JSONDecodeError:
                loaded = []
        if not loaded and not parsed_json:
            for line in text.splitlines():
                cleaned = _clean_field_name(line.split("#", 1)[0])
                if cleaned:
                    loaded.append(cleaned)
        for name in loaded:
            if name not in seen:
                seen.add(name)
                names.append(name)
    return names


def field_endpoint(name: str) -> str:
    return FIELD_ENDPOINT_PREFIX + name


def field_name_from_endpoint(endpoint: str) -> str | None:
    if endpoint.startswith(FIELD_ENDPOINT_PREFIX):
        return endpoint[len(FIELD_ENDPOINT_PREFIX) :]
    return None


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
    allow_external: bool = False,
) -> tuple[list[Page], list[Finding], list[JsEndpoint]]:
    pages: list[Page] = []
    findings: list[Finding] = []
    endpoints: list[JsEndpoint] = []
    if not is_loopback_or_local(origin) and not allow_external:
        findings.append(
            Finding(
                id="graphql-probe-skipped",
                severity="info",
                category="scan-note",
                url=origin,
                description=(
                    "Active GraphQL discovery/introspection probe was skipped "
                    "because the target is not local and --allow-external was "
                    "not passed."
                ),
                evidence=None,
            )
        )
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
        if is_loopback_or_local(url) or allow_external:
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


def replay_graphql_fields(
    url: str,
    http,
    *,
    lower_headers: dict[str, str],
    field_names: list[str] | None = None,
    enforcer=None,
) -> list[Finding]:
    """POST `{ field }` as the lower-priv session and as anonymous.

    A field that returns GraphQL data for the session but an auth error
    anonymously is the same signal authz-diff uses for HTTP URLs.
    """
    supplied = [_clean_field_name(n) or "" for n in (field_names or [])]
    names = [n for n in supplied if n]
    cap = _MAX_FIELD_REPLAY_SUPPLIED if names else _MAX_FIELD_REPLAY
    if not names:
        posted = http.post(url, json={"query": QUERY_FIELDS}, headers=lower_headers)
        names = parse_query_fields(getattr(posted, "text", "") or "")
    out: list[Finding] = []
    anon_headers = {k: v for k, v in lower_headers.items() if k.lower() != "cookie"}
    for name in names[:cap]:
        if not name.isidentifier():
            continue
        query = "{ " + name + " }"
        if enforcer is not None and not enforcer.check(url)[0]:
            break
        try:
            lower = http.post(url, json={"query": query}, headers=lower_headers)
            anon = http.post(url, json={"query": query}, headers=anon_headers)
        except Exception:
            continue
        lower_obj = _parse_json_object(getattr(lower, "text", "") or "") or {}
        anon_obj = _parse_json_object(getattr(anon, "text", "") or "") or {}
        lower_data = lower_obj.get("data")
        anon_errors = anon_obj.get("errors")
        anon_data = anon_obj.get("data")
        if not isinstance(lower_data, dict) or name not in lower_data:
            continue
        if lower_data.get(name) is None:
            continue
        anon_denied = bool(anon_errors) or anon_data in (None, {})
        if not anon_denied:
            continue
        out.append(
            Finding(
                id="graphql-field-authz",
                severity="high",
                category="auth",
                url=url,
                description=(
                    f"GraphQL field {name} returns data for the lower-privilege "
                    "session but not anonymously — the field is session-gated "
                    "without proving it is the *right* session. Confirm object-level "
                    "authorization on this field."
                ),
                evidence=f"field={name}",
            )
        )
    return out


def _parse_json_object(text: str) -> dict | None:
    if not text or not text.strip():
        return None
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None
