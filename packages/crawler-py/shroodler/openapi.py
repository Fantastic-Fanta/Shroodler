"""OpenAPI/Swagger spec discovery, parsing, and program-state merge.

Reuses probe path lists and spec loaders from ``extractors.openapi`` so crawl
and the dedicated discover action share one catalog. HTTP is httpx-only and
goes through ``paced_fetch.pace`` before every request.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from shroodler.authz_diff import headers_from_auth_line
from shroodler.extractors.openapi import (
    _is_openapi,
    _load_spec,
    _parse_object,
    probe_urls,
)
from shroodler.models import Finding
from shroodler.paced_fetch import pace
from shroodler.pacer import Pacer
from shroodler.program import ProgramState, _upsert_endpoint
from shroodler.urls import origin, same_origin

_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
_SPEC_HINTS = ("api-docs", "swagger", "openapi", ".json", ".yaml", ".yml")
_SWAGGER_URL = re.compile(
    r"""(?ix)
    ["']?urls?["']?\s*:\s*
    (?:
        \[\s*\{[^[\]]*["']url["']\s*:\s*["']([^"']+)["']
      | ["']([^"']+)["']
    )
    """
)
_SWAGGER_URL_KV = re.compile(
    r"""(?ix)["']?url["']?\s*:\s*["']([^"']+)["']"""
)


@dataclass
class OpenApiEndpoint:
    url: str
    method: str
    params: list[dict] = field(default_factory=list)  # name/in/type/example
    auth_required: bool = False


def spec_urls_from_html(html: str, page_url: str) -> list[str]:
    """Pull swagger-ui ``url:`` / ``urls:`` spec locations out of HTML."""
    if not html or "<" not in html[:4096] and "swagger" not in html.lower():
        # Still scan short config blobs that aren't full documents.
        if "url" not in (html or "").lower():
            return []
    found: list[str] = []
    seen: set[str] = set()
    for match in _SWAGGER_URL.finditer(html or ""):
        raw = match.group(1) or match.group(2) or ""
        _consider_spec_href(raw, page_url, found, seen)
    if not found:
        for match in _SWAGGER_URL_KV.finditer(html or ""):
            _consider_spec_href(match.group(1) or "", page_url, found, seen)
    return found


def _consider_spec_href(raw: str, page_url: str, found: list[str], seen: set[str]) -> None:
    href = (raw or "").strip()
    if not href or href.startswith(("#", "javascript:", "data:", "mailto:")):
        return
    lowered = href.lower()
    if not any(tok in lowered for tok in _SPEC_HINTS) and not href.startswith("/"):
        return
    joined = urljoin(page_url, href)
    parsed = urlparse(joined)
    if parsed.scheme not in {"http", "https"}:
        return
    if joined in seen:
        return
    if page_url and not same_origin(joined, page_url):
        return
    seen.add(joined)
    found.append(joined)


def discover_specs(
    base_url: str,
    *,
    client: httpx.Client | None = None,
    cookie_header: str = "",
    pacer: Pacer | None = None,
) -> list[tuple[str, dict]]:
    """GET common spec paths and return ``(spec_url, spec_dict)`` pairs."""
    headers = headers_from_auth_line(cookie_header)
    headers.setdefault("Accept", "application/json, application/yaml, text/yaml, */*")
    own = client is None
    http = client or httpx.Client(timeout=8.0, follow_redirects=True)
    out: list[tuple[str, dict]] = []
    seen_specs: set[str] = set()
    try:
        candidates = list(probe_urls(base_url))
        queued: list[str] = list(candidates)
        queued_set = set(candidates)
        idx = 0
        while idx < len(queued):
            url = queued[idx]
            idx += 1
            if not same_origin(url, base_url):
                continue
            text, final_url = _fetch_text(http, url, headers, pacer)
            if not text:
                continue
            spec = _load_spec(text)
            if spec is not None:
                key = final_url or url
                if key not in seen_specs:
                    seen_specs.add(key)
                    out.append((key, spec))
                continue
            for href in spec_urls_from_html(text, final_url or url):
                if href not in queued_set and same_origin(href, base_url):
                    queued_set.add(href)
                    queued.append(href)
    except Exception:  # noqa: BLE001 - fail closed; caller still gets what we found
        pass
    finally:
        if own:
            http.close()
    return out


def parse_spec(spec: dict, base_url: str) -> list[OpenApiEndpoint]:
    """Extract method+path endpoints, params, and auth flags from a spec dict."""
    if not isinstance(spec, dict) or not _is_openapi(spec):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    root_security = spec.get("security")
    out: list[OpenApiEndpoint] = []
    seen: set[tuple[str, str]] = set()
    for raw_path, item in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            continue
        path_item = _resolve_ref(spec, item) if isinstance(item, dict) else {}
        if not isinstance(path_item, dict):
            continue
        path_params = _collect_parameters(spec, path_item.get("parameters"))
        for method in _HTTP_METHODS:
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            op = _resolve_ref(spec, op)
            if not isinstance(op, dict):
                continue
            url = _join_operation_url(base_url, spec, raw_path)
            if not url or not same_origin(url, base_url):
                continue
            method_u = method.upper()
            key = (method_u, url)
            if key in seen:
                continue
            seen.add(key)
            params = list(path_params)
            params.extend(_collect_parameters(spec, op.get("parameters")))
            params.extend(_body_params(spec, op))
            params = _dedupe_params(params)
            out.append(
                OpenApiEndpoint(
                    url=url,
                    method=method_u,
                    params=params,
                    auth_required=_operation_auth_required(op, root_security),
                )
            )
    return out


def merge_openapi_into_state(
    state: ProgramState,
    endpoints: list[OpenApiEndpoint],
    spec_url: str,
) -> int:
    """Upsert spec endpoints into program state. Returns the number newly added."""
    from shroodler import program as program_mod

    last_seen = program_mod._now()
    added = 0
    rows: list[dict[str, Any]] = []
    existing_keys = {
        (str(row.get("method") or "").upper(), str(row.get("url") or ""))
        for row in state.openapi_endpoints
        if isinstance(row, dict)
    }
    for ep in endpoints:
        status = _upsert_endpoint(
            state,
            ep.url,
            last_seen,
            method=ep.method,
            params=ep.params,
            source="openapi",
        )
        meta = state.endpoints.get(program_mod._endpoint_key(ep.url))
        if meta is not None:
            meta["auth_required"] = bool(ep.auth_required)
        row = {
            "url": ep.url,
            "method": ep.method,
            "params": list(ep.params),
            "auth_required": bool(ep.auth_required),
        }
        key = (ep.method, ep.url)
        if key not in existing_keys:
            existing_keys.add(key)
            rows.append(row)
        if status == "new":
            added += 1
    if spec_url:
        state.openapi_spec_url = spec_url
    if rows:
        state.openapi_endpoints.extend(rows)
    if spec_url:
        _emit_spec_found(state, spec_url, len(endpoints))
    return added


def endpoint_as_dict(ep: OpenApiEndpoint) -> dict[str, Any]:
    return asdict(ep)


def _emit_spec_found(state: ProgramState, spec_url: str, n: int) -> None:
    finding = Finding(
        id="openapi-spec-found",
        severity="info",
        category="scan-note",
        url=spec_url,
        description=(
            f"OpenAPI/Swagger spec discovered at {spec_url} "
            f"({n} operation{'s' if n != 1 else ''})."
        ),
        evidence=f"endpoints={n} spec={spec_url}",
        confidence="confirmed",
    )
    seen = {(f.id, f.url) for f in state.findings}
    if (finding.id, finding.url) not in seen:
        state.findings.append(finding)


def _fetch_text(
    http: httpx.Client,
    url: str,
    headers: dict[str, str],
    pacer: Pacer | None,
) -> tuple[str, str]:
    pace(pacer)
    try:
        resp = http.request("GET", url, headers=headers)
    except Exception:  # noqa: BLE001
        return "", url
    status = int(getattr(resp, "status_code", 0) or 0)
    if status != 200:
        return "", url
    text = getattr(resp, "text", None)
    if not isinstance(text, str):
        content = getattr(resp, "content", b"") or b""
        if isinstance(content, bytes):
            text = content.decode("utf-8", errors="replace")
        else:
            text = str(content)
    final = str(getattr(resp, "url", "") or url)
    return text, final


def _resolve_ref(spec: dict, obj: object) -> object:
    if not isinstance(obj, dict):
        return obj
    ref = obj.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return obj
    cur: object = spec
    for part in ref[2:].split("/"):
        if not isinstance(cur, dict):
            return obj
        cur = cur.get(part)
    return cur if cur is not None else obj


def _schema_type(schema: object) -> str:
    if not isinstance(schema, dict):
        return ""
    raw = schema.get("type")
    if raw:
        return str(raw)
    if "properties" in schema:
        return "object"
    if "items" in schema:
        return "array"
    return ""


def _example_of(obj: dict, schema: dict | None = None) -> Any:
    if obj.get("example") is not None:
        return obj["example"]
    examples = obj.get("examples")
    if isinstance(examples, dict):
        for val in examples.values():
            if isinstance(val, dict) and "value" in val:
                return val["value"]
            return val
    if isinstance(examples, list) and examples:
        return examples[0]
    if schema:
        if schema.get("example") is not None:
            return schema["example"]
        if schema.get("default") is not None:
            return schema["default"]
    return None


def _param_dict(spec: dict, raw: object) -> dict | None:
    item = _resolve_ref(spec, raw)
    if not isinstance(item, dict):
        return None
    name = str(item.get("name") or "").strip()
    if not name:
        return None
    location = str(item.get("in") or "query")
    schema = item.get("schema")
    schema = _resolve_ref(spec, schema) if isinstance(schema, dict) else schema
    schema_d = schema if isinstance(schema, dict) else {}
    ptype = str(item.get("type") or _schema_type(schema_d) or "")
    example = _example_of(item, schema_d)
    row: dict[str, Any] = {"name": name, "in": location}
    if ptype:
        row["type"] = ptype
    if example is not None:
        row["example"] = example
        row["value"] = str(example)
    else:
        row["value"] = ""
    return row


def _collect_parameters(spec: dict, raw: object) -> list[dict]:
    if not isinstance(raw, list):
        return []
    out: list[dict] = []
    for item in raw:
        parsed = _param_dict(spec, item)
        if parsed is not None:
            out.append(parsed)
    return out


def _properties_as_params(spec: dict, schema: object, location: str) -> list[dict]:
    schema = _resolve_ref(spec, schema)
    if not isinstance(schema, dict):
        return []
    props = schema.get("properties")
    if not isinstance(props, dict):
        return []
    out: list[dict] = []
    for name, sub in props.items():
        key = str(name).strip()
        if not key:
            continue
        sub_d = _resolve_ref(spec, sub) if isinstance(sub, dict) else {}
        if not isinstance(sub_d, dict):
            sub_d = {}
        example = _example_of(sub_d, sub_d)
        row: dict[str, Any] = {"name": key, "in": location, "type": _schema_type(sub_d) or "string"}
        if example is not None:
            row["example"] = example
            row["value"] = str(example)
        else:
            row["value"] = ""
        out.append(row)
    return out


def _body_params(spec: dict, op: dict) -> list[dict]:
    body = op.get("requestBody")
    if isinstance(body, dict):
        body = _resolve_ref(spec, body)
        content = body.get("content") if isinstance(body, dict) else None
        if isinstance(content, dict):
            for key in (
                "application/json",
                "application/x-www-form-urlencoded",
                "multipart/form-data",
            ):
                media = content.get(key)
                if isinstance(media, dict):
                    schema = media.get("schema")
                    params = _properties_as_params(spec, schema, "body")
                    if params:
                        return params
            for media in content.values():
                if isinstance(media, dict):
                    params = _properties_as_params(spec, media.get("schema"), "body")
                    if params:
                        return params
    # Swagger 2 body / formData already collected via parameters; nothing extra.
    return []


def _dedupe_params(params: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for item in params:
        key = (str(item.get("name") or ""), str(item.get("in") or "query"))
        if not key[0] or key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _operation_auth_required(op: dict, root_security: object) -> bool:
    if "security" in op:
        return _security_requires_auth(op.get("security"))
    return _security_requires_auth(root_security)


def _security_requires_auth(security: object) -> bool:
    if not isinstance(security, list) or not security:
        return False
    for req in security:
        if isinstance(req, dict) and req:
            return True
    return False


def _join_operation_url(base_url: str, spec: dict, path: str) -> str:
    base = origin(base_url).rstrip("/")
    prefix = _server_prefix(base_url, spec)
    if not path.startswith("/"):
        path = "/" + path
    return prefix.rstrip("/") + path if prefix else base + path


def _server_prefix(base_url: str, spec: dict) -> str:
    base = origin(base_url).rstrip("/")
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        first = servers[0]
        if isinstance(first, dict):
            server_url = _expand_server_url(first)
            if server_url:
                if re.match(r"^https?://", server_url):
                    if same_origin(server_url, base_url):
                        return server_url.rstrip("/")
                    return ""
                if not server_url.startswith("/"):
                    server_url = "/" + server_url
                return base + server_url.rstrip("/")
    host = str(spec.get("host") or "").strip()
    base_path = str(spec.get("basePath") or "").strip()
    if host or base_path:
        schemes = spec.get("schemes")
        scheme = ""
        if isinstance(schemes, list) and schemes:
            scheme = str(schemes[0] or "")
        parsed = urlparse(base_url)
        scheme = scheme or parsed.scheme or "http"
        host = host or parsed.netloc
        if host and host != parsed.netloc:
            candidate = f"{scheme}://{host}"
            if not same_origin(candidate, base_url):
                return ""
        prefix = f"{scheme}://{host}" if host else base
        if base_path:
            if not base_path.startswith("/"):
                base_path = "/" + base_path
            prefix = prefix.rstrip("/") + base_path.rstrip("/")
        return prefix
    return base


def _expand_server_url(server: dict) -> str:
    raw = str(server.get("url") or "").strip()
    if not raw:
        return ""
    variables = server.get("variables")
    if isinstance(variables, dict):
        for name, spec in variables.items():
            default = ""
            if isinstance(spec, dict):
                default = str(spec.get("default") or "")
            raw = raw.replace("{" + str(name) + "}", default)
    if "{" in raw:
        return ""
    return raw


def parse_spec_text(text: str, base_url: str) -> list[OpenApiEndpoint]:
    """Parse JSON or YAML spec text. Returns [] when the body is not a spec."""
    obj = _parse_object(text) if text else None
    if isinstance(obj, dict):
        return parse_spec(obj, base_url)
    return []
