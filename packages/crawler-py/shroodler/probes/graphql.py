"""Active GraphQL probes: introspection, batching, IDOR, SQLi/SSTI on String args."""

from __future__ import annotations

import json
import re

import httpx

from shroodler.extractors.graphql import INTROSPECTION_QUERY, looks_like_graphql
from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, dedupe, request
from shroodler.probes.sqli import _has_sql_error
from shroodler.probes.ssti import nonce_payload, nonce_prime, ssti_evaluated
from shroodler.urls import origin as origin_of
from shroodler.waf_detect import expand_if_waf

GQL_PATHS = ("/graphql", "/api/graphql", "/gql", "/query")
TYPENAME_QUERY = "{__typename}"
_BATCH_SIZE = 10
_SQLI_PAYLOADS = ("'", "' OR '1'='1")
_SSTI_FIXED = ("{{7*7}}", "49")
_DEFAULT_STRING_TARGETS = (("user", "id"), ("search", "q"), ("search", "query"))
_MAX_STRING_TARGETS = 8
_FIELD_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_STRING_INTROSPECTION = (
    "{__schema{queryType{name}mutationType{name}types{name kind fields{"
    "name args{name type{kind name ofType{kind name ofType{kind name}}}}}}}"
)


def _json_obj(text: str):
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    return data


def _post(
    url: str,
    payload: dict | list,
    cookie_header: str,
    *,
    client: httpx.Client | None,
    pacer: Pacer | None,
) -> httpx.Response | None:
    return request(
        "POST",
        url,
        cookie_header=cookie_header,
        extra_headers={"Content-Type": "application/json", "Accept": "application/json"},
        client=client,
        pacer=pacer,
        json=payload,
    )


def _candidates(url: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    try:
        base = origin_of(url).rstrip("/")
    except Exception:  # noqa: BLE001
        base = ""
    if base:
        for path in GQL_PATHS:
            item = base + path
            if item not in seen:
                seen.add(item)
                out.append(item)
    raw = (url or "").split("#", 1)[0]
    if raw and raw.rstrip("/") not in {item.rstrip("/") for item in out} and raw not in seen:
        seen.add(raw)
        out.append(raw)
    return out


def _is_graphql(resp: httpx.Response | None) -> bool:
    if resp is None:
        return False
    return looks_like_graphql(body_text(resp))


def _unwrap_name(typ) -> str:
    while isinstance(typ, dict):
        name = typ.get("name")
        if isinstance(name, str) and name:
            return name
        typ = typ.get("ofType")
    return ""


def _string_arg_targets(text: str) -> list[tuple[str, str]]:
    obj = _json_obj(text)
    if not isinstance(obj, dict):
        return []
    data = obj.get("data") if isinstance(obj.get("data"), dict) else obj
    schema = data.get("__schema") if isinstance(data, dict) else None
    if not isinstance(schema, dict):
        return []
    query_name = "Query"
    query_type = schema.get("queryType")
    if isinstance(query_type, dict) and isinstance(query_type.get("name"), str):
        query_name = query_type["name"]
    types = schema.get("types")
    if not isinstance(types, list):
        return []
    out: list[tuple[str, str]] = []
    for typ in types:
        if not isinstance(typ, dict) or typ.get("name") != query_name:
            continue
        for field in typ.get("fields") or []:
            if not isinstance(field, dict):
                continue
            fname = field.get("name")
            if not isinstance(fname, str) or not _FIELD_NAME_RE.match(fname):
                continue
            for arg in field.get("args") or []:
                if not isinstance(arg, dict):
                    continue
                aname = arg.get("name")
                if not isinstance(aname, str) or not _FIELD_NAME_RE.match(aname):
                    continue
                if _unwrap_name(arg.get("type")) == "String":
                    out.append((fname, aname))
                    if len(out) >= _MAX_STRING_TARGETS:
                        return out
    return out


def _gql_field(field: str, arg: str, value: str) -> str:
    return "{" + field + "(" + arg + ":" + json.dumps(value) + "){__typename}}"


def _finding(
    *,
    finding_id: str,
    severity: str,
    category: str,
    url: str,
    description: str,
    evidence: str,
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,  # type: ignore[arg-type]
        category=category,  # type: ignore[arg-type]
        url=url,
        description=description,
        evidence=evidence,
        confidence="confirmed",
    )


def _user_record(text: str) -> dict | None:
    obj = _json_obj(text)
    if not isinstance(obj, dict):
        return None
    data = obj.get("data")
    if not isinstance(data, dict):
        return None
    user = data.get("user")
    return user if isinstance(user, dict) and user else None


def probe_graphql(
    url: str,
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    state=None,
    waf_detected: bool = False,
    waf_vendor: str | None = None,
) -> list[Finding]:
    """Probe GraphQL endpoints on the URL's origin (once per caller origin)."""
    findings: list[Finding] = []
    endpoints: list[str] = []
    for candidate in _candidates(url):
        resp = _post(
            candidate,
            {"query": TYPENAME_QUERY},
            cookie_header,
            client=client,
            pacer=pacer,
        )
        if _is_graphql(resp):
            endpoints.append(candidate)

    for endpoint in endpoints:
        intro = _post(
            endpoint,
            {"query": INTROSPECTION_QUERY},
            cookie_header,
            client=client,
            pacer=pacer,
        )
        intro_body = body_text(intro)
        intro_obj = _json_obj(intro_body) if intro is not None else None
        types: list = []
        if isinstance(intro_obj, dict):
            data = intro_obj.get("data")
            if isinstance(data, dict):
                schema = data.get("__schema")
                if isinstance(schema, dict) and isinstance(schema.get("types"), list):
                    types = schema["types"]
        if types:
            names = [
                str(item.get("name"))
                for item in types
                if isinstance(item, dict) and item.get("name")
            ]
            findings.append(
                _finding(
                    finding_id="graphql-introspection-enabled",
                    severity="medium",
                    category="js-endpoint",
                    url=endpoint,
                    description="GraphQL introspection is enabled and returned schema types.",
                    evidence=f"types={len(names)} sample={','.join(names[:5])}",
                )
            )

        rich = _post(
            endpoint,
            {"query": _STRING_INTROSPECTION},
            cookie_header,
            client=client,
            pacer=pacer,
        )
        targets = _string_arg_targets(body_text(rich))
        if not targets:
            targets = list(_DEFAULT_STRING_TARGETS)

        baseline = body_text(
            _post(
                endpoint,
                {"query": TYPENAME_QUERY},
                cookie_header,
                client=client,
                pacer=pacer,
            )
        )
        sqli_hit = False
        ssti_hit = False
        sqli_payloads = expand_if_waf(
            _SQLI_PAYLOADS,
            state=state,
            waf_detected=waf_detected,
            waf_vendor=waf_vendor,
        )
        for field, arg in targets:
            if not sqli_hit:
                for payload in sqli_payloads:
                    resp = _post(
                        endpoint,
                        {"query": _gql_field(field, arg, payload)},
                        cookie_header,
                        client=client,
                        pacer=pacer,
                    )
                    if resp is None:
                        continue
                    if _has_sql_error(body_text(resp)):
                        findings.append(
                            _finding(
                                finding_id="graphql-sqli",
                                severity="critical",
                                category="payload",
                                url=endpoint,
                                description=(
                                    f"GraphQL field {field}.{arg} reflected a SQL error "
                                    "after an injection payload."
                                ),
                                evidence=f"field={field} arg={arg} payload={payload!r}",
                            )
                        )
                        sqli_hit = True
                        break
            if not ssti_hit:
                prime = nonce_prime()
                nonce_tpl, expected = nonce_payload(prime)
                attempts = ((nonce_tpl, expected), _SSTI_FIXED)
                for payload, expect in attempts:
                    for injected in expand_if_waf(
                        (payload,),
                        state=state,
                        waf_detected=waf_detected,
                        waf_vendor=waf_vendor,
                    ):
                        resp = _post(
                            endpoint,
                            {"query": _gql_field(field, arg, injected)},
                            cookie_header,
                            client=client,
                            pacer=pacer,
                        )
                        if ssti_evaluated(body_text(resp), expect, baseline=baseline):
                            findings.append(
                                _finding(
                                    finding_id="graphql-ssti",
                                    severity="critical",
                                    category="payload",
                                    url=endpoint,
                                    description=(
                                        f"GraphQL field {field}.{arg} evaluated a "
                                        "template-injection payload."
                                    ),
                                    evidence=f"field={field} arg={arg} payload={payload!r}",
                                )
                            )
                            ssti_hit = True
                            break
                    if ssti_hit:
                        break
            if sqli_hit and ssti_hit:
                break

        batch = _post(
            endpoint,
            [{"query": TYPENAME_QUERY}] * _BATCH_SIZE,
            cookie_header,
            client=client,
            pacer=pacer,
        )
        if batch is not None and int(batch.status_code) == 200:
            parsed = _json_obj(body_text(batch))
            if isinstance(parsed, list) and len(parsed) >= _BATCH_SIZE:
                findings.append(
                    _finding(
                        finding_id="graphql-batch-enabled",
                        severity="low",
                        category="js-endpoint",
                        url=endpoint,
                        description="GraphQL query batching is enabled (array of operations).",
                        evidence=f"batch_size={len(parsed)}",
                    )
                )

        if cookie_header:
            one = _post(
                endpoint,
                {"query": '{user(id:"1"){email name}}'},
                cookie_header,
                client=client,
                pacer=pacer,
            )
            two = _post(
                endpoint,
                {"query": '{user(id:"2"){email name}}'},
                cookie_header,
                client=client,
                pacer=pacer,
            )
            rec_one = _user_record(body_text(one))
            rec_two = _user_record(body_text(two))
            if rec_one and rec_two and rec_one != rec_two:
                findings.append(
                    _finding(
                        finding_id="graphql-idor",
                        severity="high",
                        category="auth",
                        url=endpoint,
                        description=(
                            "Authenticated GraphQL user(id) returned different "
                            "user records for id 1 and 2 (IDOR)."
                        ),
                        evidence="query=user(id:1|2){email name}",
                    )
                )

    return dedupe(findings)
