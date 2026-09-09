from __future__ import annotations

import json
import re

from shroodler.pacer import Pacer
from shroodler.probes.graphql import probe_graphql


class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = {"content-type": "application/json"}


class FakeClient:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.handler(method, url, kw)

    def close(self):
        pass


def _payload(kw):
    return kw.get("json")


_NONCE_RE = re.compile(r"\{\{(\d+)\*7\}\}")


def _schema(types=None, string_args=True):
    query_fields = [
        {
            "name": "user",
            "args": [
                {
                    "name": "id",
                    "type": {"kind": "SCALAR", "name": "String", "ofType": None},
                }
            ],
        }
    ]
    if not string_args:
        query_fields = [{"name": "ping", "args": []}]
    return {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": types
                or [
                    {"name": "Query", "kind": "OBJECT", "fields": query_fields},
                    {"name": "User", "kind": "OBJECT", "fields": []},
                    {"name": "String", "kind": "SCALAR", "fields": None},
                ],
            }
        }
    }


def test_graphql_introspection_enabled():
    def handler(method, url, kw):
        if "/graphql" not in url and "/gql" not in url and "/query" not in url:
            return FakeResp(404, "no")
        body = _payload(kw)
        if isinstance(body, list):
            return FakeResp(400, '{"errors":[{"message":"no batch"}]}')
        query = str((body or {}).get("query") or "")
        if "__schema" in query:
            return FakeResp(200, json.dumps(_schema()))
        if "__typename" in query:
            return FakeResp(200, '{"data":{"__typename":"Query"}}')
        return FakeResp(200, '{"data":{"user":null}}')

    findings = probe_graphql(
        "http://127.0.0.1/app",
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "graphql-introspection-enabled")
    assert hit.severity == "medium"
    assert hit.confidence == "confirmed"
    assert hit.category == "js-endpoint"


def test_graphql_sqli_and_ssti_on_string_args():
    def handler(method, url, kw):
        if "/graphql" not in url:
            return FakeResp(404, "no")
        body = _payload(kw)
        if isinstance(body, list):
            return FakeResp(400, "[]")
        query = str((body or {}).get("query") or "")
        if "__schema{types{name}}" in query.replace(" ", "") or (
            "__schema" in query and "fields" not in query
        ):
            return FakeResp(200, json.dumps(_schema()))
        if "__schema" in query:
            return FakeResp(200, json.dumps(_schema()))
        if "__typename" in query and "user(" not in query:
            return FakeResp(200, '{"data":{"__typename":"Query"}}')
        if "user(" in query and "'" in query:
            return FakeResp(200, "You have an error in your SQL syntax")
        match = _NONCE_RE.search(query)
        if match:
            return FakeResp(200, json.dumps({"data": {"user": str(int(match.group(1)) * 7)}}))
        if "{{7*7}}" in query:
            return FakeResp(200, '{"data":{"user":"49"}}')
        return FakeResp(200, '{"data":{"user":null}}')

    findings = probe_graphql(
        "http://127.0.0.1/graphql",
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    ids = {f.id for f in findings}
    assert "graphql-sqli" in ids
    assert "graphql-ssti" in ids
    sqli = next(f for f in findings if f.id == "graphql-sqli")
    assert sqli.severity == "critical"
    assert sqli.category == "payload"


def test_graphql_batch_enabled():
    def handler(method, url, kw):
        if "/graphql" not in url:
            return FakeResp(404, "no")
        body = _payload(kw)
        if isinstance(body, list):
            items = [{"data": {"__typename": "Query"}} for _ in body]
            return FakeResp(200, json.dumps(items))
        query = str((body or {}).get("query") or "")
        if "__schema" in query:
            return FakeResp(200, '{"errors":[{"message":"introspection disabled"}]}')
        return FakeResp(200, '{"data":{"__typename":"Query"}}')

    findings = probe_graphql(
        "http://127.0.0.1/",
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "graphql-batch-enabled")
    assert hit.severity == "low"
    assert hit.confidence == "confirmed"


def test_graphql_idor_different_users():
    def handler(method, url, kw):
        if "/graphql" not in url:
            return FakeResp(404, "no")
        body = _payload(kw)
        if isinstance(body, list):
            return FakeResp(400, "no")
        query = str((body or {}).get("query") or "")
        if "__schema" in query:
            return FakeResp(200, '{"errors":[{"message":"no"}]}')
        if 'user(id:"1")' in query:
            return FakeResp(200, '{"data":{"user":{"email":"a@x","name":"Ada"}}}')
        if 'user(id:"2")' in query:
            return FakeResp(200, '{"data":{"user":{"email":"b@x","name":"Bob"}}}')
        return FakeResp(200, '{"data":{"__typename":"Query"}}')

    findings = probe_graphql(
        "http://127.0.0.1/",
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "graphql-idor")
    assert hit.severity == "high"
    assert hit.category == "auth"
    assert hit.confidence == "confirmed"


def test_graphql_idor_requires_auth_and_distinct_records():
    def handler(method, url, kw):
        if "/graphql" not in url:
            return FakeResp(404, "no")
        body = _payload(kw)
        if isinstance(body, list):
            return FakeResp(400, "no")
        return FakeResp(200, '{"data":{"__typename":"Query"}}')

    findings = probe_graphql(
        "http://127.0.0.1/",
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert not any(f.id == "graphql-idor" for f in findings)


def test_graphql_network_error_returns_empty():
    class Boom:
        def request(self, *a, **k):
            raise ConnectionError("down")

        def close(self):
            pass

    findings = probe_graphql(
        "http://127.0.0.1/",
        "",
        client=Boom(),
        pacer=Pacer(0),
    )
    assert findings == []
