from __future__ import annotations

import json

from shroodler.pacer import Pacer
from shroodler.probes.mass_assignment import probe_mass_assignment


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


def test_mass_assignment_reflected():
    def handler(method, url, kw):
        payload = kw.get("json") or {}
        if payload.get("role") == "admin":
            return FakeResp(200, json.dumps({"ok": True, "role": "admin", "balance": 999999}))
        return FakeResp(200, json.dumps({"ok": True}))

    findings = probe_mass_assignment(
        "http://127.0.0.1/api/users",
        "POST",
        "",
        content_type="application/json",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "mass-assignment")
    assert hit.severity == "high"
    assert hit.confidence == "confirmed"
    assert hit.category == "auth"


def test_mass_assignment_persistent_on_get():
    store = {}

    def handler(method, url, kw):
        payload = kw.get("json") or {}
        if method == "POST" and payload.get("isAdmin") is True:
            store.update(payload)
            return FakeResp(200, json.dumps({"ok": True, "isAdmin": True}))
        if method == "GET":
            return FakeResp(200, json.dumps(store or {"ok": True}))
        return FakeResp(200, json.dumps({"ok": True}))

    findings = probe_mass_assignment(
        "http://127.0.0.1/api/profile",
        "POST",
        "",
        content_type="application/json",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    ids = {f.id for f in findings}
    assert "mass-assignment" in ids
    persist = next(f for f in findings if f.id == "mass-assignment-persistent")
    assert persist.severity == "critical"
    assert persist.confidence == "confirmed"


def test_mass_assignment_skips_get():
    findings = probe_mass_assignment(
        "http://127.0.0.1/api/users",
        "GET",
        "",
        client=FakeClient(lambda *a, **k: FakeResp(200, "{}")),
        pacer=Pacer(0),
    )
    assert findings == []
