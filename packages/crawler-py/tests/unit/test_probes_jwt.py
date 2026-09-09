from __future__ import annotations

import warnings

import jwt

from shroodler.pacer import Pacer
from shroodler.probes.jwt import probe_jwt


def _mint(payload: dict, secret: str = "secret") -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return jwt.encode(payload, secret, algorithm="HS256")


class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers = {}


class FakeClient:
    def __init__(self, handler):
        self.handler = handler

    def request(self, method, url, **kw):
        return self.handler(method, url, kw)

    def close(self):
        pass


def _auth(kw) -> str:
    headers = kw.get("headers") or {}
    return " ".join(str(v) for v in headers.values())


def test_jwt_weak_secret_confirmed():
    token = _mint({"sub": "1", "role": "admin"})

    def handler(method, url, kw):
        blob = _auth(kw)
        if "garbage-signature-not-valid" in blob:
            return FakeResp(401, "denied")
        if blob.count(".") >= 2:
            return FakeResp(200, "welcome")
        return FakeResp(403, "no")

    findings = probe_jwt(
        "http://127.0.0.1/api/me",
        "",
        f"Authorization: Bearer {token}",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = findings[0]
    assert hit.id == "jwt-weak-secret"
    assert hit.severity == "critical"
    assert hit.confidence == "confirmed"
    assert hit.evidence == "secret=secret"
    assert hit.category == "secret"


def test_jwt_skips_when_no_token():
    findings = probe_jwt(
        "http://127.0.0.1/api/me",
        "session=abc",
        "",
        client=FakeClient(lambda *a, **k: FakeResp(200, "ok")),
        pacer=Pacer(0),
    )
    assert findings == []


def test_jwt_no_finding_when_garbage_also_200():
    token = _mint({"sub": "1"})

    findings = probe_jwt(
        "http://127.0.0.1/api/me",
        f"Cookie: access={token}",
        "",
        client=FakeClient(lambda *a, **k: FakeResp(200, "public")),
        pacer=Pacer(0),
    )
    assert findings == []


def test_jwt_network_error_returns_empty():
    token = _mint({"sub": "1"})

    class Boom:
        def request(self, *a, **k):
            raise ConnectionError("down")

        def close(self):
            pass

    findings = probe_jwt(
        "http://127.0.0.1/api/me",
        "",
        f"Authorization: Bearer {token}",
        client=Boom(),
        pacer=Pacer(0),
    )
    assert findings == []
