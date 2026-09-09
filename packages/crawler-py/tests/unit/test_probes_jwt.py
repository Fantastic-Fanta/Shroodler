from __future__ import annotations

import base64
import hashlib
import hmac
import json
import warnings

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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


def _token_in(blob: str) -> str:
    for word in blob.replace(",", " ").split():
        if word.count(".") >= 1 and len(word) > 8:
            return word
    return blob


def test_jwt_alg_none_elevated_access():
    token = _mint({"sub": "1", "role": "user"}, secret="not-a-weak-secret-value")

    def handler(method, url, kw):
        blob = _auth(kw)
        if "garbage-signature-not-valid" in blob:
            return FakeResp(401, "denied")
        raw = _token_in(blob)
        try:
            header = jwt.get_unverified_header(raw)
            payload = jwt.decode(raw, options={"verify_signature": False})
        except Exception:
            return FakeResp(403, '{"error":"forbidden"}')
        if str(header.get("alg") or "").lower() == "none" and payload.get("role") == "admin":
            return FakeResp(200, '{"role":"admin","flags":true}')
        return FakeResp(403, '{"error":"forbidden"}')

    findings = probe_jwt(
        "http://127.0.0.1/api/me",
        "",
        f"Authorization: Bearer {token}",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "jwt-alg-none")
    assert hit.severity == "critical"
    assert hit.confidence == "confirmed"
    assert hit.category == "secret"


def test_jwt_algorithm_confusion_rs256_to_hs256():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    numbers = private_key.public_key().public_numbers()

    def _b64(n: int) -> str:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    jwk = {"kty": "RSA", "kid": "k1", "n": _b64(numbers.n), "e": _b64(numbers.e)}
    token = jwt.encode({"sub": "1", "role": "user"}, private_key, algorithm="RS256")

    def handler(method, url, kw):
        if (
            url.endswith("/jwks.json")
            or "/.well-known/jwks.json" in url
            or url.endswith("/api/auth/keys")
        ):
            return FakeResp(200, json.dumps({"keys": [jwk]}))
        blob = _auth(kw)
        if "garbage-signature-not-valid" in blob:
            return FakeResp(401, "denied")
        raw = _token_in(blob)
        try:
            header = jwt.get_unverified_header(raw)
        except Exception:
            return FakeResp(403, "no")
        if str(header.get("alg") or "").upper() == "HS256":
            parts = raw.split(".")
            if len(parts) != 3:
                return FakeResp(401, "bad")
            msg = f"{parts[0]}.{parts[1]}".encode()
            sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
            mac = hmac.new(public_pem, msg, hashlib.sha256).digest()
            if hmac.compare_digest(sig, mac):
                return FakeResp(200, '{"confused":true}')
            return FakeResp(401, "bad")
        return FakeResp(403, '{"error":"forbidden"}')

    findings = probe_jwt(
        "http://127.0.0.1/api/me",
        "",
        f"Authorization: Bearer {token}",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "jwt-algorithm-confusion")
    assert hit.severity == "critical"
    assert hit.confidence == "confirmed"


def test_jwt_kid_injection_empty_secret():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        token = jwt.encode(
            {"sub": "1"},
            "not-a-weak-secret-value",
            algorithm="HS256",
            headers={"kid": "key-1"},
        )

    def handler(method, url, kw):
        blob = _auth(kw)
        if "garbage-signature-not-valid" in blob:
            return FakeResp(401, "denied")
        raw = _token_in(blob)
        try:
            header = jwt.get_unverified_header(raw)
        except Exception:
            return FakeResp(403, "no")
        if header.get("kid") == "../../dev/null":
            try:
                jwt.decode(raw, "", algorithms=["HS256"])
                return FakeResp(200, '{"ok":true}')
            except Exception:
                parts = raw.split(".")
                if len(parts) != 3:
                    return FakeResp(401, "no")
                msg = f"{parts[0]}.{parts[1]}".encode()
                sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
                mac = hmac.new(b"", msg, hashlib.sha256).digest()
                if hmac.compare_digest(sig, mac):
                    return FakeResp(200, '{"ok":true}')
                return FakeResp(401, "no")
        return FakeResp(403, '{"error":"forbidden"}')

    findings = probe_jwt(
        "http://127.0.0.1/api/me",
        "",
        f"Authorization: Bearer {token}",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "jwt-kid-injection")
    assert hit.severity == "critical"
    assert hit.confidence == "confirmed"
    assert "../../dev/null" in (hit.evidence or "")
