from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from shroodler.extractors.jwt_audit import audit_jwt, audit_text, crack_weak_secret, find_jwts


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def _sign(header: dict, payload: dict, secret: str, digestmod=hashlib.sha256) -> str:
    h, p = _b64(header), _b64(payload)
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), digestmod).digest()
    s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h}.{p}.{s}"


def test_find_jwts_dedupes_and_matches_shape():
    tok = _sign({"alg": "HS256"}, {"sub": "1"}, "secret")
    text = f"Authorization: Bearer {tok}\nsame again {tok}"
    found = find_jwts(text)
    assert found == [tok]


def test_crack_weak_secret_finds_known_secret():
    tok = _sign({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999}, "changeme")
    assert crack_weak_secret(tok) == "changeme"


def test_crack_weak_secret_returns_none_for_strong_secret():
    tok = _sign({"alg": "HS256"}, {"sub": "1"}, "a-genuinely-random-64-char-secret-nobody-would-guess-ever-12345")
    assert crack_weak_secret(tok) is None


def test_crack_weak_secret_ignores_non_hmac_alg():
    tok = _sign({"alg": "RS256"}, {"sub": "1"}, "secret")
    assert crack_weak_secret(tok) is None


def test_audit_jwt_flags_alg_none():
    tok = _sign({"alg": "none"}, {"sub": "1", "exp": 9999999999}, "")
    findings = audit_jwt(tok, "http://127.0.0.1/")
    ids = {f.id for f in findings}
    assert "jwt-alg-none" in ids
    hit = next(f for f in findings if f.id == "jwt-alg-none")
    assert hit.severity == "critical"


def test_audit_jwt_flags_missing_exp():
    tok = _sign({"alg": "HS256"}, {"sub": "1"}, "a-genuinely-random-64-char-secret-nobody-would-guess-ever-12345")
    findings = audit_jwt(tok, "http://127.0.0.1/")
    ids = {f.id for f in findings}
    assert "jwt-missing-exp" in ids


def test_audit_jwt_flags_long_expiry():
    far_future = int(time.time()) + 60 * 60 * 24 * 400
    tok = _sign(
        {"alg": "HS256"},
        {"sub": "1", "exp": far_future},
        "a-genuinely-random-64-char-secret-nobody-would-guess-ever-12345",
    )
    findings = audit_jwt(tok, "http://127.0.0.1/")
    ids = {f.id for f in findings}
    assert "jwt-long-expiry" in ids


def test_audit_jwt_flags_weak_secret():
    tok = _sign({"alg": "HS256"}, {"sub": "1", "exp": 9999999999}, "secret")
    findings = audit_jwt(tok, "http://127.0.0.1/")
    ids = {f.id for f in findings}
    assert "jwt-weak-secret" in ids


def test_audit_jwt_weak_secret_does_not_leak_recovered_value():
    # The finding must not embed the cracked secret in cleartext -- this
    # ends up in JSON/HTML/SARIF/JUnit reports that circulate far more
    # widely than the vulnerable app itself.
    tok = _sign({"alg": "HS256"}, {"sub": "1", "exp": 9999999999}, "changeme")
    findings = audit_jwt(tok, "http://127.0.0.1/")
    hit = next(f for f in findings if f.id == "jwt-weak-secret")
    assert "changeme" not in hit.description
    assert "changeme" not in (hit.evidence or "")


def test_audit_jwt_clean_token_has_no_findings():
    soon = int(time.time()) + 3600
    tok = _sign(
        {"alg": "HS256"},
        {"sub": "1", "exp": soon},
        "a-genuinely-random-64-char-secret-nobody-would-guess-ever-12345",
    )
    assert audit_jwt(tok, "http://127.0.0.1/") == []


def test_audit_text_scans_all_tokens_in_body():
    weak = _sign({"alg": "HS256"}, {"sub": "1", "exp": 9999999999}, "secret")
    text = f"<script>const t = '{weak}';</script>"
    findings = audit_text(text, "http://127.0.0.1/app.js")
    ids = {f.id for f in findings}
    assert "jwt-weak-secret" in ids


def test_audit_jwt_malformed_token_returns_no_findings():
    assert audit_jwt("not.a.jwt.at.all", "http://127.0.0.1/") == []
    assert audit_jwt("eyJ.not-base64!!.x", "http://127.0.0.1/") == []
