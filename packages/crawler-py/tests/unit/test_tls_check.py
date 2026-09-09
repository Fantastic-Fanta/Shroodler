from __future__ import annotations

from datetime import datetime, timedelta, timezone

from shroodler.tls_check import check_target_tls


class FakeSSLSocket:
    def __init__(self, cert, *, binary=None):
        self._cert = cert
        self._binary = binary

    def getpeercert(self, binary_form=False):
        if binary_form:
            return self._binary
        return self._cert

    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _cert(
    *,
    host="example.com",
    issuer=None,
    not_after=None,
    signature="sha256WithRSAEncryption",
):
    issuer = issuer if issuer is not None else host
    dt = not_after or (datetime.now(timezone.utc) + timedelta(days=365))
    return {
        "subject": ((("commonName", host),),),
        "issuer": ((("commonName", issuer),),),
        "notAfter": dt.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", host),),
        "signatureAlgorithm": signature,
    }


def test_tls_check_skips_http():
    assert check_target_tls("http://example.com/") == []


def test_tls_expired_and_self_signed(monkeypatch):
    expired = datetime.now(timezone.utc) - timedelta(days=2)
    cert = _cert(host="example.com", issuer="example.com", not_after=expired)
    sock = FakeSSLSocket(cert)

    def fake_connect(host, port, timeout=5.0):
        return object()

    def fake_handshake(host, port, *, min_version=None, max_version=None, timeout=5.0):
        fake_connect(host, port, timeout=timeout)
        return sock

    monkeypatch.setattr("shroodler.tls_check.socket.create_connection", fake_connect)
    monkeypatch.setattr("shroodler.tls_check._connect", fake_handshake)

    findings = check_target_tls("https://example.com/")
    ids = {f.id for f in findings}
    assert "tls-cert-expired" in ids
    assert "tls-self-signed" in ids
    expired_hit = next(f for f in findings if f.id == "tls-cert-expired")
    assert expired_hit.severity == "high"
    assert expired_hit.category == "tls"


def test_tls_hostname_mismatch_and_weak_sig(monkeypatch):
    cert = _cert(host="other.example", issuer="CA", signature="sha1WithRSAEncryption")
    sock = FakeSSLSocket(cert)

    def fake_connect(host, port, timeout=5.0):
        return object()

    def fake_handshake(host, port, *, min_version=None, max_version=None, timeout=5.0):
        fake_connect(host, port, timeout=timeout)
        return sock

    monkeypatch.setattr("shroodler.tls_check.socket.create_connection", fake_connect)
    monkeypatch.setattr("shroodler.tls_check._connect", fake_handshake)

    findings = check_target_tls("https://example.com/")
    ids = {f.id for f in findings}
    assert "tls-hostname-mismatch" in ids
    assert "tls-weak-signature" in ids
    mismatch = next(f for f in findings if f.id == "tls-hostname-mismatch")
    assert mismatch.severity == "high"


def test_tls_legacy_versions(monkeypatch):
    cert = _cert(host="example.com", issuer="CA")
    sock = FakeSSLSocket(cert)
    versions = []

    def fake_connect(host, port, timeout=5.0):
        return object()

    def fake_handshake(host, port, *, min_version=None, max_version=None, timeout=5.0):
        fake_connect(host, port, timeout=timeout)
        versions.append((min_version, max_version))
        return sock

    monkeypatch.setattr("shroodler.tls_check.socket.create_connection", fake_connect)
    monkeypatch.setattr("shroodler.tls_check._connect", fake_handshake)

    findings = check_target_tls("https://example.com/")
    ids = {f.id for f in findings}
    assert "tls-v1-enabled" in ids
    assert "tls-v11-enabled" in ids
    assert any(f.severity == "medium" for f in findings if f.id == "tls-v1-enabled")
    assert any(f.severity == "low" for f in findings if f.id == "tls-v11-enabled")


def test_tls_unreachable_is_skipped(monkeypatch):
    def boom(host, port, timeout=5.0):
        raise OSError("refused")

    monkeypatch.setattr("shroodler.tls_check.socket.create_connection", boom)
    assert check_target_tls("https://example.com/") == []
