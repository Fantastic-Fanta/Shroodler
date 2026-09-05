from __future__ import annotations

import datetime
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from shroodler.extractors.tls import check_tls, fetch_leaf_certificate, hostname_matches


def _make_cert(
    *,
    common_name: str = "localhost",
    san: list[str] | None = None,
    not_valid_before: datetime.datetime | None = None,
    not_valid_after: datetime.datetime | None = None,
    self_signed: bool = True,
):
    now = datetime.datetime.now(datetime.timezone.utc)
    not_valid_before = not_valid_before or (now - datetime.timedelta(days=1))
    not_valid_after = not_valid_after or (now + datetime.timedelta(days=365))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]),
            critical=False,
        )
    cert = builder.sign(key, hashes.SHA256())
    return key, cert


class _TLSTestServer:
    def __init__(self, key, cert):
        self._key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self._cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pem") as certfile, \
                tempfile.NamedTemporaryFile(suffix=".pem") as keyfile:
            certfile.write(self._cert_pem)
            certfile.flush()
            keyfile.write(self._key_pem)
            keyfile.flush()
            ctx.load_cert_chain(certfile.name, keyfile.name)
            self._sock.settimeout(0.5)
            while not self._stop:
                try:
                    conn, _ = self._sock.accept()
                except OSError:
                    continue
                try:
                    with ctx.wrap_socket(conn, server_side=True) as tls_conn:
                        tls_conn.recv(1)
                except (ssl.SSLError, OSError):
                    pass

    def stop(self):
        self._stop = True
        self._sock.close()
        self._thread.join(timeout=2)


@pytest.fixture
def tls_server():
    servers: list[_TLSTestServer] = []

    def _start(**cert_kwargs):
        key, cert = _make_cert(**cert_kwargs)
        server = _TLSTestServer(key, cert)
        servers.append(server)
        return server

    yield _start
    for s in servers:
        s.stop()


def test_expired_cert_is_flagged(tls_server):
    now = datetime.datetime.now(datetime.timezone.utc)
    server = tls_server(
        san=["127.0.0.1"],
        not_valid_before=now - datetime.timedelta(days=400),
        not_valid_after=now - datetime.timedelta(days=1),
    )
    findings = check_tls(f"https://127.0.0.1:{server.port}/")
    ids = {f.id for f in findings}
    assert "tls-cert-expired" in ids
    hit = next(f for f in findings if f.id == "tls-cert-expired")
    assert hit.severity == "critical"
    assert hit.category == "tls"


def test_expiring_soon_cert_is_flagged(tls_server):
    now = datetime.datetime.now(datetime.timezone.utc)
    server = tls_server(
        san=["127.0.0.1"],
        not_valid_after=now + datetime.timedelta(days=10),
    )
    findings = check_tls(f"https://127.0.0.1:{server.port}/")
    ids = {f.id for f in findings}
    assert "tls-cert-expiring-soon" in ids
    assert "tls-cert-expired" not in ids


def test_healthy_cert_is_not_flagged_for_expiry(tls_server):
    server = tls_server(san=["127.0.0.1"])
    findings = check_tls(f"https://127.0.0.1:{server.port}/")
    ids = {f.id for f in findings}
    assert "tls-cert-expired" not in ids
    assert "tls-cert-expiring-soon" not in ids


def test_self_signed_cert_is_flagged(tls_server):
    server = tls_server(san=["127.0.0.1"])
    findings = check_tls(f"https://127.0.0.1:{server.port}/")
    ids = {f.id for f in findings}
    assert "tls-cert-self-signed" in ids


def test_hostname_mismatch_is_flagged(tls_server):
    server = tls_server(san=["totally-different-host.example"])
    findings = check_tls(f"https://127.0.0.1:{server.port}/")
    ids = {f.id for f in findings}
    assert "tls-hostname-mismatch" in ids
    hit = next(f for f in findings if f.id == "tls-hostname-mismatch")
    assert "totally-different-host.example" in hit.evidence


def test_matching_san_is_not_flagged_as_mismatch(tls_server):
    server = tls_server(san=["127.0.0.1", "example.com"])
    findings = check_tls(f"https://127.0.0.1:{server.port}/")
    assert "tls-hostname-mismatch" not in {f.id for f in findings}


def test_http_target_is_skipped_entirely(tls_server):
    assert check_tls("http://127.0.0.1:8081/") == []


def test_unreachable_host_returns_no_findings():
    assert fetch_leaf_certificate("127.0.0.1", 1) is None
    assert check_tls("https://127.0.0.1:1/") == []


def test_hostname_matches_exact_and_wildcard():
    _, cert = _make_cert(san=["example.com", "*.example.com"])
    assert hostname_matches("example.com", cert)
    assert hostname_matches("foo.example.com", cert)
    assert not hostname_matches("foo.bar.example.com", cert)
    assert not hostname_matches("evil.com", cert)


def test_hostname_matches_falls_back_to_common_name_when_no_san():
    _, cert = _make_cert(common_name="cn-only.example", san=None)
    assert hostname_matches("cn-only.example", cert)
    assert not hostname_matches("other.example", cert)
