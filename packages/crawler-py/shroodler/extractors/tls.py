"""TLS certificate checks: expiry, self-signed, hostname mismatch.

Runs once per crawl against the target's origin (not per-page -- the
certificate is a property of the host:port, not of any one URL). This is
independent of the crawl's own HTTP client, which uses httpx with default
certificate verification: a genuinely expired/self-signed/mismatched cert
would make httpx refuse the connection outright (SSLError), so the crawl
itself never observes these conditions -- this module opens its own
verification-disabled connection specifically to still report on why.

Deliberately uses the `cryptography` library to parse the leaf certificate
rather than classifying by matching Python/OpenSSL's own verification
error *message* text: that text is not a stable, version-independent
format ("self signed certificate" vs. "self-signed certificate in
certificate chain" vary across OpenSSL/Python releases), so string-matching
it would be exactly the kind of unreliable proxy-for-truth the round-1
review flagged elsewhere in this codebase. Parsing notAfter/issuer/subject/
SAN directly off the DER bytes is deterministic and version-independent.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509

from shroodler.models import Finding

_EXPIRING_SOON_DAYS = 30
_CONNECT_TIMEOUT = 5.0


def _finding(fid: str, severity: str, target_url: str, description: str, evidence: str) -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        category="tls",
        url=target_url,
        description=description,
        evidence=evidence,
    )


def fetch_leaf_certificate(host: str, port: int, timeout: float = _CONNECT_TIMEOUT):
    """Return the peer's leaf certificate, or None if the TCP/TLS handshake
    itself fails (host down, port closed, protocol mismatch -- none of
    which is this module's concern; the crawl's own connection attempt
    will have already surfaced that separately)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    if not der:
        return None
    return x509.load_der_x509_certificate(der)


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return list(ext.value.get_values_for_type(x509.DNSName))


def _san_ip_addresses(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return [str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress)]


def _as_ip_literal(host: str) -> str | None:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def _common_names(cert: x509.Certificate) -> list[str]:
    return [
        attr.value
        for attr in cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if isinstance(attr.value, str)
    ]


def hostname_matches(host: str, cert: x509.Certificate) -> bool:
    """RFC 6125-style match: exact or a single-label leftmost wildcard.

    An IP-literal host (Shroodler's own default posture is scanning
    127.0.0.1/localhost) is matched exactly against the cert's
    iPAddress SAN entries instead -- RFC 6125 ss.1.7.2 requires IP
    addresses to be carried as iPAddress SANs, never as dNSName strings
    or the CN, and forbids wildcarding for them, so this deliberately
    does not fall through to the DNS-name matching below (a cert with no
    matching IP SAN is a mismatch regardless of what its CN/DNS SANs say).

    SAN DNS names take precedence per RFC 6125/CA-Browser-Forum baseline
    requirements; the CN is only consulted when there is no SAN at all
    (a legacy-cert shape, but a real one browsers also fall back for).
    """
    ip_literal = _as_ip_literal(host)
    if ip_literal is not None:
        return ip_literal in _san_ip_addresses(cert)
    host = host.lower().rstrip(".")
    names = _sans(cert) or _common_names(cert)
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[2:]
            host_label, _, host_rest = host.partition(".")
            if host_rest == suffix and host_label:
                return True
    return False


def check_tls(target_url: str) -> list[Finding]:
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        return []
    host = parsed.hostname
    if not host:
        return []
    port = parsed.port or 443

    cert = fetch_leaf_certificate(host, port)
    if cert is None:
        return []

    findings: list[Finding] = []
    now = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    if not_after < now:
        findings.append(
            _finding(
                "tls-cert-expired",
                "critical",
                target_url,
                f"TLS certificate for {host} expired on {not_after.date().isoformat()}",
                not_after.date().isoformat(),
            )
        )
    elif (not_after - now).days <= _EXPIRING_SOON_DAYS:
        findings.append(
            _finding(
                "tls-cert-expiring-soon",
                "medium",
                target_url,
                f"TLS certificate for {host} expires on {not_after.date().isoformat()}"
                f" (within {_EXPIRING_SOON_DAYS} days)",
                not_after.date().isoformat(),
            )
        )

    if cert.issuer == cert.subject:
        findings.append(
            _finding(
                "tls-cert-self-signed",
                "medium",
                target_url,
                f"TLS certificate for {host} is self-signed (issuer equals subject)",
                cert.subject.rfc4514_string(),
            )
        )

    if not hostname_matches(host, cert):
        # Evidence is diagnostic only (hostname_matches() above already
        # made the real IP-vs-DNS-SAN decision) -- show whatever names the
        # cert actually carries so a report reader can see why it doesn't
        # cover this host, even when that's a DNS name and the host is an
        # IP literal.
        names = (
            (_san_ip_addresses(cert) or _sans(cert) or _common_names(cert))
            if _as_ip_literal(host) is not None
            else (_sans(cert) or _common_names(cert))
        )
        findings.append(
            _finding(
                "tls-hostname-mismatch",
                "high",
                target_url,
                f"TLS certificate does not cover {host} (covers: {', '.join(names) or 'none'})",
                ", ".join(names) or "none",
            )
        )

    return findings
