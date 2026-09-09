"""Passive TLS/certificate analysis for HTTPS targets.

Uses stdlib ssl + socket. Optionally reuses hostname matching from
extractors.tls; does not replace that module's crawl-time checks.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from shroodler.models import Finding

_EXPIRING_SOON_DAYS = 30
_CONNECT_TIMEOUT = 5.0
_WEAK_SIGNATURES = {"sha1WithRSAEncryption", "md5WithRSAEncryption", "sha1", "md5"}


def _finding(
    finding_id: str,
    severity: str,
    url: str,
    description: str,
    evidence: str,
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,  # type: ignore[arg-type]
        category="tls",
        url=url,
        description=description,
        evidence=evidence,
        confidence="confirmed",
    )


def _name_from_rdn(rdn) -> str:
    parts: list[str] = []
    try:
        for item in rdn:
            if isinstance(item, tuple) and len(item) == 2:
                if item[0] in {"commonName", "commonName".lower()} or item[0] == "commonName":
                    parts.append(str(item[1]))
                elif str(item[0]).lower() in {"commonname", "cn"}:
                    parts.append(str(item[1]))
            elif isinstance(item, (list, tuple)):
                for inner in item:
                    if isinstance(inner, tuple) and len(inner) == 2:
                        if str(inner[0]).lower() in {"commonname", "cn"}:
                            parts.append(str(inner[1]))
    except Exception:  # noqa: BLE001
        return ""
    return ", ".join(parts)


def _flatten_name(name) -> str:
    if isinstance(name, str):
        return name
    try:
        parts: list[str] = []
        for rdn in name or ():
            text = _name_from_rdn(rdn)
            if text:
                parts.append(text)
        return ", ".join(parts)
    except Exception:  # noqa: BLE001
        return str(name or "")


def _sans(cert: dict) -> list[str]:
    out: list[str] = []
    try:
        for kind, value in cert.get("subjectAltName") or ():
            if str(kind).upper() in {"DNS", "IP ADDRESS", "IP"}:
                out.append(str(value))
    except Exception:  # noqa: BLE001
        return out
    return out


def _common_names(cert: dict) -> list[str]:
    names: list[str] = []
    try:
        for rdn in cert.get("subject") or ():
            text = _name_from_rdn(rdn)
            if text:
                names.extend(p.strip() for p in text.split(",") if p.strip())
    except Exception:  # noqa: BLE001
        return names
    return names


def _hostname_matches(host: str, cert: dict) -> bool:
    host = (host or "").lower().rstrip(".")
    names = [n.lower().rstrip(".") for n in (_sans(cert) or _common_names(cert))]
    for name in names:
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[2:]
            label, _, rest = host.partition(".")
            if rest == suffix and label:
                return True
    return False


def _parse_not_after(raw: str) -> datetime | None:
    text = (raw or "").strip()
    if not text:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            dt = datetime.strptime(text, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _sig_algorithm(cert: dict, binary: bytes | None) -> str:
    for key in ("signatureAlgorithm", "signature_algorithm"):
        value = cert.get(key)
        if value:
            return str(value)
    if not binary:
        return ""
    try:
        from cryptography import x509

        parsed = x509.load_der_x509_certificate(binary)
        oid = parsed.signature_algorithm_oid
        return getattr(oid, "_name", None) or str(oid)
    except Exception:  # noqa: BLE001
        return ""


def _connect(
    host: str,
    port: int,
    *,
    min_version=None,
    max_version=None,
    timeout: float = _CONNECT_TIMEOUT,
):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if min_version is not None:
        ctx.minimum_version = min_version
    if max_version is not None:
        ctx.maximum_version = max_version
    sock = socket.create_connection((host, port), timeout=timeout)
    return ctx.wrap_socket(sock, server_hostname=host)


def _accepts_version(host: str, port: int, version) -> bool:
    try:
        with _connect(host, port, min_version=version, max_version=version) as ssock:
            return ssock is not None
    except Exception:  # noqa: BLE001
        return False


def check_target_tls(target_url: str) -> list[Finding]:
    """Inspect the HTTPS certificate and legacy TLS versions for `target_url`."""
    parsed = urlparse(target_url)
    if parsed.scheme != "https":
        return []
    host = parsed.hostname
    if not host:
        return []
    port = parsed.port or 443

    try:
        ssock = _connect(host, port)
    except Exception:  # noqa: BLE001 - skip unreachable
        return []

    findings: list[Finding] = []
    try:
        cert = ssock.getpeercert() or {}
        try:
            der = ssock.getpeercert(binary_form=True)
        except Exception:  # noqa: BLE001
            der = None
    finally:
        try:
            ssock.close()
        except Exception:  # noqa: BLE001
            pass

    if not cert and not der:
        return []

    not_after = _parse_not_after(str((cert or {}).get("notAfter") or ""))
    now = datetime.now(timezone.utc)
    if not_after is not None:
        if not_after < now:
            findings.append(
                _finding(
                    "tls-cert-expired",
                    "high",
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
                    f"TLS certificate for {host} expires within {_EXPIRING_SOON_DAYS} days",
                    not_after.date().isoformat(),
                )
            )

    subject = _flatten_name((cert or {}).get("subject"))
    issuer = _flatten_name((cert or {}).get("issuer"))
    if subject and issuer and subject == issuer:
        findings.append(
            _finding(
                "tls-self-signed",
                "medium",
                target_url,
                f"TLS certificate for {host} is self-signed (issuer equals subject)",
                subject,
            )
        )

    algo = _sig_algorithm(cert or {}, der if isinstance(der, bytes) else None)
    lowered = algo.lower().replace("-", "").replace("_", "")
    if any(weak.lower().replace("-", "") in lowered for weak in _WEAK_SIGNATURES) or algo in _WEAK_SIGNATURES:
        findings.append(
            _finding(
                "tls-weak-signature",
                "medium",
                target_url,
                f"TLS certificate for {host} uses a weak signature algorithm ({algo})",
                algo,
            )
        )

    if cert and not _hostname_matches(host, cert):
        names = _sans(cert) or _common_names(cert)
        findings.append(
            _finding(
                "tls-hostname-mismatch",
                "high",
                target_url,
                f"TLS certificate does not cover {host} (covers: {', '.join(names) or 'none'})",
                ", ".join(names) or "none",
            )
        )

    tls10 = getattr(ssl.TLSVersion, "TLSv1", None)
    tls11 = getattr(ssl.TLSVersion, "TLSv1_1", None)
    if tls10 is not None and _accepts_version(host, port, tls10):
        findings.append(
            _finding(
                "tls-v1-enabled",
                "medium",
                target_url,
                f"{host} accepts TLS 1.0",
                "TLSv1",
            )
        )
    if tls11 is not None and _accepts_version(host, port, tls11):
        findings.append(
            _finding(
                "tls-v11-enabled",
                "low",
                target_url,
                f"{host} accepts TLS 1.1",
                "TLSv1_1",
            )
        )

    return findings
