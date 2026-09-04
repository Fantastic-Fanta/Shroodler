from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta, timezone

from shroodler.models import Finding

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")

# Small, fast, common-secret wordlist for HMAC weak-secret cracking. This is
# deliberately short (not a gitleaks/hashcat-scale list) so JWT auditing
# doesn't meaningfully slow down a crawl; it catches the "left the tutorial
# default secret in prod" class of bug, not a real brute force.
_WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "changeme",
    "changeit",
    "admin",
    "jwt_secret",
    "jwtsecret",
    "your-256-bit-secret",
    "secretkey",
    "secret_key",
    "key",
    "test",
    "testing",
    "dev",
    "development",
    "production",
    "supersecret",
    "super-secret",
    "mysecret",
    "s3cr3t",
    "qwerty",
    "letmein",
    "shroodler",
    "shhh",
    "topsecret",
    "0000",
    "1234",
    "abc123",
    "",
]

_HMAC_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}

_LONG_EXPIRY = timedelta(days=365)


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def find_jwts(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in _JWT_RE.finditer(text or ""):
        tok = m.group(0)
        if tok not in seen:
            seen.add(tok)
            out.append(tok)
    return out


def crack_weak_secret(token: str) -> str | None:
    """Try a small common-secret wordlist against an HS256/384/512 JWT.

    Returns the recovered secret string if one of the candidates reproduces
    the token's signature, else None. Non-HMAC algorithms (RS*/ES*/PS*) and
    malformed tokens are not attempted.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception:
        return None
    alg = str(header.get("alg", "")).upper()
    digestmod = _HMAC_ALGS.get(alg)
    if digestmod is None:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        target_sig = _b64url_decode(parts[2])
    except Exception:
        return None
    for candidate in _WEAK_SECRETS:
        mac = hmac.new(candidate.encode("utf-8"), signing_input, digestmod).digest()
        if hmac.compare_digest(mac, target_sig):
            return candidate
    return None


def audit_jwt(token: str, url: str) -> list[Finding]:
    parts = token.split(".")
    if len(parts) != 3:
        return []
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception:
        return []
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        payload = {}

    findings: list[Finding] = []
    ev = token if len(token) <= 40 else token[:20] + "..." + token[-8:]

    alg = str(header.get("alg", ""))
    if alg.lower() == "none":
        findings.append(
            Finding(
                id="jwt-alg-none",
                severity="critical",
                category="secret",
                url=url,
                description=(
                    "JWT declares \"alg\":\"none\" -- if the server accepts this "
                    "token without verifying a signature, an attacker can forge "
                    "arbitrary claims (full authentication/authorization bypass). "
                    "Try replaying this token with the signature stripped."
                ),
                evidence=ev,
            )
        )

    if isinstance(payload, dict) and "exp" not in payload:
        findings.append(
            Finding(
                id="jwt-missing-exp",
                severity="medium",
                category="secret",
                url=url,
                description="JWT has no \"exp\" claim -- the token never expires.",
                evidence=ev,
            )
        )
    elif isinstance(payload, dict):
        try:
            exp = datetime.fromtimestamp(float(payload["exp"]), tz=timezone.utc)
            if exp - datetime.now(timezone.utc) > _LONG_EXPIRY:
                findings.append(
                    Finding(
                        id="jwt-long-expiry",
                        severity="low",
                        category="secret",
                        url=url,
                        description=(
                            f"JWT expiry is unusually far in the future ({exp.date().isoformat()}); "
                            "a leaked long-lived token stays usable for a long time."
                        ),
                        evidence=ev,
                    )
                )
        except (TypeError, ValueError, OSError, OverflowError):
            pass

    secret = crack_weak_secret(token)
    if secret is not None:
        shown = secret if secret else "(empty string)"
        findings.append(
            Finding(
                id="jwt-weak-secret",
                severity="critical",
                category="secret",
                url=url,
                description=(
                    f"JWT signature was reproduced using a common weak secret ({shown!r}) "
                    "from a short built-in wordlist -- an attacker can forge arbitrary "
                    "tokens for this application."
                ),
                evidence=ev,
            )
        )

    return findings


def audit_text(text: str, url: str) -> list[Finding]:
    findings: list[Finding] = []
    for token in find_jwts(text):
        findings.extend(audit_jwt(token, url))
    return findings
