"""Weak-HMAC JWT secret probe: re-sign captured tokens and replay them."""

from __future__ import annotations

import re
import warnings

import httpx
import jwt

from shroodler.authz_diff import headers_from_auth_line
from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import dedupe, request

_JWT_RE = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_WEAK_SECRETS = ("secret", "password", "changeit", "webgoat", "", "HS256")
_DENIED = {401, 403}


def _find_jwts(*blobs: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for blob in blobs:
        for match in _JWT_RE.finditer(blob or ""):
            token = match.group(0)
            if token.count(".") != 2 or token in seen:
                continue
            seen.add(token)
            out.append(token)
    return out


def _headers_with_token(
    cookie_header: str,
    auth_header: str,
    original: str,
    replacement: str,
) -> dict[str, str]:
    headers = headers_from_auth_line(cookie_header)
    if auth_header:
        headers.update(headers_from_auth_line(auth_header))
    if not headers:
        headers = {"Authorization": f"Bearer {replacement}"}
        return headers
    return {key: value.replace(original, replacement) for key, value in headers.items()}


def _resign(token: str, secret: str) -> str | None:
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception:  # noqa: BLE001 - malformed token
        return None
    headers = {k: v for k, v in header.items() if k != "alg"}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return jwt.encode(payload, secret, algorithm="HS256", headers=headers or None)
    except Exception:  # noqa: BLE001 - empty/unsupported key
        return None


def probe_jwt(
    url: str,
    cookie_header: str,
    auth_header: str = "",
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
) -> list[Finding]:
    """Re-sign captured JWTs with weak HS256 secrets and replay them."""
    tokens = _find_jwts(cookie_header, auth_header)
    if not tokens:
        return []

    findings: list[Finding] = []
    for token in tokens:
        garbage = ".".join((*token.split(".")[:2], "garbage-signature-not-valid"))
        denied = request(
            "GET",
            url,
            extra_headers=_headers_with_token(cookie_header, auth_header, token, garbage),
            client=client,
            pacer=pacer,
        )
        garbage_status = int(getattr(denied, "status_code", 0) or 0)
        if garbage_status not in _DENIED:
            continue
        for secret in _WEAK_SECRETS:
            forged = _resign(token, secret)
            if not forged:
                continue
            resp = request(
                "GET",
                url,
                extra_headers=_headers_with_token(cookie_header, auth_header, token, forged),
                client=client,
                pacer=pacer,
            )
            if resp is None or int(resp.status_code) != 200:
                continue
            findings.append(
                Finding(
                    id="jwt-weak-secret",
                    severity="critical",
                    category="secret",
                    url=url,
                    description=(
                        "Server accepted a JWT re-signed with a well-known HS256 "
                        "secret while a garbage signature was denied."
                    ),
                    evidence=f"secret={secret}",
                    confidence="confirmed",
                )
            )
            return dedupe(findings)
    return dedupe(findings)
