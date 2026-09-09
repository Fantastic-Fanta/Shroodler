"""Cross-session IDOR probe for numeric path IDs."""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlparse, urlunparse

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, dedupe, request
from shroodler.urls import origin as origin_of

_ID_RE = re.compile(r"/(\d{6,})")
_NEIGHBOR_DELTAS = (1, -1, 10, -10, 100, -100)
_ANON_DENIED = {302, 401}
_ME_PATHS = (
    "/profile/me",
    "/api/profile/me",
    "/api/users/me",
    "/me",
    "/api/me",
)
_ID_KEYS = ("id", "userId", "user_id", "uid")


def _replace_id(url: str, old: str, new: str) -> str:
    parsed = urlparse(url)
    path = parsed.path
    needle = "/" + old
    idx = path.rfind(needle)
    if idx < 0:
        return url
    end = idx + len(needle)
    if end < len(path) and path[end].isdigit():
        return url
    new_path = path[:idx] + "/" + new + path[end:]
    return urlunparse(parsed._replace(path=new_path))


def _body_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()


def _peer_user_id(
    url: str,
    peer_cookie_header: str,
    *,
    client: httpx.Client | None,
    pacer: Pacer | None,
) -> str | None:
    try:
        base = origin_of(url)
    except Exception:  # noqa: BLE001
        return None
    for path in _ME_PATHS:
        resp = request(
            "GET",
            base.rstrip("/") + path,
            cookie_header=peer_cookie_header,
            client=client,
            pacer=pacer,
        )
        if resp is None or int(resp.status_code) != 200:
            continue
        try:
            data = resp.json()
        except Exception:  # noqa: BLE001
            try:
                data = json.loads(body_text(resp))
            except (ValueError, TypeError):
                continue
        if not isinstance(data, dict):
            continue
        for key in _ID_KEYS:
            value = data.get(key)
            if value is None:
                continue
            text = str(value)
            if text.isdigit():
                return text
        nested = data.get("user")
        if isinstance(nested, dict) and nested.get("id") is not None:
            text = str(nested["id"])
            if text.isdigit():
                return text
    return None


def _probe_neighbor(
    neighbor_url: str,
    cookie_header: str,
    peer_cookie_header: str,
    *,
    client: httpx.Client | None,
    pacer: Pacer | None,
) -> Finding | None:
    owner = request(
        "GET",
        neighbor_url,
        cookie_header=cookie_header,
        client=client,
        pacer=pacer,
    )
    peer = request(
        "GET",
        neighbor_url,
        cookie_header=peer_cookie_header,
        client=client,
        pacer=pacer,
    )
    anon = request("GET", neighbor_url, client=client, pacer=pacer)
    owner_status = int(getattr(owner, "status_code", 0) or 0)
    owner_hash = _body_hash(body_text(owner)) if owner is not None else ""
    if peer is None or int(peer.status_code) != 200:
        return None
    peer_body = body_text(peer)
    if not peer_body.strip():
        return None
    peer_hash = _body_hash(peer_body)
    anon_status = int(getattr(anon, "status_code", 0) or 0)
    if anon_status not in _ANON_DENIED:
        return None
    return Finding(
        id="idor",
        severity="high",
        category="auth",
        url=neighbor_url,
        description=(
            "Peer session received 200 with a non-empty body for a neighboring "
            f"object ID while an anonymous request was denied ({anon_status})."
        ),
        evidence=(
            f"peer=200 anon={anon_status} owner={owner_status} "
            f"peer_hash={peer_hash[:12]} owner_hash={owner_hash[:12]}"
        ),
        confidence="confirmed",
    )


def probe_idor(
    url: str,
    cookie_header: str,
    peer_cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
) -> list[Finding]:
    """Swap 6+ digit path IDs for neighbors and replay as owner vs peer."""
    if not (peer_cookie_header or "").strip():
        return []
    parsed = urlparse(url)
    matches = list(_ID_RE.finditer(parsed.path or ""))
    if not matches:
        return []
    original = matches[-1].group(1)
    try:
        original_n = int(original)
    except ValueError:
        return []

    candidates: list[str] = []
    seen: set[str] = set()
    for delta in _NEIGHBOR_DELTAS:
        neighbor = original_n + delta
        if neighbor <= 0:
            continue
        text = str(neighbor)
        if text not in seen:
            seen.add(text)
            candidates.append(text)
    peer_id = _peer_user_id(
        url, peer_cookie_header, client=client, pacer=pacer
    )
    if peer_id and peer_id != original and peer_id not in seen:
        candidates.append(peer_id)

    findings: list[Finding] = []
    for candidate in candidates:
        neighbor_url = _replace_id(url, original, candidate)
        if neighbor_url == url:
            continue
        hit = _probe_neighbor(
            neighbor_url,
            cookie_header,
            peer_cookie_header,
            client=client,
            pacer=pacer,
        )
        if hit is not None:
            findings.append(hit)
            break
    return dedupe(findings)
