"""Cross-account IDOR comparison: owner vs peer on ID-bearing endpoints.

Distinct from probes/idor.py (per-URL numeric neighbor swap). This engine
replays crawled resources as both principals, classifies leaks, and does a
small numeric enumeration window. Session secrets never appear in findings.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse

from shroodler.llm_agent.probe_memory import normalise_url
from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.program import ProgramState, url_to_pattern

_PLACEHOLDER_RE = re.compile(r"\{[^{}]+\}")
_NUMERIC_SEG_RE = re.compile(r"^\d+$")
# Short numeric IDs (1–2 digits) are common in CTF/demo apps (Juice Shop
# /rest/basket/1) but /api/users/1 must stay non-IDOR so PeerWrite wins in
# decide_next_action tests. 3+ digits still always count (via normalise_url).
_SHORT_ID_PARENTS = frozenset(
    {
        "basket",
        "baskets",
        "order",
        "orders",
        "card",
        "cards",
        "product",
        "products",
        "item",
        "items",
        "feedback",
        "feedbacks",
        "address",
        "addresss",
        "complaint",
        "complaints",
        "memory",
        "memories",
        "quantity",
        "quantitys",
        "recycle",
        "recycles",
        "hint",
        "hints",
        "challenge",
        "challenges",
        "delivery",
        "deliverys",
        "profile",
        "account",
        "invoice",
        "payment",
        "file",
        "document",
        "message",
        "comment",
        "review",
        "reviews",
    }
)
_COMPACT_HEX_RE = re.compile(r"^[0-9a-fA-F]{32,}$")
_BASE62_SEG_RE = re.compile(r"^[A-Za-z0-9]{8,20}$")
_DENIED = frozenset({401, 403, 404})
_ENUM_DELTAS = (1, -1, 2, -2, 3, -3, 4, -4, 5, -5)
_ENUM_CAP_PER_PATTERN = 5
_SHORT_BODY = 20


@dataclass
class IDORCandidate:
    url: str
    method: str
    owner_status: int
    peer_status: int
    owner_body_hash: str
    peer_body_hash: str
    owner_body_sample: str
    peer_body_sample: str
    param_name: str | None = None
    object_id: str | None = None


def cookie_header_to_dict(raw: str) -> dict[str, str]:
    """Split `a=b; c=d` into a dict. Never logs values."""
    out: dict[str, str] = {}
    for part in (raw or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, value = part.partition("=")
        name = name.strip()
        if name:
            out[name] = value.strip()
    return out


def session_from_auth_line(raw: str) -> tuple[dict[str, str], dict[str, str]]:
    """Turn a Cookie or Authorization line into (headers, cookies)."""
    text = (raw or "").strip()
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    if not text:
        return headers, cookies
    lowered = text.lower()
    if lowered.startswith("authorization:"):
        headers["Authorization"] = text.split(":", 1)[1].strip()
        return headers, cookies
    if lowered.startswith("cookie:"):
        text = text.split(":", 1)[1].strip()
    cookies = cookie_header_to_dict(text)
    return headers, cookies


def _path_segments(url: str) -> list[str]:
    try:
        path = urlparse(url).path or ""
    except ValueError:
        return []
    return [seg for seg in path.split("/") if seg]


def looks_like_idor_url(url: str) -> bool:
    """True when a path segment looks like a numeric / UUID / base62 object id."""
    if not url or _PLACEHOLDER_RE.search(url):
        return False
    try:
        orig_path = urlparse(url).path or ""
        norm_path = urlparse(normalise_url(url)).path or ""
    except ValueError:
        orig_path = ""
        norm_path = orig_path
    if orig_path != norm_path:
        return True
    segs = _path_segments(url)
    for i, seg in enumerate(segs):
        if _COMPACT_HEX_RE.fullmatch(seg):
            return True
        if _BASE62_SEG_RE.fullmatch(seg) and sum(ch.isdigit() for ch in seg) >= 2:
            return True
        prev = segs[i - 1] if i else ""
        if _NUMERIC_SEG_RE.fullmatch(seg) and prev.lower() != "v":
            if len(seg) >= 3 or prev.lower() in _SHORT_ID_PARENTS:
                return True
    return False


def _in_scope(url: str, state: ProgramState, config: Any) -> bool:
    from shroodler.scope import in_scope, load_scope

    path = getattr(config, "scope_file", None)
    slug = str(getattr(state, "slug", "") or "")
    return in_scope(url, load_scope(slug, path=path))


def collect_idor_targets(state: ProgramState, config: Any) -> list[tuple[str, str]]:
    """Return (url, method) pairs from state.endpoints that look IDOR-prone."""
    allowed = {
        str(m).upper()
        for m in (getattr(config, "idor_methods", None) or ["GET"])
        if str(m).strip()
    }
    if not allowed:
        allowed = {"GET"}
    out: list[tuple[str, str]] = []
    for url, meta in (getattr(state, "endpoints", None) or {}).items():
        if not looks_like_idor_url(url):
            continue
        if not _in_scope(url, state, config):
            continue
        method = str((meta or {}).get("method") or "GET").upper() or "GET"
        if method not in allowed:
            continue
        out.append((str(url), method))
    return out


def _body_hash(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8", errors="replace")).hexdigest()


def _sample(body: str) -> str:
    return (body or "")[:500]


def _curl_repro(method: str, url: str) -> str:
    verb = (method or "GET").upper() or "GET"
    return f'curl -X {verb} {url!r} -H "Cookie: <session>"'


def _replace_segment(url: str, old: str, new: str) -> str:
    try:
        parsed = urlparse(url)
    except ValueError:
        return url
    parts = (parsed.path or "").split("/")
    idxs = [i for i, seg in enumerate(parts) if seg == old]
    if not idxs:
        return url
    parts[idxs[-1]] = new
    new_path = "/".join(parts)
    if (parsed.path or "").endswith("/") and new_path and not new_path.endswith("/"):
        new_path += "/"
    return urlunparse(parsed._replace(path=new_path))


def _last_numeric_id(url: str) -> str | None:
    found: str | None = None
    for seg in _path_segments(url):
        if _NUMERIC_SEG_RE.fullmatch(seg):
            found = seg
    return found


class IDOREngine:
    """Replay ID-bearing endpoints as owner then peer; emit confirmed IDORs."""

    def __init__(
        self,
        state: ProgramState,
        config: Any,
        owner_headers: dict[str, str],
        owner_cookies: dict[str, str],
        peer_headers: dict[str, str],
        peer_cookies: dict[str, str],
        pacer: Pacer,
    ) -> None:
        self.state = state
        self.config = config
        self.owner_headers = dict(owner_headers or {})
        self.owner_cookies = dict(owner_cookies or {})
        self.peer_headers = dict(peer_headers or {})
        self.peer_cookies = dict(peer_cookies or {})
        self.pacer = pacer
        self.tested_count = 0

    def _request(
        self,
        url: str,
        headers: dict[str, str],
        cookies: dict[str, str],
        method: str = "GET",
    ) -> tuple[int, str]:
        """GET/configured method via probes.common.request. Fail closed: (0, "")."""
        from shroodler.probes.common import body_text, request

        extra_headers = {
            str(k): str(v)
            for k, v in dict(headers or {}).items()
            if str(k).lower() != "cookie"
        }
        cookie_bits: list[str] = []
        for key, value in dict(headers or {}).items():
            if str(key).lower() == "cookie" and value:
                cookie_bits.append(str(value))
        if cookies:
            cookie_bits.append(
                "; ".join(f"{k}={v}" for k, v in cookies.items() if k)
            )
        cookie_header = "; ".join(bit for bit in cookie_bits if bit)
        try:
            resp = request(
                (method or "GET").upper() or "GET",
                url,
                cookie_header=cookie_header,
                extra_headers=extra_headers,
                pacer=self.pacer,
            )
        except Exception:  # noqa: BLE001 - fail closed
            return (0, "")
        if resp is None:
            return (0, "")
        try:
            status = int(resp.status_code)
        except (TypeError, ValueError):
            return (0, "")
        return (status, body_text(resp))

    def _probe(
        self,
        url: str,
        method: str,
        *,
        param_name: str | None = None,
        object_id: str | None = None,
    ) -> IDORCandidate:
        self.tested_count += 1
        owner_status, owner_body = self._request(
            url, self.owner_headers, self.owner_cookies, method=method
        )
        peer_status, peer_body = self._request(
            url, self.peer_headers, self.peer_cookies, method=method
        )
        return IDORCandidate(
            url=url,
            method=method,
            owner_status=owner_status,
            peer_status=peer_status,
            owner_body_hash=_body_hash(owner_body),
            peer_body_hash=_body_hash(peer_body),
            owner_body_sample=_sample(owner_body),
            peer_body_sample=_sample(peer_body),
            param_name=param_name,
            object_id=object_id,
        )

    def _classify(self, cand: IDORCandidate) -> Finding | None:
        if not (200 <= cand.peer_status < 300 and 200 <= cand.owner_status < 300):
            return None
        if cand.peer_status in _DENIED:
            return None
        peer_len = len(cand.peer_body_sample if cand.peer_body_sample is not None else "")
        # Sample is capped at 500; use hash equality for identical, length of sample
        # for the short-body heuristic (bodies < 20 never exceed the sample cap).
        if cand.owner_body_hash == cand.peer_body_hash:
            severity: str = "critical"
        elif peer_len < _SHORT_BODY:
            severity = "medium"
        else:
            severity = "high"
        evidence = (
            f"owner={cand.owner_status} peer={cand.peer_status} "
            f"owner_hash={cand.owner_body_hash[:8]} peer_hash={cand.peer_body_hash[:8]}"
        )
        if cand.object_id:
            evidence += f" object_id={cand.object_id}"
        if cand.param_name:
            evidence += f" param_name={cand.param_name}"
        description = (
            f"Peer session received HTTP {cand.peer_status} for an owner resource "
            f"({cand.method} {cand.url}) while the owner session also succeeded "
            f"({cand.owner_status}). Reproduce with: {_curl_repro(cand.method, cand.url)}"
        )
        return Finding(
            id="idor-cross-account",
            severity=severity,  # type: ignore[arg-type]
            category="auth",
            url=cand.url,
            description=description,
            evidence=evidence,
            confidence="confirmed",
        )

    def _enumerate_urls(self, targets: list[tuple[str, str]]) -> list[tuple[str, str, str]]:
        """(url, method, object_id) neighbors not already in state.endpoints."""
        known = set(self.state.endpoints or {})
        per_pattern: dict[str, int] = {}
        extra: list[tuple[str, str, str]] = []
        for url, method in targets:
            nid = _last_numeric_id(url)
            if nid is None:
                continue
            try:
                n = int(nid)
            except ValueError:
                continue
            pattern = url_to_pattern(url)
            for delta in _ENUM_DELTAS:
                if per_pattern.get(pattern, 0) >= _ENUM_CAP_PER_PATTERN:
                    break
                neighbor = n + delta
                if neighbor <= 0 or neighbor == n:
                    continue
                neighbor_url = _replace_segment(url, nid, str(neighbor))
                if neighbor_url == url or neighbor_url in known:
                    continue
                known.add(neighbor_url)
                per_pattern[pattern] = per_pattern.get(pattern, 0) + 1
                extra.append((neighbor_url, method, str(neighbor)))
        return extra

    async def run(self) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        targets = collect_idor_targets(self.state, self.config)
        candidates: list[IDORCandidate] = []
        for url, method in targets:
            candidates.append(self._probe(url, method))
        for url, method, object_id in self._enumerate_urls(targets):
            candidates.append(
                self._probe(
                    url,
                    method,
                    param_name="path-enum",
                    object_id=object_id,
                )
            )
        for cand in candidates:
            hit = self._classify(cand)
            if hit is None:
                continue
            key = (url_to_pattern(cand.url), cand.peer_status)
            if key in seen:
                continue
            seen.add(key)
            findings.append(hit)
        return findings

    def run_sync(self) -> list[Finding]:
        return asyncio.run(self.run())
