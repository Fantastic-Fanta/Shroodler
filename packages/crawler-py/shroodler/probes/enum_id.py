"""Guessable capability-identifier detection.

Encodes a logic-bug pattern a scanner's signatures usually miss: a resource
addressed only by a short, opaque *capability* code — a share link, invite,
export, preview — where the code is the sole access control but its keyspace
is small enough to enumerate. (The motivating case: an export code that was
`secrets.token_hex(3)`, six hex chars, a 24-bit space, brute-forceable behind
a rate limit that a spoofed X-Forwarded-For defeats.)

Black-box and LLM-free: it reads the identifier out of the URL, estimates its
keyspace from length and character set, and — only when the endpoint actually
returns data — flags it as enumerable. Numeric/sequential ids are left to the
IDOR probe; dictionary-word slugs are ignored. Confidence is heuristic.
"""

from __future__ import annotations

import math
import re
from urllib.parse import parse_qsl, urlparse

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, request

# Param / path names that denote a capability code (a bearer of access).
CAPABILITY_HINTS = (
    "code",
    "token",
    "key",
    "share",
    "invite",
    "invitation",
    "export",
    "ref",
    "slug",
    "secret",
    "access",
    "download",
    "preview",
    "link",
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_BASE62_RE = re.compile(r"^[0-9A-Za-z]+$")
_HAS_LETTER = re.compile(r"[A-Za-z]")
_HAS_DIGIT = re.compile(r"\d")
_WORD_RE = re.compile(r"^[A-Za-z][a-z]+$")  # a plain lowercase word: a slug, not a code

# Flag identifiers whose keyspace is below this (bits). 2^48 ≈ 2.8e14: a 6-hex
# code is 2^24, a 8-hex 2^32 — well under; a 16-hex 2^64 is safe.
_MAX_SAFE_BITS = 48
_MIN_LEN = 5
_MAX_LEN = 24


def _charset_bits(value: str) -> float | None:
    """Estimate keyspace in bits, or None if `value` isn't a random-looking code."""
    v = value.strip()
    if not (_MIN_LEN <= len(v) <= _MAX_LEN):
        return None
    if v.isdigit():
        return None  # sequential/numeric ids are IDOR's job, not enumeration entropy
    if not _HAS_LETTER.search(v):
        return None
    if _WORD_RE.match(v):
        return None  # a dictionary-ish slug, not an opaque code
    if _HEX_RE.match(v):
        alphabet = 16
    elif _BASE62_RE.match(v) and _HAS_DIGIT.search(v):
        alphabet = 62
    else:
        return None
    return len(v) * math.log2(alphabet)


def _candidates(url: str) -> list[tuple[str, str, str]]:
    """(where, name, value) capability-code candidates in `url`."""
    out: list[tuple[str, str, str]] = []
    parsed = urlparse(url)
    for key, val in parse_qsl(parsed.query, keep_blank_values=True):
        if any(h in key.lower() for h in CAPABILITY_HINTS):
            out.append(("param", key, val))
    segments = [s for s in (parsed.path or "").split("/") if s]
    for i, seg in enumerate(segments):
        # A code preceded by a capability-ish collection noun, or any opaque
        # code segment (strip a file extension like {code}.png first).
        bare = seg.split(".")[0]
        prev = segments[i - 1].lower() if i > 0 else ""
        looks_capability = any(h in prev for h in CAPABILITY_HINTS) or any(
            h in bare.lower() for h in CAPABILITY_HINTS
        )
        if looks_capability or i == len(segments) - 1:
            out.append(("path", prev or "path", bare))
    return out


def probe_enumerable_id(
    url: str,
    method: str,
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
) -> list[Finding]:
    """Flag a resource reached by a short, enumerable capability code."""
    if (method or "GET").upper() != "GET":
        return []
    scored: list[tuple[str, str, str, float]] = []
    for where, name, value in _candidates(url):
        bits = _charset_bits(value)
        if bits is not None and bits < _MAX_SAFE_BITS:
            scored.append((where, name, value, bits))
    if not scored:
        return []
    # Only worth reporting if the endpoint actually returns data for this code.
    resp = request("GET", url, cookie_header=cookie_header, client=client, pacer=pacer)
    if resp is None or int(getattr(resp, "status_code", 0) or 0) != 200:
        return []
    if len((body_text(resp) or "").strip()) < 2:
        return []
    where, name, value, bits = min(scored, key=lambda s: s[3])
    space = 2 ** int(round(bits))
    return [
        Finding(
            id="guessable-capability-id",
            severity="medium",
            category="auth",
            url=url,
            description=(
                f"Resource is addressed by a short capability identifier "
                f"({where} {name!r}, {len(value)} chars, ~2^{int(round(bits))} "
                f"= {space:,} values) and returns data. The keyspace is small "
                "enough to enumerate, so the code is not a real access control."
            ),
            evidence=f"{where}={name} len={len(value)} bits={bits:.0f}",
            confidence="heuristic",
        )
    ]
