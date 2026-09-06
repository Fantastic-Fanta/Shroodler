"""Password-reset / verification-token predictability analysis.

Operates on a recorded proxy session (JSONL, the same format `--cookies-
from`/`--seed-from`/`ingest-sessions` already consume -- see
shroodler.sessions.load_sessions), not a live crawl: a token is normally
delivered out-of-band (email/SMS), so the only way Shroodler ever
observes one is if a tester's browser, routed through the recording
proxy, actually visited the reset/verification link. This is why it's a
separate `shroodler tokens` command rather than a crawl-time check.

Every finding here is deterministic given the recorded samples -- no
network requests, no live-target ambiguity of the kind earlier checks in
this codebase got flagged for cutting corners on. The trade-off is
sample size: with only one observed token for a given endpoint, this can
only make a conservative length-based estimate and says so explicitly in
the finding; with two or more, it can test for an actual sequential/
incrementing pattern or measure real per-character entropy across the
sample.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from typing import Any
from urllib.parse import parse_qsl, urlparse

from shroodler.models import Finding


def _request_url(sess: dict[str, Any]) -> str:
    return str((sess.get("request") or {}).get("url") or "")

# Query parameter names worth treating as a reset/verification token.
# Deliberately a narrow, curated list rather than "any long-looking
# value": widening this to arbitrary opaque query params would start
# flagging session IDs, CSRF tokens, and API keys that have entirely
# different generation/rotation properties than a one-shot,
# email-delivered reset token. Matched against the param name with
# underscores/hyphens both normalized to "_" (see _normalize_param_name),
# so "reset-token" and "reset_token" are treated as the same name --
# real APIs use both conventions and a hyphenated name silently missing
# entirely would be a real, easy-to-hit coverage gap.
TOKEN_PARAM_NAMES = frozenset(
    {
        "token",
        "reset_token",
        "reset_code",
        "otp",
        "verification_code",
        "verify_token",
        "confirm_token",
        "confirmation_code",
        "activation_code",
        "magic_link_token",
    }
)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_LONG_ID_RE = re.compile(r"^[0-9a-zA-Z]{8,}$")


def _normalize_param_name(name: str) -> str:
    return name.lower().replace("-", "_")


def _template_path(path: str) -> str:
    """Collapse a per-request-varying path segment (a UUID, or any long
    alphanumeric id) to a placeholder, so e.g. /reset/<uuid>/confirm and
    /reset/<other-uuid>/confirm group together as the same endpoint
    template instead of each observation landing in its own singleton
    group -- a real, common API shape (a request-id or resource-id
    segment alongside a token query param) that would otherwise silently
    keep this tool in single-sample mode forever for that endpoint,
    never running the sequential/entropy checks even with many samples.
    """
    segments = path.split("/")
    templated = [
        "{id}" if _UUID_RE.match(seg) or _LONG_ID_RE.match(seg) else seg for seg in segments
    ]
    return "/".join(templated)

_MIN_TOKEN_LEN = 6
# A real random token's per-character Shannon entropy is close to
# log2(alphabet size) -- e.g. ~4 bits/char for hex, ~6 for base64url.
# Below this, the sampled values are noticeably less varied than random
# noise over their own observed alphabet.
_LOW_ENTROPY_BITS_PER_CHAR = 2.5
# Single-sample worst-case length floor: below this many characters, even
# a maximally-diverse alphabet can't reach a reasonable token's usual
# security margin (~80 bits) -- see _worst_case_bits.
_SHORT_TOKEN_MIN_LEN = 16


def shannon_entropy_bits_per_char(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _worst_case_bits(s: str) -> float:
    """Upper-bound entropy estimate from length alone, assuming the most
    generous plausible alphabet (64 symbols, i.e. base64url) -- a
    single sample can't do better than this without more data, and using
    the most generous assumption keeps this a conservative (few false
    positives) rather than alarmist estimate."""
    return len(s) * math.log2(64)


def _finding(fid: str, severity: str, url: str, description: str, evidence: str) -> Finding:
    return Finding(
        id=fid, severity=severity, category="secret", url=url, description=description,
        evidence=evidence,
    )


def _extract_token_observations(
    sessions: list[dict[str, Any]],
) -> dict[tuple[str, str, str], list[tuple[str, str]]]:
    """Group observed token values by (host, path, param_name) -- the
    same endpoint/parameter template, however many times it was
    observed. Each entry is (token_value, full_url_it_was_seen_at)."""
    groups: dict[tuple[str, str, str], list[tuple[str, str]]] = defaultdict(list)
    for sess in sessions:
        url = _request_url(sess)
        if not url or "://" not in url:
            continue
        parsed = urlparse(url)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            name = _normalize_param_name(key)
            if name not in TOKEN_PARAM_NAMES:
                continue
            if len(value) < _MIN_TOKEN_LEN:
                continue
            groups[(parsed.hostname or "", _template_path(parsed.path), name)].append((value, url))
    return groups


def _is_sequential(values: list[str]) -> bool:
    """True when every sampled value parses as a base-10 integer and the
    samples cluster in a narrow numeric range relative to how many were
    observed -- real random tokens are practically never clean small
    integers at all, so values that parse cleanly AND cluster together
    are strong, specific evidence of a predictable/incrementing
    generator, not just "the values happen to be numeric"."""
    try:
        ints = [int(v) for v in values]
    except ValueError:
        return False
    span = max(ints) - min(ints)
    # A random 6+ digit token would essentially never fall within a span
    # this narrow purely by chance; an incrementing/near-incrementing
    # counter reliably would.
    return span <= max(len(values) * 1000, 1000)


def analyze_tokens(sessions: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for (host, path, param), observations in _extract_token_observations(sessions).items():
        sample_url = observations[-1][1]
        endpoint = f"{host}{path}?{param}=..."

        # Dedupe identical values BEFORE deciding this has "2+ samples":
        # a proxy recording naturally captures retries/redirect chains/a
        # tester revisiting the same emailed link twice, and the same
        # literal value observed N times is one real data point, not N.
        # Treating it as N would have been actively wrong for the
        # sequential check in particular -- an identical value repeated
        # has span 0, which would otherwise trip _is_sequential's
        # threshold trivially despite revealing nothing about whether
        # the generator is sequential at all.
        unique_values = sorted(set(v for v, _ in observations))

        if len(unique_values) >= 2:
            if _is_sequential(unique_values):
                findings.append(
                    _finding(
                        "reset-token-sequential",
                        "critical",
                        sample_url,
                        f"{len(unique_values)} distinct observed values of `{param}` at "
                        f"{endpoint} are small, closely-clustered integers -- consistent with a "
                        "sequential/incrementing generator rather than a random token, letting "
                        "an attacker guess a valid reset/verification token by iterating nearby "
                        "values. Treat as a strong lead to manually confirm (request two resets "
                        "back-to-back and compare), not a proven finding from this sample alone",
                        ", ".join(unique_values[:10]),
                    )
                )
                continue
            avg_bits = sum(shannon_entropy_bits_per_char(v) for v in unique_values) / len(
                unique_values
            )
            if avg_bits < _LOW_ENTROPY_BITS_PER_CHAR:
                findings.append(
                    _finding(
                        "reset-token-low-entropy",
                        "medium",
                        sample_url,
                        f"{len(unique_values)} distinct observed values of `{param}` at "
                        f"{endpoint} average {avg_bits:.1f} bits of Shannon entropy per character "
                        "(a random token typically shows several bits/char over its own "
                        "alphabet), suggesting a weak or narrow-alphabet generator",
                        ", ".join(unique_values[:10]),
                    )
                )
            continue

        # Exactly one DISTINCT sample (possibly observed multiple times):
        # no sequential/entropy comparison is possible, so this only
        # ever makes the single, explicitly conservative claim that the
        # value is short enough that even a generous alphabet assumption
        # can't reach a reasonable security margin -- and says so, rather
        # than implying the same confidence as the multi-sample checks
        # above.
        value = unique_values[0]
        if len(value) < _SHORT_TOKEN_MIN_LEN:
            bits = _worst_case_bits(value)
            findings.append(
                _finding(
                    "reset-token-short",
                    "low",
                    sample_url,
                    f"Only one `{param}` value was captured at {endpoint} ({len(value)} chars, "
                    f"~{bits:.0f} bits even under a generous base64-alphabet assumption) -- too "
                    "short for a safe margin against guessing; capture more samples to also "
                    "check for a sequential/low-entropy generation pattern",
                    value,
                )
            )

    return findings
