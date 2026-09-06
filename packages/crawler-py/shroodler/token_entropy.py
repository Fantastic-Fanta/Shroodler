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
the finding; with three or more, it can test for an actual sequential/
incrementing pattern or estimate the real keyspace behind the sample.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from typing import Any
from urllib.parse import parse_qsl, urlparse

from shroodler.models import Finding
from shroodler.sessions import _request_url, _usable

# Query parameter names worth treating as a reset/verification token.
# Widened after review found the original list missed some of the most
# common real ones (Rails/Devise's reset_password_token, WordPress's
# key, and the near-universal generic code/t). Matched against the name
# with hyphens/underscores both normalized to "_" (see
# _normalize_param_name), so "reset-token" and "reset_token" are treated
# as the same name -- real APIs use both conventions.
TOKEN_PARAM_NAMES = frozenset(
    {
        "token",
        "reset_token",
        "reset_password_token",
        "reset_code",
        "otp",
        "code",
        "key",
        "t",
        "verification_code",
        "verify_token",
        "confirm_token",
        "confirmation_code",
        "confirmation_token",
        "activation_code",
        "activation_token",
        "magic_link_token",
        "auth_token",
        "invite_token",
        "invitation_token",
        "email_token",
        "signup_token",
    }
)

# Some frameworks (Django, Laravel) put the token in the PATH rather
# than the query string -- .../reset/<uidb64>/<token>/,
# .../password/reset/<token>. A path is only searched for a candidate
# token segment when it also contains one of these flow-indicating
# words, to avoid treating an arbitrary long path segment on an
# unrelated endpoint as a token.
_RESET_FLOW_PATH_RE = re.compile(r"reset|verify|confirm|activat|invit", re.IGNORECASE)

# An id-shaped path segment worth templating to a placeholder before
# grouping (a per-request id alongside the real token param, e.g.
# /reset/<uuid>/confirm?token=...), OR worth treating as a candidate
# token value itself on a reset-flow path. Deliberately requires actual
# id shape -- a UUID, all-digits, hex, or a mix of letters and digits --
# and never matches a pure-alphabetic segment: an earlier version of
# this regex (`[0-9a-zA-Z]{8,}`) matched ordinary path words like
# "passwordreset"/"verifyemail" too, which merged two DIFFERENT flows
# with different generators into one group in review.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_HEX_ID_RE = re.compile(r"^[0-9a-f]{12,}$", re.IGNORECASE)
_DIGIT_ID_RE = re.compile(r"^[0-9]{6,}$")
_MIXED_ALNUM_ID_RE = re.compile(r"^(?=[0-9a-zA-Z]*[0-9])(?=[0-9a-zA-Z]*[a-zA-Z])[0-9a-zA-Z]{8,}$")

# Applied to the (possibly common-affix-stripped) analyzed values, not
# the raw token -- no minimum length here since stripping a shared
# prefix/suffix can legitimately shorten a value well below
# _MIN_TOKEN_LEN while what's left is still the real varying part.
_STRICT_INT_RE = re.compile(r"^[0-9]+$")

_MIN_TOKEN_LEN = 6
# Below this many pooled bits of keyspace (length * log2(observed
# alphabet size)), the sample is small enough to be brute-forced at
# scale if the endpoint has no real rate limiting -- this tool cannot
# see whether rate limiting exists, so the finding says exactly that
# instead of claiming the generator itself is broken.
_SMALL_KEYSPACE_BITS = 64.0
# Sequential detection requires 3+ distinct values (a relative-span
# check on just 2 points is too easily fooled either way) and looks at
# the RELATIVE span (max-min)/mean rather than an absolute window, so it
# catches a big-jump shared auto-increment or an epoch-timestamp token
# just as reliably as a tightly-incrementing counter -- both have a
# relative span many orders of magnitude below a genuinely random
# sample's, regardless of the token's absolute magnitude.
_MIN_SEQUENTIAL_SAMPLES = 3
_SEQUENTIAL_RELATIVE_SPAN = 0.01
# Single-sample worst-case length floor, in bits, assuming the sample's
# own observed alphabet (not a generous base64 fantasy) -- see
# _single_sample_bits.
_SHORT_TOKEN_MIN_BITS = 64.0


def _is_id_shaped(segment: str) -> bool:
    return bool(
        _UUID_RE.match(segment)
        or _HEX_ID_RE.match(segment)
        or _DIGIT_ID_RE.match(segment)
        or _MIXED_ALNUM_ID_RE.match(segment)
    )


def _normalize_param_name(name: str) -> str:
    return name.lower().replace("-", "_")


def _template_path(path: str) -> str:
    """Collapse a per-request-varying, id-shaped path segment to a
    placeholder, so e.g. /reset/<uuid>/confirm and
    /reset/<other-uuid>/confirm group together as the same endpoint
    template instead of each observation landing in its own singleton
    group."""
    segments = path.split("/")
    templated = ["{id}" if _is_id_shaped(seg) else seg for seg in segments]
    return "/".join(templated)


def _path_token_candidates(path: str) -> list[str]:
    """Id-shaped segments on a path whose wording suggests a reset/
    verification flow -- covers Django (/reset/<uidb64>/<token>/) and
    Laravel (/password/reset/<token>) style URLs, where the token is a
    path segment rather than a query parameter."""
    if not _RESET_FLOW_PATH_RE.search(path):
        return []
    return [seg for seg in path.split("/") if _is_id_shaped(seg) and len(seg) >= _MIN_TOKEN_LEN]


def _common_affix_stripped(values: list[str]) -> list[str]:
    """Strip the longest common prefix and suffix shared by every value
    before analysis, so a token like "reset-<timestamp>" is judged on
    its actually-varying part rather than the fixed "reset-" text
    inflating an entropy/keyspace estimate that has nothing to do with
    how unpredictable the token really is."""
    if len(values) < 2:
        return values
    prefix_len = 0
    shortest = min(len(v) for v in values)
    while prefix_len < shortest and len({v[prefix_len] for v in values}) == 1:
        prefix_len += 1
    suffix_len = 0
    while (
        suffix_len < shortest - prefix_len
        and len({v[len(v) - 1 - suffix_len] for v in values}) == 1
    ):
        suffix_len += 1
    return [v[prefix_len : len(v) - suffix_len] if suffix_len else v[prefix_len:] for v in values]


def _pooled_keyspace_bits(values: list[str]) -> float:
    """Conservative keyspace estimate from the sample actually observed:
    the shortest sampled length times log2 of the alphabet actually used
    across all samples (not an assumed alphabet) -- deliberately not
    per-string Shannon entropy, which review found routinely
    false-positives on short-but-correct tokens (a 6-digit OTP's entropy
    ceiling, log2(6), is barely above any reasonable low-entropy
    threshold, so a single repeated digit sinks a perfectly good OTP)."""
    alphabet = {ch for v in values for ch in v}
    if not alphabet:
        return 0.0
    min_len = min(len(v) for v in values)
    return min_len * math.log2(len(alphabet))


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def _finding(fid: str, severity: str, url: str, description: str, evidence: str) -> Finding:
    return Finding(
        id=fid, severity=severity, category="secret", url=url, description=description,
        evidence=evidence,
    )


def _extract_token_observations(
    sessions: list[dict[str, Any]],
) -> dict[tuple[str, str, str], list[tuple[str, str]]]:
    """Group observed token values by (host, path_template, source) --
    the same endpoint/parameter template, however many times it was
    observed. `source` is either a normalized query-param name or the
    literal marker "{path}" for a path-segment token. Each entry is
    (token_value, full_url_it_was_seen_at), in first-observed order."""
    groups: dict[tuple[str, str, str], list[tuple[str, str]]] = defaultdict(list)
    for sess in sessions:
        if not _usable(sess):
            continue
        url = _request_url(sess)
        parsed = urlparse(url)
        template = _template_path(parsed.path)

        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            name = _normalize_param_name(key)
            if name not in TOKEN_PARAM_NAMES or len(value) < _MIN_TOKEN_LEN:
                continue
            groups[(parsed.hostname or "", template, name)].append((value, url))

        for value in _path_token_candidates(parsed.path):
            groups[(parsed.hostname or "", template, "{path}")].append((value, url))

    return groups


def _is_sequential(values: list[str]) -> bool:
    """True when the samples reduce to strict base-10 integers that
    cluster within a narrow range RELATIVE to their own magnitude --
    catches a shared auto-increment counter that jumps by hundreds of
    thousands, or a millisecond-epoch token, exactly as reliably as a
    tightly-incrementing counter, since both have a relative span many
    orders of magnitude below a genuinely random sample's regardless of
    absolute size. Requires 3+ distinct values: a relative-span check on
    just 2 points is too easily fooled either way (see
    _MIN_SEQUENTIAL_SAMPLES).

    Values are used as-is if already all-digit; only when they AREN'T
    (a fixed textual prefix/suffix, e.g. "reset-1757000000") is each
    value's own leading/trailing non-digit characters stripped away
    (per-value, NOT a cross-sample common-affix strip -- close-in-time
    epoch timestamps routinely share several leading digits too, e.g.
    "1757000000"/"1757000431"/"1757001902" all start with "175700", and
    a cross-sample common-prefix strip would eat into that shared digit
    run and leave too little behind, exactly the kind of self-defeating
    interaction a dedicated per-value strip avoids), keeping only the
    digit run. That's rejected if it's not still a long-enough run
    (>=6 digits) to be a meaningful counter/timestamp rather than a tiny
    1-2 digit remainder -- e.g. stripping a purely-numeric value's OWN
    leading digits ("100001"/"2"/"3" down to "1"/"2"/"3", if it were
    mishandled the same way) would wrongly blow up the relative-span
    metric, since relative span is meaningless for single-digit
    magnitudes."""
    if len(values) < _MIN_SEQUENTIAL_SAMPLES:
        return False
    if all(_STRICT_INT_RE.match(v) for v in values):
        candidates = values
    else:
        stripped = [re.sub(r"^\D+", "", re.sub(r"\D+$", "", v)) for v in values]
        if not all(_STRICT_INT_RE.match(v) and len(v) >= _MIN_TOKEN_LEN for v in stripped):
            return False
        candidates = stripped
    ints = [int(v) for v in candidates]
    mean = sum(ints) / len(ints)
    if mean == 0:
        return False
    relative_span = (max(ints) - min(ints)) / mean
    return relative_span <= _SEQUENTIAL_RELATIVE_SPAN


def analyze_tokens(sessions: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for (host, path, source), observations in _extract_token_observations(sessions).items():
        sample_url = observations[-1][1]
        label = source if source == "{path}" else f"`{source}`"
        endpoint = f"{host}{path}"

        # Dedupe identical values before deciding how many samples there
        # are: a proxy recording naturally captures retries/redirect
        # chains/a tester revisiting the same emailed link twice, and
        # the same literal value observed N times is one real data
        # point, not N.
        seen_values: list[str] = []
        for v, _ in observations:
            if v not in seen_values:
                seen_values.append(v)

        # Always-true, always-confirmable baseline signal: this value is
        # sitting in a URL, which leaks via Referer headers, proxy/CDN/
        # server access logs, and browser history regardless of how
        # predictable it is.
        findings.append(
            _finding(
                "reset-token-in-url",
                "medium",
                sample_url,
                f"A reset/verification value ({label} at {endpoint}) is transmitted in a URL, "
                "which leaks via Referer headers, browser history, and proxy/server access logs "
                "-- prefer a one-time POST body or a single-use, immediately-consumed redirect",
                _redact(seen_values[0]),
            )
        )

        analyzed = _common_affix_stripped(seen_values) if len(seen_values) >= 2 else seen_values

        if len(seen_values) >= _MIN_SEQUENTIAL_SAMPLES and _is_sequential(seen_values):
            findings.append(
                _finding(
                    "reset-token-sequential",
                    # high, not critical: this is a strong statistical
                    # lead from a handful of samples, not a proven
                    # finding -- consistent with how this codebase scores
                    # every other single-session/small-sample signal
                    # (see idor-adjacent-id-accessible's remediation
                    # text for the same reasoning).
                    "high",
                    sample_url,
                    f"{len(seen_values)} distinct observed values of {label} at {endpoint} are "
                    "small relative to each other (after stripping any common prefix/suffix) -- "
                    "consistent with a sequential/incrementing or timestamp-derived generator "
                    "rather than a random token. Treat as a strong lead to manually confirm "
                    "(request two resets back-to-back and compare), not a proven finding from "
                    "this sample alone",
                    ", ".join(_redact(v) for v in seen_values[:5]),
                )
            )
            continue

        if len(seen_values) >= 2:
            bits = _pooled_keyspace_bits(analyzed)
            if bits < _SMALL_KEYSPACE_BITS:
                findings.append(
                    _finding(
                        "reset-token-small-keyspace",
                        "medium",
                        sample_url,
                        f"{len(seen_values)} distinct observed values of {label} at {endpoint} "
                        f"span an estimated ~{bits:.0f} bits of keyspace (after stripping any "
                        "common prefix/suffix) -- brute-forceable at scale unless this endpoint "
                        "has real rate limiting/lockout on repeated attempts, which this tool "
                        "cannot observe from a recorded session",
                        ", ".join(_redact(v) for v in seen_values[:5]),
                    )
                )
            continue

        # Exactly one distinct sample: no cross-sample comparison is
        # possible, so this only ever makes a single, explicitly
        # conservative claim from the sample's OWN observed alphabet
        # (not an assumed one), and says so, rather than implying the
        # same confidence as the multi-sample checks above.
        value = seen_values[0]
        bits = _pooled_keyspace_bits([value])
        if bits < _SHORT_TOKEN_MIN_BITS:
            findings.append(
                _finding(
                    "reset-token-short",
                    "low",
                    sample_url,
                    f"Only one distinct value of {label} was captured at {endpoint} "
                    f"({len(value)} chars over its own {len(set(value))}-symbol alphabet, "
                    f"~{bits:.0f} bits) -- too short for a safe margin against guessing; "
                    "capture more samples to also check for a sequential or small-keyspace "
                    "generation pattern",
                    _redact(value),
                )
            )

    return findings
