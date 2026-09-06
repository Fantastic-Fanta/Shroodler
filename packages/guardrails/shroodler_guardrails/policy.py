"""Consent/scope manifest + safety guardrails for agentic active-payload testing.

A target can publish `.well-known/scan-policy.json` to declare, in a
machine-readable way, what it consents to being actively tested and under
what limits. This module fetches and verifies that manifest, and enforces
it (origin + scope allow/deny, rate limits, an audit trail) around any
active payload-sending code path -- this is the prerequisite the roadmap
calls out before shipping any agent-autonomous active-testing mode: an
agent should not be able to fire payloads outside a scope a human (or the
target itself) explicitly consented to, and every attempt -- allowed or
blocked -- should leave a durable record.

The manifest is intentionally simple JSON, not a new DSL: allow/deny are
lists of path globs (matched the same way `.shroodlerignore` matches
URLs), plus numeric rate/volume limits and free-text contact/expiry
fields for humans.

Threat model notes (read before trusting this for anything real):

- A manifest only ever grants consent for the origin (scheme+host+port)
  it was fetched from. `ScanPolicy.covers()` rejects any URL whose origin
  doesn't match, regardless of what its allow/deny globs say -- a form
  discovered on the target whose `action` points off-host is never
  "in scope" no matter how permissive the manifest is.
- The manifest is fetched over plain HTTP unless the target is
  loopback/local, which is inherently spoofable by an on-path attacker;
  this is a best-effort, self-reported consent signal from the target
  operator, not a cryptographically verified one. Treat a fetched
  manifest as informational unless you control the network path.
- Numeric limits in a fetched manifest are clamped to hard ceilings the
  *caller* controls (`PolicyEnforcer(..., rpm_ceiling=..., total_ceiling=...)`),
  not just floored at 1 -- a malicious/compromised target cannot use its
  own manifest to raise its own rate limit above what the operator
  running the scan is willing to allow.
- The audit log is tamper-evident (hash-chained), not tamper-proof: it
  will reveal a deleted or edited line on replay, but nothing stops a
  local process with filesystem access from rewriting the whole file
  from scratch.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

WELL_KNOWN_PATH = "/.well-known/scan-policy.json"
DEFAULT_MAX_REQUESTS_PER_MINUTE = 60
DEFAULT_MAX_TOTAL_REQUESTS = 5000
# Absolute ceilings applied regardless of what a fetched manifest claims --
# a target's own manifest may only ever *tighten* these, never loosen them.
HARD_MAX_REQUESTS_PER_MINUTE = 600
HARD_MAX_TOTAL_REQUESTS = 50_000
MAX_MANIFEST_BYTES = 64 * 1024

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _glob_match(pattern: str, value: str) -> bool:
    if not pattern or pattern == "*":
        return True
    escaped = re.escape(pattern)
    regex = "^" + escaped.replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.search(regex, value) is not None


def _normalize_path(raw_path: str) -> str:
    """Percent-decode and collapse `.`/`..` segments before matching so an
    encoded or dot-segment path can't slip past a deny rule (or slip INTO
    an allow rule) that a literal string comparison would miss -- e.g.
    `/admin%2Fdelete` and `/public/../admin/delete` both normalize to
    `/admin/delete`, matching a deny of `/admin/*` the way a real
    webserver's router would resolve either form.
    """
    # Percent-decoding can itself reveal another layer in odd inputs; two
    # passes cover the common double-encoding evasion without looping
    # indefinitely on adversarial input.
    decoded = unquote(unquote(raw_path or "/"))
    segments: list[str] = []
    for part in decoded.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if segments:
                segments.pop()
            continue
        segments.append(part)
    return "/" + "/".join(segments)


def _path_of(url: str) -> str:
    return _normalize_path(urlparse(url).path or "/")


def origin_of(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme.lower()}://{p.hostname.lower() if p.hostname else ''}:{p.port or ''}"


# Internal alias kept for readability at call sites within this module.
_origin_of = origin_of


def _is_local_host(hostname: str | None) -> bool:
    return bool(hostname) and hostname.lower() in _LOCAL_HOSTS


@dataclass(frozen=True)
class ScanPolicy:
    """Parsed `.well-known/scan-policy.json` contents, bound to the origin
    it was fetched from (or explicitly supplied for a local policy file)."""

    raw: dict
    origin: str
    allow: tuple[str, ...] = ("*",)
    deny: tuple[str, ...] = ()
    max_requests_per_minute: int = DEFAULT_MAX_REQUESTS_PER_MINUTE
    max_total_requests: int = DEFAULT_MAX_TOTAL_REQUESTS
    contact: str = ""
    expires: str | None = None

    def covers(self, url: str) -> bool:
        # Origin binding is checked first and is not itself a glob: a
        # manifest fetched from (or authored for) one origin never grants
        # consent for requests to a different scheme/host/port, no matter
        # how permissive its allow list is. Only skipped when this policy
        # was constructed without a known origin (a bare --policy-file
        # with no target context), in which case scope is path-only.
        if self.origin and _origin_of(url) != self.origin:
            return False
        path = _path_of(url)
        if any(_glob_match(pat, path) for pat in self.deny):
            return False
        return any(_glob_match(pat, path) for pat in self.allow)

    def is_expired(self, *, today: date | None = None) -> bool:
        if not self.expires:
            return False
        try:
            exp = date.fromisoformat(self.expires)
        except ValueError:
            return True
        return (today or datetime.now(timezone.utc).date()) > exp


class PolicyViolation(RuntimeError):
    """Raised when the enforcer is asked to run in a mode that requires a
    manifest but none was found/valid, or when a caller explicitly opts
    into hard-fail-on-block semantics."""


def parse_policy(data: dict, *, origin: str = "") -> ScanPolicy:
    allow = tuple(str(p) for p in (data.get("allow") or ["*"]))
    deny = tuple(str(p) for p in (data.get("deny") or []))
    max_rpm = int(data.get("max_requests_per_minute", DEFAULT_MAX_REQUESTS_PER_MINUTE))
    max_total = int(data.get("max_total_requests", DEFAULT_MAX_TOTAL_REQUESTS))
    return ScanPolicy(
        raw=data,
        origin=origin,
        allow=allow,
        deny=deny,
        # A manifest may tighten these (any positive value below the hard
        # ceiling) but never loosen them past the ceiling the caller owns.
        max_requests_per_minute=max(1, min(max_rpm, HARD_MAX_REQUESTS_PER_MINUTE)),
        max_total_requests=max(1, min(max_total, HARD_MAX_TOTAL_REQUESTS)),
        contact=str(data.get("contact", "")),
        expires=data.get("expires"),
    )


def policy_hash(policy: ScanPolicy | dict) -> str:
    """Canonical sha256 of the manifest, embedded in reports as
    proof-of-consent -- lets a report reviewer confirm exactly which
    version of the target's manifest gated a given scan."""
    raw = policy.raw if isinstance(policy, ScanPolicy) else policy
    canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def fetch_policy(target: str, *, client=None, timeout: float = 5.0) -> ScanPolicy | None:
    """Fetch and parse the target's scan-policy manifest, if any.

    Returns None (not an error) when the target has no manifest -- most
    targets won't have one yet, and that absence is a legitimate, common
    state that callers decide how to treat (see PolicyEnforcer's
    `require_policy`). Also returns None for a manifest fetched over
    plain HTTP against a non-local target: an unauthenticated document is
    only meaningful as consent if it can't be trivially forged by
    whoever happens to be on-path, so a public target's manifest must be
    served over HTTPS to be honored.
    """
    import httpx

    base = target if target.endswith("/") else target + "/"
    url = urljoin(base, WELL_KNOWN_PATH.lstrip("/"))
    parsed = urlparse(url)
    if parsed.scheme != "https" and not _is_local_host(parsed.hostname):
        return None

    own_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        with http.stream("GET", url) as resp:
            if resp.status_code != 200:
                return None
            body = b""
            for chunk in resp.iter_bytes():
                body += chunk
                if len(body) > MAX_MANIFEST_BYTES:
                    return None
        data = json.loads(body)
        if not isinstance(data, dict):
            return None
        return parse_policy(data, origin=_origin_of(url))
    except (httpx.HTTPError, json.JSONDecodeError, ValueError):
        return None
    finally:
        if own_client:
            http.close()


@dataclass
class PolicyEnforcer:
    """Wraps origin+scope checks, rate limiting, and a tamper-evident audit
    log around active payload sends. One instance is meant to live for the
    lifetime of a single active-testing run (e.g. one `shroodler payload`
    invocation), and `check()` must be called once per actual outbound
    HTTP request -- not once per form/endpoint -- for the rate and
    blast-radius limits to mean what they say.
    """

    policy: ScanPolicy | None
    require_policy: bool = False
    audit_path: Path | None = None
    rpm_ceiling: int = HARD_MAX_REQUESTS_PER_MINUTE
    total_ceiling: int = HARD_MAX_TOTAL_REQUESTS
    _request_times: list[float] = field(default_factory=list)
    _total_requests: int = field(default=0)
    _audit_events: list[dict] = field(default_factory=list)
    _last_audit_hash: str = field(default="0" * 64)

    def __post_init__(self) -> None:
        if self.require_policy and self.policy is None:
            raise PolicyViolation(
                "no scan-policy manifest found at "
                f"{WELL_KNOWN_PATH} and --require-policy was set; refusing to "
                "run active payloads without explicit target consent"
            )
        if self.policy is not None and self.policy.is_expired():
            raise PolicyViolation(
                f"scan-policy manifest expired ({self.policy.expires}); "
                "refusing to run active payloads against a stale consent grant"
            )

    def _effective_rpm(self) -> int:
        base = self.policy.max_requests_per_minute if self.policy else DEFAULT_MAX_REQUESTS_PER_MINUTE
        return min(base, self.rpm_ceiling)

    def _effective_total(self) -> int:
        base = self.policy.max_total_requests if self.policy else DEFAULT_MAX_TOTAL_REQUESTS
        return min(base, self.total_ceiling)

    def check(self, url: str) -> tuple[bool, str]:
        """Return (allowed, reason). Always records an audit event."""
        now = time.monotonic()
        reason = "ok"
        allowed = True

        if self.policy is not None and not self.policy.covers(url):
            allowed, reason = False, "outside manifest allow/deny scope"
        elif self._total_requests >= self._effective_total():
            allowed, reason = False, "blast-radius limit (max_total_requests) reached"
        else:
            window_start = now - 60.0
            self._request_times = [t for t in self._request_times if t >= window_start]
            if len(self._request_times) >= self._effective_rpm():
                allowed, reason = False, "rate limit (max_requests_per_minute) reached"

        if allowed:
            self._request_times.append(now)
            self._total_requests += 1

        self._audit(url=url, allowed=allowed, reason=reason)
        return allowed, reason

    def _audit(self, *, url: str, allowed: bool, reason: str) -> None:
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "url": url,
            "allowed": allowed,
            "reason": reason,
            "policy_hash": policy_hash(self.policy) if self.policy else None,
            "prev_hash": self._last_audit_hash,
        }
        # Hash-chain each entry to the previous one (like a mini
        # append-only ledger) so deleting or editing a past line is
        # detectable on replay via `verify_audit_log`, even though
        # nothing stops rewriting the file wholesale from scratch.
        digest = hashlib.sha256(
            (self._last_audit_hash + json.dumps(event, sort_keys=True)).encode("utf-8")
        ).hexdigest()
        event["hash"] = digest
        self._last_audit_hash = digest
        self._audit_events.append(event)
        if self.audit_path is not None:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event) + "\n")

    @property
    def audit_events(self) -> list[dict]:
        return list(self._audit_events)

    def summary(self) -> dict:
        blocked = [e for e in self._audit_events if not e["allowed"]]
        return {
            "policy_hash": policy_hash(self.policy) if self.policy else None,
            "policy_present": self.policy is not None,
            "requests_attempted": len(self._audit_events),
            "requests_blocked": len(blocked),
            "block_reasons": sorted({e["reason"] for e in blocked}),
        }


def verify_audit_log(path: Path) -> list[str]:
    """Replay a hash-chained audit log and return a list of problems found
    (empty if the chain is intact). Detects deleted/reordered/edited lines."""
    problems: list[str] = []
    prev_hash = "0" * 64
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        event = json.loads(line)
        claimed_hash = event.get("hash", "")
        recomputed_input = {k: v for k, v in event.items() if k != "hash"}
        if recomputed_input.get("prev_hash") != prev_hash:
            problems.append(f"line {lineno}: prev_hash does not chain from the prior entry")
        expected = hashlib.sha256(
            (recomputed_input.get("prev_hash", "") + json.dumps(recomputed_input, sort_keys=True)).encode(
                "utf-8"
            )
        ).hexdigest()
        if expected != claimed_hash:
            problems.append(f"line {lineno}: hash does not match its own content (tampered?)")
        prev_hash = claimed_hash
    return problems
