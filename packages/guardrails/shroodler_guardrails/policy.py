"""Consent/scope manifest + safety guardrails for agentic active-payload testing.

A target can publish `.well-known/scan-policy.json` to declare, in a
machine-readable way, what it consents to being actively tested and under
what limits. This module fetches and verifies that manifest, and enforces
it (scope allow/deny, rate limits, an audit trail) around any active
payload-sending code path -- this is the prerequisite the roadmap calls
out before shipping any agent-autonomous active-testing mode: an agent
should not be able to fire payloads outside a scope a human (or the
target itself) explicitly consented to, and every attempt -- allowed or
blocked -- should leave a durable record.

The manifest is intentionally simple JSON, not a new DSL: allow/deny are
lists of path globs (matched the same way `.shroodlerignore` matches
URLs), plus numeric rate/volume limits and free-text contact/expiry
fields for humans.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

WELL_KNOWN_PATH = "/.well-known/scan-policy.json"
DEFAULT_MAX_REQUESTS_PER_MINUTE = 60
DEFAULT_MAX_TOTAL_REQUESTS = 5000


def _glob_match(pattern: str, value: str) -> bool:
    if not pattern or pattern == "*":
        return True
    escaped = re.escape(pattern)
    regex = "^" + escaped.replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.search(regex, value) is not None


def _path_of(url: str) -> str:
    return urlparse(url).path or "/"


@dataclass(frozen=True)
class ScanPolicy:
    """Parsed `.well-known/scan-policy.json` contents."""

    raw: dict
    allow: tuple[str, ...] = ("*",)
    deny: tuple[str, ...] = ()
    max_requests_per_minute: int = DEFAULT_MAX_REQUESTS_PER_MINUTE
    max_total_requests: int = DEFAULT_MAX_TOTAL_REQUESTS
    contact: str = ""
    expires: str | None = None

    def covers(self, url: str) -> bool:
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


def parse_policy(data: dict) -> ScanPolicy:
    allow = tuple(str(p) for p in (data.get("allow") or ["*"]))
    deny = tuple(str(p) for p in (data.get("deny") or []))
    max_rpm = int(data.get("max_requests_per_minute", DEFAULT_MAX_REQUESTS_PER_MINUTE))
    max_total = int(data.get("max_total_requests", DEFAULT_MAX_TOTAL_REQUESTS))
    return ScanPolicy(
        raw=data,
        allow=allow,
        deny=deny,
        max_requests_per_minute=max(1, max_rpm),
        max_total_requests=max(1, max_total),
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
    `require_policy`).
    """
    import httpx

    url = urljoin(target if target.endswith("/") else target + "/", WELL_KNOWN_PATH.lstrip("/"))
    own_client = client is None
    http = client or httpx.Client(timeout=timeout)
    try:
        resp = http.get(url)
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not isinstance(data, dict):
            return None
        return parse_policy(data)
    except (httpx.HTTPError, json.JSONDecodeError, ValueError):
        return None
    finally:
        if own_client:
            http.close()


@dataclass
class PolicyEnforcer:
    """Wraps scope checks, rate limiting, and an audit log around active
    payload sends. One instance is meant to live for the lifetime of a
    single active-testing run (e.g. one `shroodler payload` invocation).
    """

    policy: ScanPolicy | None
    require_policy: bool = False
    audit_path: Path | None = None
    _request_times: list[float] = field(default_factory=list)
    _total_requests: int = field(default=0)
    _audit_events: list[dict] = field(default_factory=list)

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

    def check(self, url: str) -> tuple[bool, str]:
        """Return (allowed, reason). Always records an audit event."""
        now = time.monotonic()
        reason = "ok"
        allowed = True

        if self.policy is not None and not self.policy.covers(url):
            allowed, reason = False, "outside manifest allow/deny scope"
        elif self._total_requests >= (
            self.policy.max_total_requests if self.policy else DEFAULT_MAX_TOTAL_REQUESTS
        ):
            allowed, reason = False, "blast-radius limit (max_total_requests) reached"
        else:
            window_start = now - 60.0
            self._request_times = [t for t in self._request_times if t >= window_start]
            limit = (
                self.policy.max_requests_per_minute
                if self.policy
                else DEFAULT_MAX_REQUESTS_PER_MINUTE
            )
            if len(self._request_times) >= limit:
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
        }
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
