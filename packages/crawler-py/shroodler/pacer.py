"""Minimum interval between live requests (agent-safe rate limit).

Playwright/fetch loops in a bounty session can stampede a 1-req/s program
and eat a Cloudflare 1015. Every live helper that fires more than one
request (peer-write, paced-fetch) goes through this so the CLI and MCP
paths share one clock. Sleep is injectable so tests do not wait.
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable

# Per-host spacing. quiet = 2 req/s, balanced = 5, aggressive = 20.
NOISE_PROFILES: dict[str, float] = {
    "quiet": 0.5,
    "balanced": 0.2,
    "aggressive": 0.05,
}


def compose_user_agent(base: str | None = None, suffix: str | None = None) -> str:
    """Append an operator suffix (e.g. Bugcrowd-handle) without replacing the UA."""
    from shroodler.robots import DEFAULT_UA

    ua = (base or DEFAULT_UA).strip() or DEFAULT_UA
    suf = (suffix or "").strip()
    if suf and suf not in ua:
        return f"{ua} {suf}"
    return ua


class Pacer:
    def __init__(
        self,
        min_interval: float = 1.0,
        *,
        profile: str | None = None,
        jitter: float | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.monotonic,
        rng: Callable[[], float] | None = None,
    ) -> None:
        if profile:
            if profile not in NOISE_PROFILES:
                raise ValueError(
                    f"unknown noise profile {profile!r}; "
                    "use quiet, balanced, or aggressive"
                )
            min_interval = NOISE_PROFILES[profile]
            if jitter is None:
                jitter = min_interval * 0.2
        self.min_interval = max(0.0, float(min_interval))
        self.jitter = max(0.0, float(jitter or 0.0))
        self.profile = profile or ""
        self._sleeper = sleeper
        self._now = now
        self._rng = rng or random.random
        self._last: float | None = None
        self._host_last: dict[str, float] = {}
        self._backoff: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str | None = None) -> None:
        with self._lock:
            if host:
                self._wait_keyed(host, self._host_last)
            else:
                self._wait_global()

    def note_status(self, host: str, status: int) -> None:
        """Back off a host that returned 429 or 503. Other statuses clear it."""
        if not host:
            return
        with self._lock:
            if int(status) in {429, 503}:
                current = self._backoff.get(host, 0.0)
                base = current or max(self.min_interval, 0.5)
                self._backoff[host] = min(30.0, base * 2)
            else:
                self._backoff.pop(host, None)

    def _wait_global(self) -> None:
        if self.min_interval <= 0:
            return
        t = self._now()
        if self._last is not None:
            gap = self.min_interval - (t - self._last)
            if gap > 0:
                self._sleeper(gap)
                t = self._now()
        self._last = t

    def _wait_keyed(self, host: str, clock: dict[str, float]) -> None:
        extra = self._backoff.get(host, 0.0)
        interval = self.min_interval + extra
        if self.jitter > 0 and interval > 0:
            interval += self.jitter * float(self._rng())
        if interval <= 0:
            return
        t = self._now()
        previous = clock.get(host)
        if previous is not None:
            gap = interval - (t - previous)
            if gap > 0:
                self._sleeper(gap)
                t = self._now()
        clock[host] = t
