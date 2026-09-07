"""Minimum interval between live requests (agent-safe rate limit).

Playwright/fetch loops in a bounty session can stampede a 1-req/s program
and eat a Cloudflare 1015. Every live helper that fires more than one
request (peer-write, paced-fetch) goes through this so the CLI and MCP
paths share one clock. Sleep is injectable so tests do not wait.
"""

from __future__ import annotations

import time
from collections.abc import Callable


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
        sleeper: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        self.min_interval = max(0.0, float(min_interval))
        self._sleeper = sleeper
        self._now = now
        self._last: float | None = None

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        t = self._now()
        if self._last is not None:
            gap = self.min_interval - (t - self._last)
            if gap > 0:
                self._sleeper(gap)
                t = self._now()
        self._last = t
