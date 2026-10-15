from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from shroodler.modes import headless


def test_failed_launch_releases_the_event_loop():
    """A browser-launch failure must stop the sync_playwright driver so its
    event loop does not leak into the process. Regression test: a leaked loop
    made every later asyncio.run() fail with 'another event loop is running',
    cascading one missing CI browser into dozens of unrelated failures."""
    with patch.object(headless, "sync_playwright") as m:
        started = m.return_value.start.return_value
        started.chromium.launch.side_effect = RuntimeError("missing browser")

        with pytest.raises(RuntimeError):
            headless.HeadlessFetcher()

        # The driver was stopped (loop released)...
        assert started.stop.called
        # ...so asyncio.run works instead of raising "another event loop is
        # running".
        async def _ping() -> str:
            return "pong"

        assert asyncio.run(_ping()) == "pong"
