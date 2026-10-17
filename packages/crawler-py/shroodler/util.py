"""Small shared helpers used across modules.

Keep this module dependency-free (stdlib only) so anything can import it
without risking an import cycle.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone


def now_utc() -> datetime:
    """Timezone-aware current time in UTC."""
    return datetime.now(timezone.utc)


def now_iso() -> str:
    """Current UTC time as an ISO 8601 timestamp with a trailing 'Z'."""
    return now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")


def log_exc(component: str, exc: BaseException) -> None:
    """Print a one-line JSON error to stderr, tagged with the component name."""
    print(
        json.dumps(
            {"error": f"{component}: {type(exc).__name__}: {exc}"}, default=str
        ),
        file=sys.stderr,
        flush=True,
    )
