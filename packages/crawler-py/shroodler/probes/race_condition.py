"""Race-condition / TOCTOU probe (conservative, low false-positive).

Blindly firing concurrent requests at any endpoint and calling multiple 200s a
"race" is noise: most endpoints are idempotent. This probe only reports when it
sees the actual TOCTOU signature:

1. a first request succeeds, and a second *sequential* request is rejected --
   so the endpoint enforces a single-use / limit check serially; then
2. a concurrent burst of the same request still gets two or more successes --
   so that check has a time-of-check/time-of-use window.

Only then does it report `race-condition` (medium, heuristic). If the endpoint
happily repeats (not single-use), it bails without firing the burst.

Side-effecting (it submits the request several times), so it is off by default
and runs only in aggressive mode.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, normalize_params, request, url_without_query

_REJECT_STATUSES = {403, 409, 423, 429}
_REJECT_MARKERS = ("already", "used", "exceeded", "limit", "duplicate", "only once", "not allowed")
_MAX_CONCURRENCY = 10


def _is_success(resp: httpx.Response | None) -> bool:
    if resp is None:
        return False
    return 200 <= int(getattr(resp, "status_code", 0) or 0) < 300


def _has_reject_marker(resp: httpx.Response) -> bool:
    body = body_text(resp).lower()
    return any(marker in body for marker in _REJECT_MARKERS)


def _looks_rejected(first: httpx.Response, second: httpx.Response | None) -> bool:
    """True when `second` looks like a single-use/limit rejection vs `first`."""
    if second is None:
        return False
    s1 = int(getattr(first, "status_code", 0) or 0)
    s2 = int(getattr(second, "status_code", 0) or 0)
    if s2 in _REJECT_STATUSES and s2 != s1:
        return True
    if not (200 <= s2 < 300) and (200 <= s1 < 300):
        return True
    # A rejection phrase that appears in the second response but not the first.
    return _has_reject_marker(second) and not _has_reject_marker(first)


def _single_use_enforced(r1: httpx.Response | None, r2: httpx.Response | None) -> bool:
    return _is_success(r1) and _looks_rejected(r1, r2)  # type: ignore[arg-type]


def _count_successes(responses: list[httpx.Response | None]) -> int:
    return sum(1 for r in responses if _is_success(r))


def probe_race_condition(
    url: str,
    method: str,
    params: list[dict],
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    state=None,
    concurrency: int = 8,
    fire: Callable[[], Any] | None = None,
) -> list[Finding]:
    """Detect a TOCTOU window on a single-use state-changing endpoint."""
    method_u = (method or "POST").upper()
    if method_u not in {"POST", "PUT", "PATCH", "DELETE"}:
        return []
    normalized = normalize_params(params)
    values = {item["name"]: item.get("value") or "shroodler" for item in normalized}

    def _default_fire() -> httpx.Response | None:
        return request(
            method_u,
            url_without_query(url),
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
            data=values,
        )

    do = fire or _default_fire

    # Sequential: does the endpoint enforce single-use at all?
    r1 = do()
    r2 = do()
    if not _single_use_enforced(r1, r2):
        return []

    # Concurrent burst: does the single-use check have a race window?
    n = max(2, min(int(concurrency), _MAX_CONCURRENCY))
    with ThreadPoolExecutor(max_workers=n) as pool:
        responses = list(pool.map(lambda _i: do(), range(n)))
    successes = _count_successes(responses)
    if successes < 2:
        return []

    return [
        Finding(
            id="race-condition",
            severity="medium",  # type: ignore[arg-type]
            category="payload",
            url=url,
            description=(
                f"{method_u} enforced a single-use/limit check sequentially (a "
                f"second request was rejected) but {successes}/{n} concurrent "
                "requests succeeded, indicating a time-of-check/time-of-use race."
            ),
            evidence=f"concurrent_successes={successes}/{n} method={method_u}",
            confidence="heuristic",  # type: ignore[arg-type]
        )
    ]
