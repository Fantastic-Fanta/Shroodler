"""Rate-limited GETs for agent/Playwright loops.

A bounty program that says 1 req/s is not a suggestion. This is the
shared helper for `shroodler paced-fetch` and the MCP `paced_fetch` tool
so neither path can stampede. It does not solve captchas; a challenge
response is recorded and the next URL still waits out the pacer.
"""

from __future__ import annotations

from typing import Any

import httpx

from shroodler.extractors.challenge import detect_challenge
from shroodler.pacer import Pacer, compose_user_agent
from shroodler.urls import is_loopback_or_local

DEFAULT_RATE = 1.0
MAX_URLS = 100
MCP_MAX_URLS = 20


def _challenge(resp: httpx.Response) -> bool:
    headers = {k: v for k, v in resp.headers.items()}
    raw = resp.headers.get("set-cookie")
    set_cookies = [raw] if raw else []
    return detect_challenge(headers, resp.text, resp.status_code, set_cookies) is not None


def fetch_urls(
    urls: list[str],
    *,
    method: str = "GET",
    cookie_header: str = "",
    extra_headers: dict[str, str] | None = None,
    allow_external: bool = False,
    client: httpx.Client | None = None,
    enforcer=None,
    pacer: Pacer | None = None,
    rate: float = DEFAULT_RATE,
    user_agent: str = "",
    user_agent_suffix: str = "",
    max_urls: int = MAX_URLS,
) -> dict[str, Any]:
    if len(urls) > max_urls:
        urls = list(urls[:max_urls])
        truncated = True
    else:
        truncated = False

    method = (method or "GET").upper()
    if method not in {"GET", "HEAD", "OPTIONS"}:
        raise ValueError("paced-fetch only sends GET/HEAD/OPTIONS (no write methods)")

    ua = compose_user_agent(user_agent or None, user_agent_suffix or None)
    headers = dict(extra_headers or {})
    if cookie_header:
        headers["Cookie"] = cookie_header
    if ua:
        headers.setdefault("User-Agent", ua)

    clock = pacer or Pacer(rate)
    http = client or httpx.Client(timeout=8.0, follow_redirects=False)
    own = client is None
    results: list[dict[str, Any]] = []
    try:
        for url in urls:
            url = (url or "").strip()
            if not url:
                continue
            if not allow_external and not is_loopback_or_local(url):
                results.append({"url": url, "error": "non-local; pass --allow-external"})
                continue
            clock.wait()
            if enforcer is not None:
                ok, reason = enforcer.check(url)
                if not ok:
                    results.append({"url": url, "error": f"blocked: {reason}"})
                    continue
            try:
                resp = http.request(method, url, headers=headers)
            except httpx.HTTPError as exc:
                results.append({"url": url, "error": str(exc)})
                continue
            row: dict[str, Any] = {
                "url": url,
                "status": resp.status_code,
                "bytes": len(resp.content),
            }
            if _challenge(resp):
                row["challenge"] = True
            results.append(row)
    finally:
        if own:
            http.close()

    out: dict[str, Any] = {"results": results, "rate": rate}
    if truncated:
        out["truncated"] = True
    return out


_shared_pacer: Pacer | None = None


def pace(pacer: Pacer | None = None) -> None:
    """Block until the next live request is allowed by the rate limiter.

    Probe modules must call this before every HTTP request. Pass the agent's
    Pacer when one is available so crawl/probe share a clock; otherwise a
    module-level 1 req/s pacer is used.
    """
    global _shared_pacer
    clock = pacer
    if clock is None:
        if _shared_pacer is None:
            _shared_pacer = Pacer(DEFAULT_RATE)
        clock = _shared_pacer
    clock.wait()
