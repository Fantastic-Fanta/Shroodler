"""Closed-loop remediate-and-reverify: after a finding is (supposedly)
patched, re-scan just that route and report whether the specific finding
is actually gone -- "verified fixed", not "a patch was applied". Nobody
closes this loop end-to-end today; every "AI security fix" product stops
at a suggested patch and leaves verification to a human. This is the
verification half: an agent (or a human) that just edited source in
response to a finding calls this on the same URL before opening/merging
a PR, and only a `verified_fixed: true` result means the specific
(id, url) pair that was flagged is actually gone from a fresh scan --
not merely "the page still loads", and not "some other finding at the
same URL disappeared instead."

Known limitation, important to the trust this is built on: a finding's
id is per (pack, route), not per (pack, parameter) -- if a page has TWO
vulnerable query parameters that the same payload pack flags, the
original scan reports ONE finding for that (id, url) pair, and fixing
only one of them still leaves the finding_id "present" (good -- the
active payload re-run above re-fuzzes every parameter the page exposes,
so this is actually caught). The real gap is the other direction: `url`
here MUST be the exact URL recorded on the original finding, including
its query string -- passing a simplified/bare path instead means the
active payload run has no query-string parameters to rediscover and
fuzz for that page, so a still-vulnerable parameter can go untested and
this can wrongly report `verified_fixed: true`. `reverify()` cannot
detect that mistake after the fact; callers building automation on top
of this (e.g. auto-merging a PR on `verified_fixed`) must pass the
finding's own `url` field unmodified, not a hand-typed approximation of
it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib.parse import urlparse


def _payload_tester_dir() -> Path:
    env = os.environ.get("SHROODLER_PAYLOAD_DIR")
    if env:
        cand = Path(env)
        if (cand / "tester.py").is_file():
            return cand
        raise FileNotFoundError(f"payload-tester not found in {cand}")
    for parent in Path(__file__).resolve().parents:
        for cand in (parent / "packages" / "payload-tester", parent / "payload-tester"):
            if (cand / "tester.py").is_file():
                return cand
    raise FileNotFoundError("payload-tester not found; set SHROODLER_PAYLOAD_DIR")


def reverify(
    url: str,
    finding_id: str,
    *,
    mode: str = "static",
    allow_external: bool = False,
    run_payloads: bool = True,
    enforcer=None,
    cookies: list[str] | None = None,
    headers: list[str] | None = None,
) -> dict:
    """Re-crawl exactly `url` (no link-following) and, unless
    `run_payloads=False`, re-run active payload packs against it, then
    report whether `finding_id` still appears among the results for that
    same URL. `enforcer`, if given, gates the payload run exactly like
    `shroodler payload`/`scan_route` do.
    """
    from shroodler.crawler import crawl_url
    from shroodler.validate import validate_crawl

    result = crawl_url(
        url,
        mode=mode,
        depth=0,
        max_pages=1,
        allow_external=allow_external,
        cookies=list(cookies or []),
        headers=list(headers or []),
    )
    doc = result.to_dict()
    validate_crawl(doc)
    findings = list(doc.get("findings", []))

    payload_out = None
    if run_payloads:
        tester_dir = str(_payload_tester_dir())
        if tester_dir not in sys.path:
            sys.path.insert(0, tester_dir)
        import tester

        payload_out = tester.run(doc, allow_external=allow_external, enforcer=enforcer)
        findings.extend(payload_out["findings"])

    parsed_url = urlparse(url)
    target_path = parsed_url.path or "/"
    still_present = [
        f
        for f in findings
        if f.get("id") == finding_id and (urlparse(f.get("url", "")).path or "/") == target_path
    ]

    warnings: list[str] = []
    if run_payloads and finding_id.startswith("payload-") and not parsed_url.query:
        warnings.append(
            "url has no query string but finding_id looks like a GET-parameter-based "
            "payload finding -- if the original finding was at a URL with query "
            "parameters, this re-scan won't rediscover or re-fuzz them, and a "
            "verified_fixed=true here would not actually prove that parameter is "
            "fixed. Pass the finding's exact original url, including its query string."
        )

    return {
        "url": url,
        "finding_id": finding_id,
        "still_present": bool(still_present),
        "verified_fixed": not still_present,
        "matching_findings": still_present,
        "all_findings": findings,
        "guardrail": payload_out.get("guardrail") if payload_out else None,
        "warnings": warnings,
    }
