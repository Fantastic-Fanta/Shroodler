"""Auto-generate a regression test from a confirmed-then-fixed finding.

Closes the loop without needing an agent present at fix time: a finding
that `reverify` confirmed is gone gets a small, standalone pytest file
that re-checks the same (finding_id, url) pair on every future CI run,
so if the fix regresses, a targeted test fails immediately rather than
waiting for the next full scan (or a bug report) to notice.

The generated test calls `shroodler.reverify.reverify()` directly rather
than re-deriving the original request from scratch: reverify already
knows how to re-crawl a route and re-run active payload packs against
it, and reusing it means the generated test's pass/fail semantics are
identical to the check that confirmed the fix in the first place -- no
separate, potentially-drifting reimplementation of "how do I resend
this."
"""

from __future__ import annotations

import re


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_").lower()
    return slug or "finding"


def render_regression_test(
    url: str,
    finding_id: str,
    *,
    mode: str = "static",
    run_payloads: bool = True,
    allow_external: bool = False,
) -> str:
    """Returns the full contents of a pytest module. Write it to a file
    named `test_regression_<slug>.py` under wherever the project keeps
    its regression tests.
    """
    func_name = f"test_regression_{_slugify(finding_id)}_{_slugify(url)}"
    return f'''"""Auto-generated regression test -- do not hand-edit the assertions below;
regenerate with `shroodler gen-regression-test` instead if the target URL
or finding id changes.

Guards against {finding_id!r} reappearing at {url!r}, confirmed fixed via
`shroodler reverify` at generation time.
"""

from __future__ import annotations

from shroodler.reverify import reverify

URL = {url!r}
FINDING_ID = {finding_id!r}


def {func_name}():
    result = reverify(
        URL,
        FINDING_ID,
        mode={mode!r},
        run_payloads={run_payloads!r},
        allow_external={allow_external!r},
    )
    assert result["verified_fixed"], (
        f"{{FINDING_ID}} has regressed at {{URL}}: "
        f"{{result['matching_findings']}}"
    )
'''
