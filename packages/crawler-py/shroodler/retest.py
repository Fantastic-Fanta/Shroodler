"""Standing retest: re-check a set of findings over time, with a status that
distinguishes "fixed" from "could not confirm".

:mod:`shroodler.reverify` answers one question about one finding: is it still
present on a fresh scan of its URL. This module turns that into a tracked,
multi-finding, over-time view -- the thing a human remembers across engagements
and a point-in-time scan does not:

* a three-state status per finding -- ``reproduces`` (still exploitable),
  ``fixed`` (demonstrably gone on a trustworthy re-scan), or ``unconfirmable``
  (the re-scan could not establish either, e.g. the original URL's query string
  was dropped, a guardrail gated the payload run, or the re-scan errored). The
  third state is the honest one: silence is not a fix.
* transitions against a prior retest -- a finding that was ``fixed`` and now
  ``reproduces`` is a **regression**, the most important signal here; a finding
  that was ``reproduces`` and is now ``fixed`` is newly resolved.

Clean-room reimplementation of the architecture behind ARTEX's retester agent
(AGPL); this is Shroodler's own code, under Apache-2.0.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from shroodler.util import now_iso

RetestStatus = Literal["reproduces", "fixed", "unconfirmable"]
Transition = Literal[
    "regressed",  # was fixed/absent before, reproduces now
    "newly_fixed",  # was reproducing before, fixed now
    "still_broken",  # reproduced before and still does
    "still_fixed",  # fixed before and still is
    "unchanged",  # same status, nothing notable
    "new",  # not seen in the prior retest
]

# A function with reverify()'s shape; injectable so the tracker is testable
# without a live target or the go engine.
ReverifyFn = Callable[..., dict]


class RetestEntry(BaseModel):
    url: str
    finding_id: str
    status: RetestStatus
    reason: str = ""
    transition: Transition | None = None
    prior_status: RetestStatus | None = None


class RetestReport(BaseModel):
    target: str = ""
    checked_at: str = Field(default_factory=now_iso)
    entries: list[RetestEntry] = Field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        out = {"reproduces": 0, "fixed": 0, "unconfirmable": 0}
        for e in self.entries:
            out[e.status] += 1
        return out

    @property
    def regressions(self) -> list[RetestEntry]:
        return [e for e in self.entries if e.transition == "regressed"]


def classify_reverify(result: dict) -> tuple[RetestStatus, str]:
    """Map a :func:`shroodler.reverify.reverify` result to a tracked status.

    ``fixed`` is asserted only on a *trustworthy* clean re-scan: no warnings
    (reverify warns when it could not re-fuzz the original parameter) and no
    error. Anything that is neither clearly reproducing nor cleanly fixed is
    ``unconfirmable`` -- the re-scan's silence is not treated as a fix.
    """
    if result.get("error"):
        return "unconfirmable", f"re-scan error: {result['error']}"
    if result.get("still_present"):
        return "reproduces", "finding still present on re-scan"
    warnings = result.get("warnings") or []
    if warnings:
        return "unconfirmable", str(warnings[0])
    guardrail = result.get("guardrail")
    if guardrail:
        # A guardrail that gated the payload run means nothing was tested, so a
        # verified_fixed here would be "found nothing because it ran nothing".
        return "unconfirmable", f"payload run gated by guardrail: {guardrail}"
    if result.get("verified_fixed"):
        return "fixed", "not present on a trustworthy re-scan"
    return "unconfirmable", "re-scan was indeterminate"


def _transition(prior: RetestStatus | None, now: RetestStatus) -> Transition:
    if prior is None:
        return "new"
    if prior == "reproduces" and now == "reproduces":
        return "still_broken"
    if prior == "fixed" and now == "fixed":
        return "still_fixed"
    if now == "reproduces" and prior in ("fixed", "unconfirmable"):
        # A finding that was fixed (or last could not be confirmed) and is
        # exploitable again is a regression worth surfacing loudly.
        return "regressed" if prior == "fixed" else "unchanged"
    if now == "fixed" and prior == "reproduces":
        return "newly_fixed"
    return "unchanged"


def targets_from_doc(doc: dict, *, confirmed_only: bool = True) -> list[tuple[str, str]]:
    """Extract ``(url, finding_id)`` pairs to retest from a scan document.

    Defaults to confirmed findings -- the ones worth re-checking; passing
    ``confirmed_only=False`` retests every finding. Deduplicated, order-stable.
    """
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for f in doc.get("findings") or []:
        if confirmed_only and str(f.get("confidence") or "").lower() != "confirmed":
            continue
        url = str(f.get("url") or "")
        fid = str(f.get("id") or "")
        if not url or not fid:
            continue
        key = (url, fid)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _prior_index(prior: RetestReport | None) -> dict[tuple[str, str], RetestStatus]:
    if prior is None:
        return {}
    return {(e.url, e.finding_id): e.status for e in prior.entries}


def retest_findings(
    targets: Iterable[tuple[str, str]],
    *,
    target_name: str = "",
    reverify_fn: ReverifyFn | None = None,
    prior: RetestReport | None = None,
    reverify_kwargs: dict[str, Any] | None = None,
) -> RetestReport:
    """Re-check each ``(url, finding_id)`` and return a tracked report.

    ``reverify_fn`` defaults to :func:`shroodler.reverify.reverify`; inject a
    stub to test without a live target. A re-check that raises is recorded as
    ``unconfirmable`` (never aborts the run). ``prior`` supplies the previous
    report so each entry gets a transition and regressions are flagged.
    """
    if reverify_fn is None:
        from shroodler.reverify import reverify as reverify_fn  # noqa: PLW0127
    kwargs = dict(reverify_kwargs or {})
    prior_status = _prior_index(prior)

    entries: list[RetestEntry] = []
    for url, finding_id in targets:
        try:
            result = reverify_fn(url, finding_id, **kwargs)
        except Exception as exc:  # noqa: BLE001 - one bad re-check must not abort
            result = {"error": str(exc) or exc.__class__.__name__}
        status, reason = classify_reverify(result)
        was = prior_status.get((url, finding_id))
        entries.append(
            RetestEntry(
                url=url,
                finding_id=finding_id,
                status=status,
                reason=reason,
                transition=_transition(was, status),
                prior_status=was,
            )
        )
    return RetestReport(target=target_name, entries=entries)


def save_report(report: RetestReport, path: str | Path) -> None:
    """Append a retest report as one JSON line of an over-time history file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(report.model_dump_json() + "\n")


def load_history(path: str | Path) -> list[RetestReport]:
    """Load all retest reports from a history file, oldest first. Missing/empty
    file yields an empty list; a malformed line is skipped, not fatal."""
    p = Path(path)
    if not p.exists():
        return []
    out: list[RetestReport] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(RetestReport.model_validate_json(line))
        except Exception:  # noqa: BLE001 - a bad history line is not fatal
            continue
    return out


def latest_report(path: str | Path) -> RetestReport | None:
    """The most recent retest report in a history file, or None."""
    history = load_history(path)
    return history[-1] if history else None
