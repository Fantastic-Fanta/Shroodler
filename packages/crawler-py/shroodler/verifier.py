"""Adversarial verifier: argue the false-positive case against a finding.

A scanner's job is to find things; a senior triager's job is to try to break the
finding before anyone trusts it. This module is that second role. For each
finding it builds the strongest case that the finding is a *false positive* --
the pushback a human reviewer would give -- and grades how well the finding
survives it. A finding that cannot be refuted from its own evidence is one worth
reporting; one that is only an assertion gets flagged, not silently trusted.

Precision is the north star: a tool that cries wolf does not replace a human, so
the verifier is deliberately skeptical and never upgrades a finding on its own
say-so. It only strengthens a finding when the *evidence* is strong -- above all
an evidence-bound ``Proof`` (see :mod:`shroodler.evidence`), which is captured,
verbatim-checked traffic and so is the hardest thing to argue away.

The core here is deterministic and offline: it reasons from the finding's own
fields (id, category, severity, confidence, evidence text, proof/verified). An
optional model-driven debate layer can be layered on top later; the deterministic
verdict is the source of truth so every rule is testable without a network.

This is Shroodler's own code (Apache-2.0); the idea of an adversarial verifier
that debates findings is reimplemented clean, not copied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
# Signals in evidence text that a response was a WAF / bot interstitial rather
# than the application itself, so the probe may have tested the WAF, not the app.
_WAF_HINTS = (
    "waf",
    "cloudflare",
    "akamai",
    "perimeterx",
    "datadome",
    "captcha",
    "attention required",
    "bot detection",
    "challenge",
)
# Signals that a reflection actually executed (vs merely echoed into the page).
_EXEC_HINTS = ("executed", "alert(", "fired", "ran in", "window.", "sentinel")

Strength = str  # "proven" | "solid" | "weak" | "refuted"


def _get(finding: Any, key: str, default: Any = "") -> Any:
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


def _has_proof(finding: Any) -> bool:
    proof = _get(finding, "proof", None)
    if isinstance(proof, dict):
        return bool(proof.get("url")) and bool(proof.get("quotes"))
    return bool(proof)


def _lower_severity(severity: str) -> str:
    try:
        i = _SEVERITY_ORDER.index(str(severity or "info").lower())
    except ValueError:
        return "info"
    return _SEVERITY_ORDER[max(0, i - 1)]


@dataclass
class Verdict:
    """The result of arguing the false-positive case against one finding."""

    finding_id: str
    url: str
    stands: bool
    strength: Strength
    suggested_severity: str
    counterarguments: list[str] = field(default_factory=list)
    reason: str = ""


def verify_finding(finding: Any) -> Verdict:
    """Argue the FP case against one finding and grade how well it survives.

    Deterministic and side-effect free; never raises. ``stands`` is False only
    when the finding is not a vulnerability at all or is refuted outright;
    otherwise it stands but may be flagged ``weak`` with the counterarguments a
    reviewer should see. An evidence-bound finding is graded ``proven`` and is
    the hardest to argue away.
    """
    fid = str(_get(finding, "id", "") or "")
    url = str(_get(finding, "url", "") or "")
    category = str(_get(finding, "category", "") or "").lower()
    severity = str(_get(finding, "severity", "info") or "info").lower()
    confidence = str(_get(finding, "confidence", "") or "").lower()
    verified = bool(_get(finding, "verified", False))
    evidence = str(_get(finding, "evidence", "") or "").lower()

    args: list[str] = []
    suggested = severity

    # A scan-note is an explicit coverage marker, never a vulnerability.
    if category == "scan-note":
        return Verdict(
            finding_id=fid,
            url=url,
            stands=False,
            strength="refuted",
            suggested_severity="info",
            counterarguments=["scan-note is a coverage marker, not a vulnerability"],
            reason="scan-note",
        )

    # A response that looks like a WAF/bot interstitial means the probe may have
    # hit the WAF, not the application -- the strongest single counterargument.
    waf = category == "waf-challenge" or any(h in evidence for h in _WAF_HINTS)
    if waf:
        args.append(
            "response resembles a WAF/bot-mitigation interstitial, so the probe "
            "may have tested the WAF rather than the application"
        )

    # Evidence-bound findings are the hard-to-refute ones: a Proof is captured,
    # verbatim-checked traffic. They stand as proven unless the WAF caveat bites.
    if verified and _has_proof(finding):
        strength: Strength = "weak" if waf else "proven"
        if not waf:
            reason = "evidence-bound: proof carries verbatim traffic that demonstrates it"
        else:
            reason = "evidence-bound but captured behind a possible WAF interstitial"
        return Verdict(
            finding_id=fid,
            url=url,
            stands=True,
            strength=strength,
            suggested_severity=suggested,
            counterarguments=args,
            reason=reason,
        )

    # Not evidence-bound: grade by how it was established, and raise the specific
    # pushback a reviewer would give for this class.
    if confidence == "confirmed":
        args.append("confirmed by signal match but not evidence-bound (no captured proof)")
        strength = "solid"
    elif confidence == "probable":
        args.append("established by a blind/timing signal, which can be coincidental")
        strength = "solid"
    elif confidence == "heuristic":
        args.append("passive heuristic (e.g. a missing header), not a demonstrated exploit")
        strength = "weak"
    else:
        args.append("no confidence recorded; establishment method is unclear")
        strength = "weak"

    # Reflected-injection class: reflection is not execution.
    if "xss" in fid or "reflect" in evidence:
        if not any(h in evidence for h in _EXEC_HINTS) and not verified:
            args.append(
                "payload is reflected but not shown to execute; it may be "
                "sanitized or encoded on render"
            )
            strength = "weak"

    # A high/critical severity resting on a weak basis is overstated.
    if strength == "weak" and severity in ("high", "critical"):
        suggested = _lower_severity(severity)
        args.append(
            f"severity {severity} is not supported by the evidence; "
            f"suggest {suggested}"
        )

    if waf:
        strength = "weak"

    return Verdict(
        finding_id=fid,
        url=url,
        stands=True,
        strength=strength,
        suggested_severity=suggested,
        counterarguments=args,
        reason=f"not evidence-bound; graded {strength}",
    )


def verify_findings(findings: list[Any]) -> list[Verdict]:
    """Verify a batch of findings. Never raises; a bad item is skipped."""
    out: list[Verdict] = []
    for f in findings or []:
        try:
            out.append(verify_finding(f))
        except Exception:  # noqa: BLE001 - one bad finding must not abort the batch
            continue
    return out


def verdict_as_dict(v: Verdict) -> dict:
    return {
        "finding_id": v.finding_id,
        "url": v.url,
        "stands": v.stands,
        "strength": v.strength,
        "suggested_severity": v.suggested_severity,
        "counterarguments": list(v.counterarguments),
        "reason": v.reason,
    }
