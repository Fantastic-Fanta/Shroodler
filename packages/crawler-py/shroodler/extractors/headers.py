from __future__ import annotations

import re

from shroodler.models import Finding, HeaderAnalysis

TRACKED = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


_SCRIPT_WILDCARDS = {"*", "https:"}


def _header_map(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


def _parse_csp(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for raw in policy.split(";"):
        raw = raw.strip()
        if not raw:
            continue
        parts = raw.split()
        directives[parts[0].lower()] = [p.lower() for p in parts[1:]]
    return directives


def _script_src_tokens(directives: dict[str, list[str]]) -> list[str]:
    if "script-src" in directives:
        return directives["script-src"]
    return directives.get("default-src", [])


def extract_headers(headers: dict[str, str], page_url: str) -> tuple[HeaderAnalysis, list[Finding]]:
    lower = _header_map(headers)
    present: list[str] = []
    missing: list[str] = []
    findings: list[Finding] = []

    for name in TRACKED:
        if name.lower() in lower:
            present.append(name)
        else:
            missing.append(name)

    csp = lower.get("content-security-policy")
    report_only = lower.get("content-security-policy-report-only")
    has_xfo = "x-frame-options" in lower
    if csp is None:
        findings.append(
            Finding(
                id="missing-csp",
                severity="medium",
                category="header",
                url=page_url,
                description="Content-Security-Policy header not set",
                evidence=None,
            )
        )
    else:
        if "unsafe-inline" in csp.lower() or "unsafe-eval" in csp.lower():
            findings.append(
                Finding(
                    id="weak-csp",
                    severity="low",
                    category="header",
                    url=page_url,
                    description="Content-Security-Policy allows unsafe-inline or unsafe-eval",
                    evidence=csp[:120],
                )
            )
        directives = _parse_csp(csp)
        if any(tok in _SCRIPT_WILDCARDS for tok in _script_src_tokens(directives)):
            findings.append(
                Finding(
                    id="csp-wildcard-script",
                    severity="medium",
                    category="header",
                    url=page_url,
                    description=(
                        "Content-Security-Policy script-src or default-src "
                        "allows a host wildcard"
                    ),
                    evidence=csp[:120],
                )
            )
        if "frame-ancestors" not in directives and not has_xfo:
            findings.append(
                Finding(
                    id="csp-missing-frame-ancestors",
                    severity="medium",
                    category="header",
                    url=page_url,
                    description=(
                        "Content-Security-Policy has no frame-ancestors "
                        "and X-Frame-Options is not set"
                    ),
                    evidence=None,
                )
            )
    if report_only is not None and csp is None:
        findings.append(
            Finding(
                id="csp-report-only",
                severity="info",
                category="header",
                url=page_url,
                description=(
                    "Content-Security-Policy-Report-Only is set without "
                    "an enforcing Content-Security-Policy"
                ),
                evidence=report_only[:120],
            )
        )

    if "x-frame-options" not in lower:
        findings.append(
            Finding(
                id="missing-x-frame-options",
                severity="medium",
                category="header",
                url=page_url,
                description="X-Frame-Options header not set",
                evidence=None,
            )
        )

    hsts = lower.get("strict-transport-security")
    https = page_url.lower().startswith("https://")
    if hsts is None:
        if https:
            findings.append(
                Finding(
                    id="missing-hsts",
                    severity="medium",
                    category="header",
                    url=page_url,
                    description="Strict-Transport-Security header not set",
                    evidence=None,
                )
            )
    else:
        m = re.search(r"max-age\s*=\s*(\d+)", hsts, flags=re.IGNORECASE)
        max_age = int(m.group(1)) if m else 0
        if max_age < 15_552_000:
            findings.append(
                Finding(
                    id="short-hsts",
                    severity="low",
                    category="header",
                    url=page_url,
                    description="HSTS max-age is shorter than 180 days",
                    evidence=hsts,
                )
            )

    xcto = lower.get("x-content-type-options")
    if xcto is None:
        findings.append(
            Finding(
                id="missing-x-content-type-options",
                severity="low",
                category="header",
                url=page_url,
                description="X-Content-Type-Options header not set",
                evidence=None,
            )
        )
    elif xcto.lower() != "nosniff":
        findings.append(
            Finding(
                id="weak-x-content-type-options",
                severity="low",
                category="header",
                url=page_url,
                description="X-Content-Type-Options is not nosniff",
                evidence=xcto,
            )
        )

    if "referrer-policy" not in lower:
        findings.append(
            Finding(
                id="missing-referrer-policy",
                severity="info",
                category="header",
                url=page_url,
                description="Referrer-Policy header not set",
                evidence=None,
            )
        )

    server = lower.get("server")
    if server and re.search(r"\d", server):
        findings.append(
            Finding(
                id="server-version-leak",
                severity="info",
                category="header",
                url=page_url,
                description="Server header discloses a version",
                evidence=server,
            )
        )

    xpb = lower.get("x-powered-by")
    if xpb:
        findings.append(
            Finding(
                id="x-powered-by",
                severity="info",
                category="header",
                url=page_url,
                description="X-Powered-By header discloses the stack",
                evidence=xpb,
            )
        )

    return HeaderAnalysis(present=present, missing=missing), findings
