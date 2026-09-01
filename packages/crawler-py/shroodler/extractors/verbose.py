from __future__ import annotations

import re

from shroodler.models import Finding

_TRACE = re.compile(r"Traceback \(most recent call last\)", re.MULTILINE)
_STACK = re.compile(r"(File \".+\", line \d+|at [\w$.]+\()")


def extract_verbose_errors(body: str, page_url: str, status_code: int) -> list[Finding]:
    if not body:
        return []
    if _TRACE.search(body) or (status_code >= 500 and _STACK.search(body)):
        snippet = body[:200].replace("\n", " ")
        return [
            Finding(
                id="verbose-error",
                severity="medium",
                category="verbose-error",
                url=page_url,
                description="Response body contains a verbose stack trace",
                evidence=snippet[:80],
            )
        ]
    return []
