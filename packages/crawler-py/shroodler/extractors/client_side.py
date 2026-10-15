"""Client-side (DOM) weaknesses mined statically from HTML/JS.

A human reads the JS; this does a best-effort static pass for the most common
DOM issue a scanner otherwise misses: a ``message`` event listener that never
validates ``event.origin``, so any page can postMessage into it (cross-origin
message injection, often a DOM-XSS or state-tampering primitive).

Heuristic (regex, not a full AST): if a file registers a message listener but
references ``.origin`` nowhere, the handler almost certainly does not validate
the sender. One finding per URL.
"""

from __future__ import annotations

import re

from shroodler.models import Finding

_MESSAGE_LISTENER = re.compile(r"addEventListener\s*\(\s*['\"]message['\"]", re.I)
_ONMESSAGE = re.compile(r"\bonmessage\s*=", re.I)
_ORIGIN_CHECK = re.compile(r"\.origin\b", re.I)


def extract_client_side(text: str, url: str) -> list[Finding]:
    if not text:
        return []
    has_listener = bool(_MESSAGE_LISTENER.search(text) or _ONMESSAGE.search(text))
    if not has_listener:
        return []
    if _ORIGIN_CHECK.search(text):
        return []  # some origin check is present; not obviously missing
    return [
        Finding(
            id="postmessage-no-origin-check",
            severity="medium",  # type: ignore[arg-type]
            category="payload",
            url=url,
            description=(
                "A window 'message' event listener was registered but the code "
                "never checks event.origin, so any origin can postMessage into "
                "this handler (cross-origin message injection; often a DOM-XSS or "
                "state-tampering primitive)."
            ),
            evidence="message listener present; no event.origin validation found in the script",
            confidence="heuristic",  # type: ignore[arg-type]
        )
    ]
