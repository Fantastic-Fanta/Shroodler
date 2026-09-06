"""Cost-of-attack classification, keyed by finding id with a category
fallback -- mirrors remediation.py's shape and reasoning for the same
practical reason: new payload/secret pack ids are added far more often
than a lookup table gets updated, so unclassified ids fall back to a
sane category default rather than silently having no value at all.

This is a cross-cutting axis alongside severity, not a replacement for
it: "cost_of_attack: none" (no account needed) doesn't make a finding
more or less severe, it tells a triager how *cheap* it is for an
attacker to actually pull off. A critical SQLi reachable by anyone with
network access (cost: none) and a critical privilege-escalation bug that
first requires a compromised low-priv account (cost: medium) deserve
different urgency even at the same severity.

Tiers, cheapest to most expensive for the attacker:
- "none":   works against an anonymous, unauthenticated attacker.
- "low":    needs a guessable/low-entropy secret or token (this scan's
            own token-entropy checks already flag which tokens qualify),
            not a real account.
- "medium": needs a valid (even low-privilege) authenticated session.
- "high":   needs privileged/admin access, or a high-entropy secret that
            isn't itself the finding (i.e. exploiting it presupposes
            already having compromised something else non-trivial).
"""

from __future__ import annotations

# Exact finding-id classification. Checked first; falls back to
# _BY_CATEGORY below.
_BY_ID: dict[str, str] = {
    # Low-entropy/guessable tokens ARE the cheap attack primitive here --
    # exploiting them costs only the effort of guessing/brute-forcing the
    # token itself, not owning an account.
    "reset-token-sequential": "low",
    "reset-token-small-keyspace": "low",
    "reset-token-short": "low",
    "reset-token-in-url": "low",
    "oauth-missing-state": "low",
    # Forging a token with a known-weak/absent signature needs no prior
    # session -- once the weakness is known, any anonymous attacker can
    # mint a token.
    "jwt-alg-none": "none",
    "jwt-weak-secret": "none",
    # Broken access control / IDOR / session-hygiene findings all
    # presuppose the attacker already holds *some* authenticated session
    # (that's exactly what authz-diff's two-session replay requires) --
    # a real, if low-privileged, account, not just a guessed token.
    "authz-still-accessible": "medium",
    "authz-broken-access-control": "medium",
    "idor-adjacent-id-accessible": "medium",
    "session-fixation": "medium",
    "logout-not-invalidated": "medium",
    "oauth-implicit-flow": "medium",
}

# Category fallback for ids not listed above.
_BY_CATEGORY: dict[str, str] = {
    "header": "none",
    "cookie": "none",
    "secret": "none",
    "exposed-file": "none",
    "js-endpoint": "none",
    "verbose-error": "none",
    "autocomplete": "none",
    "payload": "none",
    "auth": "medium",
}

_DEFAULT = "none"


def cost_of_attack_for(finding_id: str, category: str = "") -> str:
    if finding_id in _BY_ID:
        return _BY_ID[finding_id]
    if category in _BY_CATEGORY:
        return _BY_CATEGORY[category]
    return _DEFAULT
