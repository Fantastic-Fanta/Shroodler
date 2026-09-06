from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cost_of_attack import cost_of_attack_for


def test_unauthenticated_header_finding_is_none():
    assert cost_of_attack_for("missing-hsts", "header") == "none"


def test_guessable_token_is_low():
    assert cost_of_attack_for("reset-token-sequential", "auth") == "low"


def test_jwt_forgery_needs_no_account():
    assert cost_of_attack_for("jwt-weak-secret", "auth") == "none"


def test_idor_needs_a_session():
    assert cost_of_attack_for("idor-adjacent-id-accessible", "auth") == "medium"


def test_unknown_id_falls_back_to_category():
    # "auth" defaults to "none", not "medium": most unenumerated auth-
    # category ids (rate limiting, pre-auth OAuth checks) are exploited
    # by an anonymous attacker, and overstating cost as "medium" would
    # understate urgency for a triager.
    assert cost_of_attack_for("some-brand-new-auth-id", "auth") == "none"


def test_unknown_id_and_category_falls_back_to_default():
    assert cost_of_attack_for("totally-unknown", "totally-unknown") == "none"


def test_missing_rate_limit_is_unauthenticated():
    assert cost_of_attack_for("missing-rate-limit", "auth") == "none"


def test_session_fixation_needs_no_account():
    assert cost_of_attack_for("session-fixation", "auth") == "none"


def test_logout_session_not_invalidated_needs_a_stolen_token_not_an_account():
    assert cost_of_attack_for("logout-session-not-invalidated", "auth") == "low"
