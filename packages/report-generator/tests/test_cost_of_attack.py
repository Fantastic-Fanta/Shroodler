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
    assert cost_of_attack_for("some-brand-new-auth-id", "auth") == "medium"


def test_unknown_id_and_category_falls_back_to_default():
    assert cost_of_attack_for("totally-unknown", "totally-unknown") == "none"
