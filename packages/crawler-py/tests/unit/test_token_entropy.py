from __future__ import annotations

import json

import pytest

from shroodler.cli import main as cli_main
from shroodler.token_entropy import _pooled_keyspace_bits, analyze_tokens


def _session(url: str) -> dict:
    return {"request": {"method": "GET", "url": url}}


def _ids(findings) -> set[str]:
    return {f.id for f in findings}


# --- reset-token-in-url: always-true baseline signal --------------------


def test_any_recognized_token_always_gets_the_in_url_finding():
    findings = analyze_tokens([_session("https://x.example/reset?token=k3Jd8fQz1mWpXv92Tn7L")])
    assert "reset-token-in-url" in _ids(findings)


# --- sequential detection: relative span, 3+ samples, strict int format -


def test_tightly_incrementing_tokens_are_flagged_sequential():
    sessions = [
        _session("https://x.example/reset?token=100001"),
        _session("https://x.example/reset?token=100002"),
        _session("https://x.example/reset?token=100003"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-sequential" in _ids(findings)
    hit = next(f for f in findings if f.id == "reset-token-sequential")
    assert hit.severity == "high"
    assert "confirm" in hit.description.lower()


def test_big_jump_shared_auto_increment_is_still_flagged_sequential():
    # Regression test: an earlier absolute-span check missed a
    # shared/tenant-wide auto-increment column that jumps by hundreds of
    # thousands between resets -- the RELATIVE span is still tiny.
    sessions = [
        _session("https://x.example/reset?token=1000348211"),
        _session("https://x.example/reset?token=1000601994"),
        _session("https://x.example/reset?token=1000922870"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-sequential" in _ids(findings)


def test_epoch_millisecond_tokens_are_flagged_sequential():
    sessions = [
        _session("https://x.example/reset?token=1757000000123"),
        _session("https://x.example/reset?token=1757000180456"),
        _session("https://x.example/reset?token=1757000431789"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-sequential" in _ids(findings)


def test_two_samples_alone_never_trigger_sequential():
    # Only 2 distinct points is too easily fooled either way -- requires
    # 3+ before making a sequential claim at all.
    sessions = [
        _session("https://x.example/reset?token=100001"),
        _session("https://x.example/reset?token=100002"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-sequential" not in _ids(findings)


def test_random_looking_six_digit_otps_are_not_flagged_sequential():
    sessions = [
        _session("https://x.example/otp?token=439563"),
        _session("https://x.example/otp?token=258176"),
        _session("https://x.example/otp?token=514002"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-sequential" not in _ids(findings)


def test_underscore_signed_and_unicode_digit_strings_are_not_treated_as_plain_ints():
    # int() is far more permissive than a plain base-10 literal: PEP 515
    # underscores, leading +, and Unicode digits all parse but must not
    # be treated as "clean sequential integers".
    sessions = [
        _session("https://x.example/reset?token=1_000_001"),
        _session("https://x.example/reset?token=1_000_002"),
        _session("https://x.example/reset?token=1_000_003"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-sequential" not in _ids(findings)


# --- keyspace check: pooled length x observed alphabet, not per-string --
# --- Shannon entropy (which false-positived on short-but-correct OTPs) --


def test_six_digit_otps_are_flagged_small_keyspace_not_sequential():
    sessions = [
        _session("https://x.example/otp?token=439563"),
        _session("https://x.example/otp?token=258176"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-small-keyspace" in _ids(findings)
    assert "reset-token-sequential" not in _ids(findings)
    hit = next(f for f in findings if f.id == "reset-token-small-keyspace")
    assert hit.severity == "medium"
    assert "rate limit" in hit.description.lower()


def test_long_high_alphabet_tokens_are_not_flagged_small_keyspace():
    sessions = [
        _session("https://x.example/reset?token=k3Jd8fQz1mWpXv92Tn7L"),
        _session("https://x.example/reset?token=b7Qm2Yx0Hs5RfKp3Ldz8"),
        _session("https://x.example/reset?token=Vc9Nt1Zw6Xj4GhLq0RmB"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-small-keyspace" not in _ids(findings)
    assert "reset-token-sequential" not in _ids(findings)


def test_structured_timestamp_prefixed_tokens_are_flagged_after_affix_stripping():
    # Regression test: a constant prefix plus a wall-clock timestamp has
    # high per-string Shannon entropy from the varying digits, but is
    # trivially predictable -- stripping the common "reset-" prefix
    # before analysis exposes the real (small, clustered) varying part.
    sessions = [
        _session("https://x.example/reset?token=reset-1757000000"),
        _session("https://x.example/reset?token=reset-1757000431"),
        _session("https://x.example/reset?token=reset-1757001902"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-sequential" in _ids(findings)


# --- endpoint grouping: id-shaped path segments only, never plain words -


def test_two_different_reset_flows_do_not_merge_into_one_group():
    # Regression test: an earlier id-shaped-segment regex matched any
    # 8+-char alphanumeric segment, including plain path WORDS like
    # "passwordreset"/"verifyemail" -- merging two different endpoints
    # with different generators into one (falsely) sequential-looking
    # group. Pure-alphabetic segments must never be templated.
    sessions = [
        _session("https://x.example/account/passwordreset?token=100001"),
        _session("https://x.example/account/verifyemail?token=100999"),
        _session("https://x.example/account/otherpage?token=100500"),
    ]
    findings = analyze_tokens(sessions)
    # Each landed in its own single-sample group (different literal
    # paths, correctly NOT templated together), so none has 2+ samples.
    assert "reset-token-sequential" not in _ids(findings)
    assert "reset-token-small-keyspace" not in _ids(findings)


def test_path_with_varying_request_id_segment_still_groups_together():
    # A common real API shape: /reset/<request-id>/confirm?token=... --
    # the request id differs every time even though it's conceptually
    # the same endpoint. An id-shaped (UUID) segment IS templated, so
    # this correctly still groups as one endpoint across samples.
    sessions = [
        _session(
            "https://x.example/reset/11111111-1111-1111-1111-111111111111/confirm?token=100001"
        ),
        _session(
            "https://x.example/reset/22222222-2222-2222-2222-222222222222/confirm?token=100002"
        ),
        _session(
            "https://x.example/reset/33333333-3333-3333-3333-333333333333/confirm?token=100003"
        ),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-sequential" in _ids(findings)


# --- path-segment tokens (Django/Laravel-style) --------------------------


def test_django_style_path_segment_token_is_detected():
    sessions = [
        _session("https://x.example/reset/MQ/aaaaaaaaaaaa1/"),
        _session("https://x.example/reset/Mg/aaaaaaaaaaaa2/"),
        _session("https://x.example/reset/Mw/aaaaaaaaaaaa3/"),
    ]
    findings = analyze_tokens(sessions)
    assert any(f.id == "reset-token-in-url" for f in findings)


def test_non_reset_flow_path_does_not_extract_path_segments():
    sessions = [_session("https://x.example/orders/1000000000000001/")]
    findings = analyze_tokens(sessions)
    assert findings == []


# --- widened param-name coverage ------------------------------------------


def test_devise_style_reset_password_token_is_recognized():
    findings = analyze_tokens(
        [_session("https://x.example/users/password?reset_password_token=k3Jd8fQz1mWpXv92")]
    )
    assert "reset-token-in-url" in _ids(findings)


def test_wordpress_style_key_param_is_recognized():
    findings = analyze_tokens(
        [_session("https://x.example/wp-login.php?action=rp&key=k3Jd8fQz1mWpXv92")]
    )
    assert "reset-token-in-url" in _ids(findings)


def test_generic_code_param_is_recognized():
    findings = analyze_tokens([_session("https://x.example/verify?code=k3Jd8fQz1mWpXv92")])
    assert "reset-token-in-url" in _ids(findings)


def test_hyphenated_param_name_is_recognized():
    sessions = [
        _session("https://x.example/reset?reset-token=100001"),
        _session("https://x.example/reset?reset-token=100002"),
        _session("https://x.example/reset?reset-token=100003"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-sequential" in _ids(findings)


# --- duplicate/session-replay inflation -----------------------------------


def test_duplicate_identical_value_is_not_treated_as_multiple_samples():
    # A proxy recording naturally captures retries/redirect chains, or a
    # tester revisiting the same emailed link twice -- the same literal
    # value observed 3 times is one real data point, not three, and must
    # not trip the sequential check via a trivial span of 0.
    sessions = [
        _session("https://x.example/reset?token=k3Jd8fQz1mWpXv92Tn7L"),
        _session("https://x.example/reset?token=k3Jd8fQz1mWpXv92Tn7L"),
        _session("https://x.example/reset?token=k3Jd8fQz1mWpXv92Tn7L"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-sequential" not in _ids(findings)
    assert "reset-token-small-keyspace" not in _ids(findings)
    assert _ids(findings) == {"reset-token-in-url"}


def test_duplicate_short_value_falls_back_to_single_sample_check():
    sessions = [
        _session("https://x.example/reset?token=abc123"),
        _session("https://x.example/reset?token=abc123"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-short" in _ids(findings)


# --- single-sample path ----------------------------------------------------


def test_single_short_sample_is_flagged_low_severity():
    findings = analyze_tokens([_session("https://x.example/reset?token=abc123")])
    hit = next(f for f in findings if f.id == "reset-token-short")
    assert hit.severity == "low"
    assert "one distinct" in hit.description.lower()


def test_single_long_high_entropy_sample_is_not_flagged_short():
    findings = analyze_tokens(
        [_session("https://x.example/reset?token=k3Jd8fQz1mWpXv92Tn7Lq5RcYb0Hs")]
    )
    assert "reset-token-short" not in _ids(findings)


# --- evidence redaction ----------------------------------------------------


def test_evidence_never_contains_a_raw_live_token_value():
    live_token = "k3Jd8fQz1mWpXv92Tn7L"
    findings = analyze_tokens([_session(f"https://x.example/reset?token={live_token}")])
    for f in findings:
        assert live_token not in (f.evidence or "")


# --- irrelevant params/values are ignored ----------------------------------


def test_non_token_param_names_are_ignored():
    findings = analyze_tokens(
        [
            _session("https://x.example/search?q=100001"),
            _session("https://x.example/search?q=100002"),
        ]
    )
    assert findings == []


def test_short_values_below_minimum_length_are_ignored():
    findings = analyze_tokens([_session("https://x.example/reset?token=abc")])
    assert findings == []


def test_non_get_or_malformed_sessions_are_skipped():
    assert analyze_tokens([{"request": {}}]) == []
    assert analyze_tokens([{}]) == []
    opts_session = {"request": {"method": "OPTIONS", "url": "https://x/?token=abcdef"}}
    assert analyze_tokens([opts_session]) == []


# --- keyspace helper --------------------------------------------------------


def test_pooled_keyspace_bits_of_six_digit_otp_is_small():
    assert _pooled_keyspace_bits(["439563", "258176"]) < 64.0


def test_pooled_keyspace_bits_of_long_varied_token_is_large():
    assert _pooled_keyspace_bits(["k3Jd8fQz1mWpXv92Tn7L", "b7Qm2Yx0Hs5RfKp3Ldz8"]) >= 64.0


# --- CLI wiring --------------------------------------------------------------


def test_cli_tokens_command(tmp_path):
    sessions = [
        _session("https://x.example/reset?token=100001"),
        _session("https://x.example/reset?token=100002"),
        _session("https://x.example/reset?token=100003"),
    ]
    p = tmp_path / "s.jsonl"
    p.write_text("".join(json.dumps(s) + "\n" for s in sessions), encoding="utf-8")
    out = tmp_path / "out.json"
    with pytest.raises(SystemExit) as ex:
        cli_main(["tokens", str(p), "-o", str(out)])
    assert ex.value.code == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert any(f["id"] == "reset-token-sequential" for f in doc["findings"])
