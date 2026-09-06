from __future__ import annotations

import json

import pytest

from shroodler.cli import main as cli_main
from shroodler.token_entropy import analyze_tokens, shannon_entropy_bits_per_char


def _session(url: str) -> dict:
    return {"request": {"method": "GET", "url": url}}


def _ids(findings) -> set[str]:
    return {f.id for f in findings}


def test_sequential_tokens_are_flagged_critical():
    sessions = [
        _session("https://x.example/reset?token=100001"),
        _session("https://x.example/reset?token=100002"),
        _session("https://x.example/reset?token=100003"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-sequential" in _ids(findings)
    hit = next(f for f in findings if f.id == "reset-token-sequential")
    assert hit.severity == "critical"
    assert hit.category == "secret"


def test_widely_scattered_numeric_tokens_are_not_sequential():
    # Numeric, but not clustered -- span is far larger than the sample
    # count would explain by an incrementing counter.
    sessions = [
        _session("https://x.example/reset?token=100001"),
        _session("https://x.example/reset?token=987654321"),
        _session("https://x.example/reset?token=555000111"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-sequential" not in _ids(findings)


def test_low_entropy_repeated_pattern_is_flagged():
    sessions = [
        _session("https://x.example/reset?token=aaaaaaaaaaaaaaaa"),
        _session("https://x.example/reset?token=aaaaaaaaaaaaaaab"),
        _session("https://x.example/reset?token=aaaaaaaaaaaaaaac"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-low-entropy" in _ids(findings)
    hit = next(f for f in findings if f.id == "reset-token-low-entropy")
    assert hit.severity == "medium"


def test_high_entropy_multi_sample_tokens_are_not_flagged():
    sessions = [
        _session("https://x.example/reset?token=k3Jd8fQz1mWpXv92Tn7L"),
        _session("https://x.example/reset?token=b7Qm2Yx0Hs5RfKp3Ldz8"),
        _session("https://x.example/reset?token=Vc9Nt1Zw6Xj4GhLq0RmB"),
    ]
    findings = analyze_tokens(sessions)
    assert findings == []


def test_single_short_sample_is_flagged_low_severity():
    findings = analyze_tokens([_session("https://x.example/reset?token=abc123")])
    assert "reset-token-short" in _ids(findings)
    hit = next(f for f in findings if f.id == "reset-token-short")
    assert hit.severity == "low"
    assert "one" in hit.description.lower()


def test_single_long_high_entropy_sample_is_not_flagged():
    findings = analyze_tokens(
        [_session("https://x.example/reset?token=k3Jd8fQz1mWpXv92Tn7Lq5RcYb0Hs")]
    )
    assert findings == []


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


def test_hyphenated_param_name_is_recognized():
    # Real APIs use both reset_token and reset-token conventions -- a
    # hyphenated name must not silently fall outside the curated list.
    sessions = [
        _session("https://x.example/reset?reset-token=100001"),
        _session("https://x.example/reset?reset-token=100002"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-sequential" in _ids(findings)


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
    # Falls back to the single-sample path since there's really only one
    # distinct value -- and this one is long/high-entropy, so no finding.
    assert findings == []


def test_duplicate_short_value_falls_back_to_single_sample_check():
    sessions = [
        _session("https://x.example/reset?token=abc123"),
        _session("https://x.example/reset?token=abc123"),
    ]
    findings = analyze_tokens(sessions)
    assert _ids(findings) == {"reset-token-short"}


def test_path_with_varying_request_id_segment_still_groups_together():
    # A common real API shape: /reset/<request-id>/confirm?token=... --
    # the request id differs every time even though it's conceptually
    # the same endpoint. Without path templating, every observation
    # would land in its own singleton group and this tool would never
    # run the multi-sample checks for such an endpoint at all.
    sessions = [
        _session("https://x.example/reset/11111111-1111-1111-1111-111111111111/confirm?token=100001"),
        _session("https://x.example/reset/22222222-2222-2222-2222-222222222222/confirm?token=100002"),
    ]
    findings = analyze_tokens(sessions)
    assert "reset-token-sequential" in _ids(findings)


def test_non_get_or_malformed_sessions_are_skipped():
    assert analyze_tokens([{"request": {}}]) == []
    assert analyze_tokens([{}]) == []


def test_shannon_entropy_of_empty_string_is_zero():
    assert shannon_entropy_bits_per_char("") == 0.0


def test_shannon_entropy_of_single_repeated_char_is_zero():
    assert shannon_entropy_bits_per_char("aaaaaaaa") == 0.0


def test_shannon_entropy_of_varied_chars_is_positive():
    assert shannon_entropy_bits_per_char("abcdefgh") > 2.5


def test_cli_tokens_command(tmp_path):
    sessions = [
        _session("https://x.example/reset?token=100001"),
        _session("https://x.example/reset?token=100002"),
    ]
    p = tmp_path / "s.jsonl"
    p.write_text("".join(json.dumps(s) + "\n" for s in sessions), encoding="utf-8")
    out = tmp_path / "out.json"
    with pytest.raises(SystemExit) as ex:
        cli_main(["tokens", str(p), "-o", str(out)])
    assert ex.value.code == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert any(f["id"] == "reset-token-sequential" for f in doc["findings"])
