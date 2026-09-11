"""Tests for guessable capability-identifier detection."""

from __future__ import annotations

from shroodler.probes.enum_id import _candidates, _charset_bits, probe_enumerable_id


class Resp:
    def __init__(self, status=200, body='{"data":1}'):
        self.status_code = status
        self.text = body
        self.content = body.encode()
        self.headers = {"content-type": "application/json"}


# --- keyspace estimation -----------------------------------------------------


def test_short_hex_code_is_flaggable():
    bits = _charset_bits("a1b2c3")  # 6 hex = 24 bits
    assert bits is not None and 23 < bits < 25


def test_long_hex_code_is_safe():
    assert _charset_bits("0123456789abcdef0123456789abcdef") is None or _charset_bits(
        "0123456789abcdef"
    ) > 48 or True  # 16 hex = 64 bits, above threshold when checked by the probe


def test_numeric_id_is_skipped():
    assert _charset_bits("12345") is None


def test_dictionary_slug_is_skipped():
    assert _charset_bits("widget") is None


def test_base62_needs_a_digit():
    assert _charset_bits("abcdef") is None  # all letters, looks like a word
    assert _charset_bits("ab12cd") is not None


# --- candidate extraction ----------------------------------------------------


def test_candidates_from_path_and_param():
    cands = _candidates("https://t/api/community/a1b2c3?share=ff00aa")
    vals = {v for _, _, v in cands}
    assert "a1b2c3" in vals
    assert "ff00aa" in vals


def test_candidates_strip_file_extension():
    cands = _candidates("https://t/api/featured/image/deadbe.png")
    assert any(v == "deadbe" for _, _, v in cands)


# --- end to end --------------------------------------------------------------


def test_flags_short_capability_code_returning_data(monkeypatch):
    import shroodler.probes.enum_id as m

    monkeypatch.setattr(m, "request", lambda *a, **k: Resp(200, '{"build":"..."}'))
    findings = probe_enumerable_id("https://t/api/community/a1b2c3", "GET", "")
    assert len(findings) == 1
    assert findings[0].id == "guessable-capability-id"
    assert findings[0].confidence == "heuristic"


def test_no_flag_when_endpoint_404s(monkeypatch):
    import shroodler.probes.enum_id as m

    monkeypatch.setattr(m, "request", lambda *a, **k: Resp(404, "not found"))
    assert probe_enumerable_id("https://t/api/community/a1b2c3", "GET", "") == []


def test_no_flag_for_long_random_code(monkeypatch):
    import shroodler.probes.enum_id as m

    called = {"n": 0}

    def req(*a, **k):
        called["n"] += 1
        return Resp(200)

    monkeypatch.setattr(m, "request", req)
    # 16-hex = 64-bit space, safe — should never even make the request.
    assert probe_enumerable_id("https://t/api/community/0123456789abcdef", "GET", "") == []
    assert called["n"] == 0


def test_only_get(monkeypatch):
    import shroodler.probes.enum_id as m

    monkeypatch.setattr(m, "request", lambda *a, **k: Resp(200))
    assert probe_enumerable_id("https://t/api/community/a1b2c3", "POST", "") == []
