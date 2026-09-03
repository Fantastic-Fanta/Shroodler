from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from shroodler.extractors.secrets import scan_text


@given(st.binary(max_size=4096))
@settings(max_examples=2000, deadline=None)
def test_scanner_never_crashes_on_random_bytes(data: bytes):
    text = data.decode("utf-8", errors="replace")
    findings = scan_text(text, "http://127.0.0.1/fuzz")
    assert isinstance(findings, list)


@given(st.binary(min_size=64, max_size=256))
@settings(max_examples=400, deadline=None)
def test_false_positive_rate_on_random_bytes_is_bounded(data: bytes):
    text = data.decode("latin-1", errors="replace")
    findings = scan_text(text, "http://127.0.0.1/fuzz")
    # Allow entropy heuristic some room; regex secrets should be rare on random bytes.
    regex_hits = [f for f in findings if f.id != "generic-api-key"]
    assert len(regex_hits) <= 2
