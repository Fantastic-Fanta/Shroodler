from __future__ import annotations

from datetime import timedelta

from shroodler.pacer import Pacer
from shroodler.probes.race_condition import probe_race_condition


class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.elapsed = timedelta(seconds=0.0)
        self.headers = {}


_PARAMS = [{"name": "coupon", "value": "SAVE10"}]


def _scripted_fire(responses):
    """Return a fire() that yields the given responses in order, then repeats
    the last one for the concurrent burst."""
    seq = list(responses)
    state = {"i": 0}

    def fire():
        i = state["i"]
        state["i"] += 1
        return seq[i] if i < len(seq) else seq[-1]

    return fire


def test_race_detected_when_sequential_rejects_but_burst_succeeds():
    # r1 success, r2 rejected (409) -> single-use enforced; burst all succeed.
    fire = _scripted_fire([FakeResp(200, "redeemed"), FakeResp(409, "already used")]
                          + [FakeResp(200, "redeemed")] * 8)
    findings = probe_race_condition(
        "http://t/redeem", "POST", _PARAMS, "", pacer=Pacer(0), concurrency=8, fire=fire
    )
    hit = next(f for f in findings if f.id == "race-condition")
    assert hit.severity == "medium"
    assert hit.confidence == "heuristic"


def test_no_finding_when_endpoint_is_idempotent():
    # Both sequential requests succeed -> not single-use -> bail, no burst.
    fire = _scripted_fire([FakeResp(200, "ok"), FakeResp(200, "ok")])
    findings = probe_race_condition(
        "http://t/redeem", "POST", _PARAMS, "", pacer=Pacer(0), fire=fire
    )
    assert findings == []


def test_no_finding_when_burst_also_rejects():
    # Single-use enforced AND the burst holds (no race): only 1 success.
    fire = _scripted_fire(
        [FakeResp(200, "redeemed"), FakeResp(409, "already used")]
        + [FakeResp(409, "already used")] * 8
    )
    findings = probe_race_condition(
        "http://t/redeem", "POST", _PARAMS, "", pacer=Pacer(0), concurrency=8, fire=fire
    )
    assert findings == []


def test_marker_based_rejection():
    # Second response is 200 but says "limit exceeded" -> treated as rejection.
    fire = _scripted_fire(
        [FakeResp(200, "transferred"), FakeResp(200, "daily limit exceeded")]
        + [FakeResp(200, "transferred")] * 6
    )
    findings = probe_race_condition(
        "http://t/transfer", "POST", _PARAMS, "", pacer=Pacer(0), concurrency=6, fire=fire
    )
    assert any(f.id == "race-condition" for f in findings)


def test_get_method_skips():
    fire = _scripted_fire([FakeResp(200), FakeResp(409)])
    findings = probe_race_condition(
        "http://t/x", "GET", _PARAMS, "", pacer=Pacer(0), fire=fire
    )
    assert findings == []
