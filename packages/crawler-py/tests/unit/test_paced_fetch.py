from __future__ import annotations

import pytest

from shroodler.paced_fetch import fetch_urls
from shroodler.pacer import Pacer


def test_refuses_write_methods():
    with pytest.raises(ValueError, match="GET/HEAD/OPTIONS"):
        fetch_urls(["http://127.0.0.1/"], method="POST")


def test_non_local_without_flag():
    out = fetch_urls(["https://example.com/"], pacer=Pacer(0))
    assert out["results"][0]["error"].startswith("non-local")


def test_fetches_and_records_status(fx):
    fx.on("GET", "/a", lambda inc: (200, {}, b"ok"))
    fx.on("GET", "/b", lambda inc: (404, {}, b"no"))
    slept: list[float] = []
    out = fetch_urls(
        [fx.origin + "/a", fx.origin + "/b"],
        pacer=Pacer(1.0, sleeper=slept.append, now=lambda: 0.0),
    )
    statuses = [r["status"] for r in out["results"]]
    assert statuses == [200, 404]
    assert slept  # second URL waited


def test_enforcer_blocks_and_empty_url_skipped(fx):
    from shroodler_guardrails.policy import PolicyEnforcer, origin_of, parse_policy

    fx.on("GET", "/a", lambda inc: (200, {}, b"ok"))
    policy = parse_policy({"allow": ["/nope/*"]}, origin=origin_of(fx.origin))
    out = fetch_urls(
        ["", fx.origin + "/a"],
        pacer=Pacer(0),
        enforcer=PolicyEnforcer(policy=policy),
    )
    assert out["results"][0]["error"].startswith("blocked")


def test_challenge_flag_on_interstitial(fx):
    body = b"Just a moment... checking your browser before accessing"
    fx.on("GET", "/a", lambda inc: (403, {}, body))
    out = fetch_urls([fx.origin + "/a"], pacer=Pacer(0))
    assert out["results"][0].get("challenge") is True


def test_caps_url_list(fx):
    fx.on("GET", "/a", lambda inc: (200, {}, b"ok"))
    out = fetch_urls([fx.origin + "/a"] * 5, pacer=Pacer(0), max_urls=2)
    assert len(out["results"]) == 2
    assert out["truncated"] is True
