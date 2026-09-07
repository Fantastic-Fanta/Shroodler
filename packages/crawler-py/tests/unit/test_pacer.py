from __future__ import annotations

import pytest

from shroodler.pacer import Pacer, compose_user_agent


def test_zero_interval_never_sleeps():
    slept: list[float] = []
    now = iter([0.0, 0.1, 0.2])
    p = Pacer(0, sleeper=slept.append, now=lambda: next(now))
    p.wait()
    p.wait()
    assert slept == []


def test_second_call_sleeps_remaining_interval():
    slept: list[float] = []
    ticks = iter([10.0, 10.2, 11.2, 11.2])
    p = Pacer(1.0, sleeper=slept.append, now=lambda: next(ticks))
    p.wait()
    p.wait()
    assert slept == pytest.approx([0.8])


def test_compose_user_agent_appends_suffix_once():
    ua = compose_user_agent("Shroodler/0.1.0", "Bugcrowd-handle")
    assert ua.endswith("Bugcrowd-handle")
    assert compose_user_agent(ua, "Bugcrowd-handle") == ua
