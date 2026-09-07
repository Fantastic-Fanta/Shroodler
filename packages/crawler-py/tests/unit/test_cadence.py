from __future__ import annotations

import json

from shroodler.cadence import recommend, render_text
from shroodler.cli import build_parser


def test_pr_skips_payload_and_uses_safe():
    rec = recommend("pr")
    assert "--profile" in rec["crawl"] and "safe" in rec["crawl"]
    assert rec["payload"] is None
    text = render_text(rec)
    assert "skip payload" in text
    assert "--allow-external" not in text


def test_nightly_and_weekly_include_payload():
    nightly = recommend("nightly", url="http://127.0.0.1:8081/")
    assert "--check-idor" in nightly["crawl"]
    assert nightly["payload"][1] == "payload"
    weekly = recommend("weekly")
    assert "aggressive" in weekly["crawl"]
    assert "--adaptive" in weekly["payload"]
    assert "--allow-external" not in weekly["crawl"]


def test_unknown_tier_raises():
    import pytest

    with pytest.raises(ValueError, match="unknown cadence"):
        recommend("hourly")


def test_cli_cadence_json(tmp_path):
    parser = build_parser()
    out = tmp_path / "cadence.json"
    args = parser.parse_args(
        ["cadence", "--tier", "pr", "--format", "json", "-o", str(out)]
    )
    assert args.func.__name__ == "cmd_cadence"
    assert args.tier == "pr"
    rc = args.func(args)
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["tier"] == "pr"
    assert doc["payload"] is None
