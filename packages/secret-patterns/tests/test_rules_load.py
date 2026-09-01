from __future__ import annotations

from pathlib import Path

import yaml


def test_rules_are_loadable_yaml():
    rules_dir = Path(__file__).resolve().parents[1] / "rules"
    files = list(rules_dir.glob("*.yaml"))
    assert files
    for path in files:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        for rule in data:
            assert "id" in rule and "pattern" in rule
