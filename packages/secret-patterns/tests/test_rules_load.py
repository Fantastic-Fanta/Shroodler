from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_rules_are_loadable_yaml():
    rules_dir = ROOT / "rules"
    files = list(rules_dir.glob("*.yaml"))
    assert files
    ids: set[str] = set()
    for path in files:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        for rule in data:
            assert "id" in rule and "pattern" in rule
            assert "severity" in rule
            assert rule["id"] not in ids
            ids.add(rule["id"])
    assert "aws-access-key" in ids
    assert "github-pat" in ids
    assert "stripe-secret-key" in ids


def test_wordlists_are_plain_text_paths():
    wordlists = ROOT / "wordlists"
    files = sorted(wordlists.glob("*.txt"))
    assert files
    paths: list[str] = []
    for path in files:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            assert line.startswith("/"), path
            paths.append(line)
    assert "/.git/config" in paths
    assert "/.git/HEAD" in paths
    assert "/.well-known/security.txt" in paths
    assert "/.env" in paths
    assert len(paths) == len(set(paths))
