from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load_rules() -> list[dict]:
    rules: list[dict] = []
    for path in sorted((ROOT / "rules").glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        rules.extend(data)
    return rules


def test_rules_are_loadable_yaml():
    rules = _load_rules()
    assert rules
    ids: set[str] = set()
    for rule in rules:
        assert "id" in rule and "pattern" in rule
        assert "severity" in rule
        assert rule["id"] not in ids
        ids.add(rule["id"])
    assert "aws-access-key" in ids
    assert "slack-token" in ids
    assert "github-pat" in ids
    assert "github-fine-grained-pat" in ids
    assert "npm-access-token" in ids
    assert "stripe-secret-key-live" in ids
    assert "stripe-secret-key-test" in ids
    assert "google-api-key" in ids
    assert "azure-storage-account-key" in ids


PATH_WORDLISTS = {"common-paths.txt", "source-control.txt", "well-known.txt"}


def test_wordlists_are_plain_text_paths():
    wordlists = ROOT / "wordlists"
    files = sorted(p for p in wordlists.glob("*.txt") if p.name in PATH_WORDLISTS)
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


def test_backup_suffix_wordlist():
    root = Path(__file__).resolve().parents[1]
    suffixes: list[str] = []
    for raw in (root / "wordlists" / "backup-suffixes.txt").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        suffixes.append(line)
    assert suffixes == [".bak", ".old", ".orig", "~", ".swp", ".copy"]
    names: list[str] = []
    for raw in (root / "wordlists" / "backup-interesting.txt").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        names.append(line)
    assert "login" in names
    assert "settings" in names


def test_html_comment_keywords_are_plain_text():
    path = Path(__file__).resolve().parents[1] / "keywords" / "html-comments.txt"
    text = path.read_text(encoding="utf-8")
    keys = {
        line.strip().upper()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    assert {"TODO", "FIXME", "PASSWORD", "API_KEY"} <= keys
