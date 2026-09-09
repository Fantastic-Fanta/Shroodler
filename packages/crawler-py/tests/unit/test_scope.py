from __future__ import annotations

import json

from shroodler.scope import in_scope, load_scope, save_scope


def test_in_scope_missing_file_allows_all():
    assert in_scope("https://evil.example.com/x", {}) is True
    assert in_scope("https://evil.example.com/x", None) is True


def test_wildcard_include():
    scope = {
        "include": ["*.example.com", "example.com"],
        "exclude": [],
        "allow_subdomains": True,
    }
    assert in_scope("https://api.example.com/v1", scope) is True
    assert in_scope("https://example.com/", scope) is True
    assert in_scope("https://other.com/", scope) is False


def test_exclude_wins():
    scope = {
        "include": ["*.example.com", "example.com"],
        "exclude": ["cdn.example.com"],
        "allow_subdomains": True,
    }
    assert in_scope("https://cdn.example.com/app.js", scope) is False
    assert in_scope("https://www.example.com/", scope) is True


def test_allow_subdomains_false_is_exact():
    scope = {
        "include": ["example.com"],
        "exclude": [],
        "allow_subdomains": False,
    }
    assert in_scope("https://example.com/", scope) is True
    assert in_scope("https://api.example.com/", scope) is False


def test_load_missing_scope_file(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert load_scope("lab") == {}


def test_save_and_load_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    save_scope(
        "lab",
        {
            "include": ["*.example.com"],
            "exclude": ["cdn.example.com"],
            "allow_subdomains": True,
        },
    )
    loaded = load_scope("lab")
    assert loaded["include"] == ["*.example.com"]
    assert loaded["exclude"] == ["cdn.example.com"]
    path = tmp_path / ".shroodler" / "programs" / "lab" / "scope.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["exclude"] == ["cdn.example.com"]
