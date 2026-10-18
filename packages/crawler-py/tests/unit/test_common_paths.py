from __future__ import annotations

from shroodler.extractors.common_paths import (
    load_backup_suffixes,
    load_paths,
    mutation_paths,
)


def test_wordlists_are_data_files():
    paths = load_paths()
    assert len(paths) == len(set(paths))
    assert "/.git/HEAD" in paths
    assert "/.well-known/security.txt" in paths
    assert "/humans.txt" in paths


def test_backup_suffixes_are_data_files():
    suffixes = load_backup_suffixes()
    assert suffixes == [".bak", ".old", ".orig", "~", ".swp", ".copy"]
    paths = load_paths()
    assert "/backup.sql.bak" in paths
    assert ".bak" not in paths
    assert "/.bak" not in paths
    assert "~" not in paths


def test_mutation_paths_small_set_from_discovered():
    discovered = ["/", "/login", "/settings", "/about", "/backup.sql.bak", "/static/app.js"]
    mutated = mutation_paths(discovered)
    assert "/login.bak" in mutated
    assert "/login.old" in mutated
    assert "/login~" in mutated
    assert "/settings.bak" in mutated
    assert "/backup.sql.bak.bak" in mutated
    assert "/backup.sql.bak.old" in mutated
    assert "/about.bak" not in mutated
    assert "/static/app.js.bak" not in mutated
    assert "/.bak" not in mutated


