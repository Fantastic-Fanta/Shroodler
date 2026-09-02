from __future__ import annotations

from shroodler.crawler import crawl_url
from shroodler.extractors.common_paths import (
    load_backup_suffixes,
    load_paths,
    mutation_paths,
)


def test_common_paths_true_and_false_positives(fx):
    fx.html("/", "<p>home</p>")
    fx.html("/.git/config", "[core]\n")
    fx.html("/.git/HEAD", "ref: refs/heads/main\n")
    fx.html("/backup.sql.bak", "DUMP")
    # .env, .DS_Store, wp-config.php.bak absent → 404
    result = crawl_url(fx.origin + "/", depth=0)
    urls = {p.url for p in result.pages}
    assert fx.origin + "/.git/config" in urls
    assert fx.origin + "/.git/HEAD" in urls
    assert fx.origin + "/backup.sql.bak" in urls
    assert fx.origin + "/.env" not in urls
    assert fx.origin + "/.DS_Store" not in urls
    assert fx.origin + "/wp-config.php.bak" not in urls
    exposed = [f for f in result.findings if f.id == "exposed-file"]
    paths = {f.evidence for f in exposed}
    assert "/.git/config" in paths
    assert "/.git/HEAD" in paths
    assert "/backup.sql.bak" in paths
    assert "/.env" not in paths
    assert "/.DS_Store" not in paths
    assert "/wp-config.php.bak" not in paths


def test_wordlists_are_data_files():
    paths = load_paths()
    assert len(paths) == len(set(paths))
    assert "/.git/HEAD" in paths
    assert "/.well-known/security.txt" in paths
    assert "/humans.txt" in paths


def test_probed_body_is_scanned_for_secrets(fx):
    fx.html("/", "<p>home</p>")
    fx.html("/.env", "GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz\n")
    result = crawl_url(fx.origin + "/", depth=0)
    ids = {(f.id, f.url.replace(fx.origin, "")) for f in result.findings}
    assert ("exposed-file", "/.env") in ids or any(
        f.id == "exposed-file" and f.url.endswith("/.env") for f in result.findings
    )
    assert any(f.id == "github-pat" and f.url.endswith("/.env") for f in result.findings)


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


def test_backup_name_mutation_true_and_false_positives(fx):
    fx.html("/", '<a href="/login">login</a><a href="/settings">s</a>')
    fx.html("/login", "<p>login</p>")
    fx.html("/settings", "<p>settings</p>")
    fx.html("/login.bak", "# leftover login template backup\n")
    # /settings.bak and /login.old absent → 404
    result = crawl_url(fx.origin + "/", depth=1)
    urls = {p.url for p in result.pages}
    assert fx.origin + "/login.bak" in urls
    assert fx.origin + "/settings.bak" not in urls
    assert fx.origin + "/login.old" not in urls
    exposed = {f.evidence for f in result.findings if f.id == "exposed-file"}
    assert "/login.bak" in exposed
    assert "/settings.bak" not in exposed
    assert "/login.old" not in exposed
