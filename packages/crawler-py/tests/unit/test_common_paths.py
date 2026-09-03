from __future__ import annotations

from shroodler.crawler import crawl_url
from shroodler.extractors.common_paths import load_paths


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
    assert "/.well-known/security.txt" not in paths


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

