from __future__ import annotations

from shroodler.crawler import crawl_url


def test_common_paths_true_and_false_positives(fx):
    fx.html("/", "<p>home</p>")
    fx.html("/.git/config", "[core]\n")
    fx.html("/backup.sql.bak", "DUMP")
    # .env, .DS_Store, wp-config.php.bak absent → 404
    result = crawl_url(fx.origin + "/", depth=0)
    urls = {p.url for p in result.pages}
    assert fx.origin + "/.git/config" in urls
    assert fx.origin + "/backup.sql.bak" in urls
    assert fx.origin + "/.env" not in urls
    assert fx.origin + "/.DS_Store" not in urls
    assert fx.origin + "/wp-config.php.bak" not in urls
    exposed = [f for f in result.findings if f.id == "exposed-file"]
    paths = {f.evidence for f in exposed}
    assert "/.git/config" in paths
    assert "/backup.sql.bak" in paths
    assert "/.env" not in paths
    assert "/.DS_Store" not in paths
    assert "/wp-config.php.bak" not in paths
