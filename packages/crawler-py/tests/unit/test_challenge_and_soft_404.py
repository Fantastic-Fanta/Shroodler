from __future__ import annotations

from shroodler.crawler import crawl_url
from shroodler.extractors.challenge import detect_challenge


def test_detect_challenge_from_body_marker():
    finding = detect_challenge({}, "<html>Just a moment...</html>", 503)
    assert finding is not None
    assert finding.category == "waf-challenge"
    assert finding.id == "waf-challenge-detected"


def test_detect_challenge_ignores_plain_cf_ray_on_normal_page():
    # cf-ray is present on *all* Cloudflare-proxied traffic, including
    # perfectly ordinary 200 responses -- must not fire on its own.
    body = "<html><body>" + ("normal page content " * 500) + "</body></html>"
    finding = detect_challenge({"cf-ray": "abc123-SJC"}, body, 200)
    assert finding is None


def test_detect_challenge_fires_on_small_cf_ray_response():
    finding = detect_challenge({"cf-ray": "abc123-SJC"}, "short body", 200)
    assert finding is not None


def test_crawl_flags_challenge_page_and_skips_content_extraction(fx):
    fx.html(
        "/",
        '<html><body>Just a moment...<form action="/login"><input name="u">'
        "</form>AKIAABCDEFGHIJKLMNOP</body></html>",
        status=503,
        headers={"Server": "cloudflare"},
    )
    result = crawl_url(fx.origin + "/", depth=0)
    challenge = [f for f in result.findings if f.category == "waf-challenge"]
    assert len(challenge) == 1
    assert challenge[0].url == fx.origin + "/"
    # The page was not parsed as real content: no form/secret findings from it.
    assert not [f for f in result.findings if f.id == "aws-access-key"]
    page = next(p for p in result.pages if p.url == fx.origin + "/")
    assert page.forms == []


def test_soft_404_suppresses_templated_not_found_page(fx):
    fx.html("/", "<p>home</p>")
    fx.prefix(
        "/",
        lambda path: (
            200,
            {"Content-Type": "text/html"},
            b"<html><body>Nothing to see here, sorry about that!</body></html>",
        ),
    )
    # A real hit: distinctly different length/content from the templated page,
    # registered as an explicit route so it wins over the catch-all prefix.
    fx.html("/.git/HEAD", "ref: refs/heads/main\n" * 50)

    result = crawl_url(fx.origin + "/", depth=0)
    exposed = {f.evidence for f in result.findings if f.id == "exposed-file"}
    assert "/.git/HEAD" in exposed
    assert "/.env" not in exposed
    assert "/backup.sql.bak" not in exposed


def test_probe_mutations_respects_remaining_page_budget(fx):
    fx.html("/", '<a href="/login">login</a>')
    fx.html("/login", "<p>login</p>")
    # Every backup-suffix mutation of /login exists, so without a budget
    # bound the mutation-probe phase alone would blow past max_pages.
    for suffix in (".bak", ".old", "~", ".swp", ".copy"):
        fx.html(f"/login{suffix}", f"backup {suffix}")

    result = crawl_url(fx.origin + "/", depth=1, max_pages=3)
    assert result.stats is not None
    assert result.stats.pages_crawled <= 3
    assert len(result.pages) <= 3
