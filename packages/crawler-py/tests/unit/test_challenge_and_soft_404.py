from __future__ import annotations

from shroodler.crawler import crawl_url
from shroodler.extractors.challenge import detect_challenge, has_challenge_cookie


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


def test_detect_challenge_ignores_cf_ray_even_on_a_small_200_response():
    # Small 200 API responses are the norm on Cloudflare-fronted sites (JSON
    # endpoints, redirects, minimal templated pages) -- cf-ray alone must not
    # reclassify them as a challenge regardless of size.
    finding = detect_challenge({"cf-ray": "abc123-SJC"}, "short body", 200)
    assert finding is None


def test_detect_challenge_fires_on_cf_ray_with_block_status():
    finding = detect_challenge({"cf-ray": "abc123-SJC"}, "short body", 403)
    assert finding is not None


def test_detect_challenge_ignores_recaptcha_widget_on_ordinary_signup_form():
    # reCAPTCHA/hCaptcha/Turnstile/DataDome are routinely embedded by site
    # owners on ordinary forms as a proactive anti-abuse control -- the tag
    # alone, on a normal 200 response, is not evidence of a block page.
    body = '<form><div class="g-recaptcha" data-sitekey="x"></div></form>'
    assert detect_challenge({}, body, 200) is None


def test_detect_challenge_fires_on_recaptcha_tag_with_block_status():
    body = '<form><div class="g-recaptcha" data-sitekey="x"></div></form>'
    assert detect_challenge({}, body, 403) is not None


def test_detect_challenge_fires_on_clearance_cookie_with_block_status():
    finding = detect_challenge({}, "short body", 403, ["cf_clearance=abc; Path=/"])
    assert finding is not None
    assert finding.evidence == "Cloudflare"


def test_detect_challenge_ignores_clearance_cookie_on_200():
    finding = detect_challenge({}, "short body", 200, ["cf_clearance=abc; Path=/"])
    assert finding is None


def test_has_challenge_cookie():
    assert has_challenge_cookie(["cf_clearance=abc; Path=/"])
    assert not has_challenge_cookie(["session=abc123; Path=/"])


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


def test_challenge_recovers_after_cookie_priming(fx):
    hits = {"n": 0}

    def handler(_incoming):
        hits["n"] += 1
        if hits["n"] == 1:
            return (
                503,
                {"Content-Type": "text/html", "Set-Cookie": "cf_clearance=abc; Path=/"},
                b"Just a moment...",
            )
        return (200, {"Content-Type": "text/html"}, b"<html><body>real content</body></html>")

    fx.on("GET", "/", handler)
    result = crawl_url(fx.origin + "/", depth=0)
    assert hits["n"] == 2
    assert not [f for f in result.findings if f.category == "waf-challenge"]
    page = next(p for p in result.pages if p.url == fx.origin + "/")
    assert page.status_code == 200


def test_challenge_stays_reported_when_retry_also_fails(fx):
    def handler(_incoming):
        return (
            503,
            {"Content-Type": "text/html", "Set-Cookie": "cf_clearance=abc; Path=/"},
            b"Just a moment...",
        )

    fx.on("GET", "/", handler)
    result = crawl_url(fx.origin + "/", depth=0)
    assert any(f.category == "waf-challenge" for f in result.findings)


def test_recovered_challenge_page_still_discovers_links(fx):
    hits = {"n": 0}

    def handler(_incoming):
        hits["n"] += 1
        if hits["n"] == 1:
            return (
                503,
                {"Content-Type": "text/html", "Set-Cookie": "cf_clearance=abc; Path=/"},
                b"Just a moment...",
            )
        return (200, {"Content-Type": "text/html"}, b'<a href="/discovered-child">child</a>')

    fx.on("GET", "/", handler)
    fx.html("/discovered-child", "child page")

    result = crawl_url(fx.origin + "/", depth=2)
    urls = {p.url for p in result.pages}
    assert fx.origin + "/discovered-child" in urls


def test_common_path_probe_reports_challenge_instead_of_silently_dropping(fx):
    fx.html("/", "home")
    fx.html("/.git/HEAD", "Just a moment...", status=503)

    result = crawl_url(fx.origin + "/", depth=0)
    challenge_urls = {f.url for f in result.findings if f.category == "waf-challenge"}
    assert fx.origin + "/.git/HEAD" in challenge_urls
    # And it must not also show up as a false exposed-file hit.
    exposed = {f.evidence for f in result.findings if f.id == "exposed-file"}
    assert "/.git/HEAD" not in exposed


def test_sitewide_challenge_escalation(fx):
    fx.html("/", '<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>')
    for path in ("/a", "/b", "/c"):
        fx.html(path, "Just a moment...", status=503)
    result = crawl_url(fx.origin + "/", depth=1)
    assert any(f.id == "waf-challenge-sitewide" for f in result.findings)
    assert result.stats.pages_challenged >= 3


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
