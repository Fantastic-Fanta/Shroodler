from __future__ import annotations

from shroodler.extractors.challenge import detect_challenge, has_challenge_cookie


def test_detect_challenge_from_body_marker():
    finding = detect_challenge({}, "<html>Just a moment...</html>", 503)
    assert finding is not None
    assert finding.category == "waf-challenge"
    assert finding.id == "waf-challenge-detected"
    assert finding.severity == "info"


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


