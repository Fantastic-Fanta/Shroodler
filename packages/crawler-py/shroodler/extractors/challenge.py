from __future__ import annotations

import re

from shroodler.models import Finding

# Detection only -- this module never attempts to solve, bypass, or evade a
# challenge. Its only job is to stop the crawler from silently treating a
# WAF/bot-mitigation interstitial as real page content (a false negative: a
# "clean" scan against a challenge-fronted target currently means nothing).

_HEADER_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    # (header name, value substring to match, vendor label)
    ("server", "cloudflare", "Cloudflare"),
    ("cf-mitigated", "", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("x-datadome", "", "DataDome"),
    ("x-akamai-transformed", "", "Akamai"),
    ("server", "akamaighost", "Akamai"),
    ("x-px-block", "", "PerimeterX"),
    ("perimeterx", "", "PerimeterX"),
    ("x-sucuri-id", "", "Sucuri"),
)

_BODY_SIGNATURES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"just a moment", re.I), "Cloudflare"),
    (re.compile(r"checking your browser before accessing", re.I), "Cloudflare"),
    (re.compile(r'id=["\']challenge-form["\']', re.I), "Cloudflare"),
    (re.compile(r"cf-turnstile|cf_chl_opt", re.I), "Cloudflare Turnstile"),
    (re.compile(r"hcaptcha", re.I), "hCaptcha"),
    (re.compile(r"g-recaptcha|recaptcha/api", re.I), "reCAPTCHA"),
    (re.compile(r"perimeterx|_pxCaptcha|px-captcha", re.I), "PerimeterX"),
    (re.compile(r"datadome", re.I), "DataDome"),
    (re.compile(r"access denied.{0,80}akamai", re.I), "Akamai"),
    (re.compile(r"sucuri.{0,40}(firewall|website firewall)", re.I), "Sucuri"),
)


def _match_headers(headers: dict[str, str]) -> str | None:
    lowered = {k.lower(): v for k, v in headers.items()}
    for name, needle, vendor in _HEADER_SIGNATURES:
        value = lowered.get(name)
        if value is None:
            continue
        if not needle or needle.lower() in value.lower():
            return vendor
    return None


def _match_body(body: str) -> str | None:
    for pattern, vendor in _BODY_SIGNATURES:
        if pattern.search(body):
            return vendor
    return None


def detect_challenge(
    headers: dict[str, str], body: str, status_code: int
) -> Finding | None:
    """Return a finding if this response looks like a WAF/bot-mitigation
    challenge/interstitial page rather than real target content.

    Header signatures alone (e.g. a plain `cf-ray` header on an otherwise
    normal 200 response, which Cloudflare adds to *all* proxied traffic) are
    not sufficient on their own -- only header signatures paired with a
    small/error-shaped response, or a body-content signature, count as a hit.
    """
    body = body or ""
    vendor = _match_body(body)
    if vendor:
        return _make_finding(vendor, status_code)
    header_vendor = _match_headers(headers)
    if header_vendor and (status_code in (403, 503) or len(body) < 4000):
        return _make_finding(header_vendor, status_code)
    return None


def _make_finding(vendor: str, status_code: int) -> Finding:
    return Finding(
        id="waf-challenge-detected",
        severity="high",
        category="waf-challenge",
        url="",
        description=(
            f"Response looks like a {vendor} challenge/interstitial page, not "
            "real target content -- the crawler stopped extracting forms/"
            "secrets/links from this page. Passive/active checks against "
            "this URL were not meaningfully performed. This is a detection-"
            "only signal: Shroodler does not attempt to solve or bypass "
            "challenges. If this is unexpected on an authorized scan, ask "
            "the target's operator to allowlist the scanner's source "
            f"IP/User-Agent (HTTP status was {status_code})."
        ),
        evidence=None,
    )
