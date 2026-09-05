from __future__ import annotations

import re

from shroodler.models import Finding

# Detection only -- this module never attempts to solve, bypass, or evade a
# challenge. Its only job is to stop the crawler from silently treating a
# WAF/bot-mitigation interstitial as real page content (a false negative: a
# "clean" scan against a challenge-fronted target currently means nothing).
#
# Both header and "weak" body signatures are common on ordinary, non-blocked
# traffic (cf-ray is stamped on every Cloudflare-proxied response; reCAPTCHA/
# hCaptcha/Turnstile/DataDome are routinely embedded by site owners on normal
# login/signup forms as a deliberate anti-abuse control, not only on block
# pages) -- so neither counts as a hit unless paired with a 403/503 status.
# Only "strong" body phrases (the interstitial's own wording, e.g. Cloudflare's
# "Just a moment...") are specific enough to fire standalone.

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

_BLOCK_STATUSES = (403, 503)

# Fire on their own, any status: these are the interstitial page's own
# wording, not a widget/tag that a site might embed on an ordinary page.
_STRONG_BODY_SIGNATURES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"just a moment", re.I), "Cloudflare"),
    (re.compile(r"checking your browser before accessing", re.I), "Cloudflare"),
    (re.compile(r'id=["\']challenge-form["\']', re.I), "Cloudflare"),
    (re.compile(r"access denied.{0,80}akamai", re.I), "Akamai"),
    (re.compile(r"sucuri.{0,40}(firewall|website firewall)", re.I), "Sucuri"),
)

# Only count as a hit paired with a 403/503 status: these are widgets/tags
# vendors' *own* SDKs tell site owners to embed directly on normal forms
# (login, signup, contact) as a proactive anti-abuse control, so seeing the
# tag alone is not evidence this particular response is a block page.
_WEAK_BODY_SIGNATURES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"cf-turnstile|cf_chl_opt", re.I), "Cloudflare Turnstile"),
    (re.compile(r"hcaptcha", re.I), "hCaptcha"),
    (re.compile(r"g-recaptcha|recaptcha/api", re.I), "reCAPTCHA"),
    (re.compile(r"perimeterx|_pxCaptcha|px-captcha", re.I), "PerimeterX"),
    (re.compile(r"datadome", re.I), "DataDome"),
)

# Cookies vendors' own challenge/bot-mitigation flow sets on the response to a
# challenge -- a useful signal, but (like the weak body tags above) some of
# these can also appear on ordinary non-blocked traffic from the same vendor,
# so cookie matches are gated on a 403/503 status too, same tier as "weak".
_COOKIE_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("cf_clearance", "Cloudflare"),
    ("__cf_bm", "Cloudflare"),
    ("cf_chl_", "Cloudflare"),
    ("incap_ses_", "Imperva Incapsula"),
    ("visid_incap_", "Imperva Incapsula"),
    ("ak_bmsc", "Akamai"),
    ("_abck", "Akamai"),
    ("bm_sz", "Akamai"),
    ("datadome", "DataDome"),
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


def _match_body(patterns: tuple[tuple[re.Pattern[str], str], ...], body: str) -> str | None:
    for pattern, vendor in patterns:
        if pattern.search(body):
            return vendor
    return None


def _cookie_name(set_cookie: str) -> str:
    return set_cookie.split("=", 1)[0].strip().lower()


def _match_cookies(set_cookies: list[str]) -> str | None:
    names = [_cookie_name(c) for c in set_cookies]
    for prefix, vendor in _COOKIE_SIGNATURES:
        if any(name.startswith(prefix) for name in names):
            return vendor
    return None


def has_challenge_cookie(set_cookies: list[str]) -> bool:
    """Whether this response's Set-Cookie headers include a known challenge/
    bot-mitigation cookie (e.g. Cloudflare's `cf_clearance`). Used to decide
    whether a single same-URL retry is worth attempting: these cookies are
    typically set *on the response to the challenge itself*, so a follow-up
    request through the same cookie jar may already satisfy it -- still
    detection-only, this never solves the challenge itself."""
    return _match_cookies(set_cookies) is not None


def detect_challenge(
    headers: dict[str, str],
    body: str,
    status_code: int,
    set_cookies: list[str] | None = None,
) -> Finding | None:
    """Return a finding if this response looks like a WAF/bot-mitigation
    challenge/interstitial page rather than real target content.

    Only a "strong" body signature (the interstitial's own wording) fires on
    its own. A bare header signature (e.g. `cf-ray`, present on *all*
    Cloudflare-proxied traffic), a "weak" body signature (a CAPTCHA/
    bot-mitigation widget tag that site owners routinely embed on ordinary
    forms), or a challenge-issuance cookie only counts as a hit when paired
    with a 403/503 status -- none of those alone is specific enough to mean
    "this response IS the block page".
    """
    body = body or ""
    vendor = _match_body(_STRONG_BODY_SIGNATURES, body)
    if vendor:
        return _make_finding(vendor, status_code)
    if status_code in _BLOCK_STATUSES:
        vendor = (
            _match_body(_WEAK_BODY_SIGNATURES, body)
            or _match_headers(headers)
            or _match_cookies(set_cookies or [])
        )
        if vendor:
            return _make_finding(vendor, status_code)
    return None


def _make_finding(vendor: str, status_code: int) -> Finding:
    return Finding(
        id="waf-challenge-detected",
        severity="medium",
        category="waf-challenge",
        url="",
        description=(
            f"Response looks like a {vendor} challenge/interstitial page, not "
            "real target content -- the crawler stopped extracting forms/"
            "secrets/links from this page. Passive/active checks against "
            "this URL were not meaningfully performed. This is a detection-"
            "only signal: Shroodler does not attempt to solve or bypass "
            "challenges. If this is unexpected on an authorized scan, try "
            "--user-agent to rule out UA-based blocking, or ask the "
            "target's operator to allowlist the scanner's source IP/"
            f"User-Agent (HTTP status was {status_code})."
        ),
        evidence=vendor,
    )
