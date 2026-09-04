from __future__ import annotations

from urllib.parse import urlparse

from shroodler.models import Finding, Form

_LOGIN_ACTION_HINTS = (
    "login",
    "signin",
    "sign-in",
    "log-in",
    "auth",
    "authenticate",
    "reset-password",
    "forgot-password",
    "password-reset",
)

_LOCKOUT_KEYWORDS = (
    "too many attempts",
    "too many requests",
    "rate limit",
    "rate-limit",
    "try again later",
    "temporarily locked",
    "temporarily blocked",
    "account locked",
    "captcha",
)

DEFAULT_ATTEMPTS = 6


def is_login_shaped(form: Form) -> bool:
    """Heuristic: does this form look like a login/auth/reset endpoint?

    Used to scope --check-rate-limit probing to forms where hammering the
    endpoint is actually meaningful (and where the safety tradeoff of
    sending repeated requests is worth it) rather than every form on site.
    """
    types = {(f.type or "").lower() for f in form.fields}
    if "password" in types:
        return True
    action = (form.action or "").lower()
    return any(hint in action for hint in _LOGIN_ACTION_HINTS)


def _probe_values(form: Form, attempt: int) -> dict[str, str]:
    values: dict[str, str] = {}
    for f in form.fields:
        if not f.name:
            continue
        if (f.type or "").lower() == "password":
            values[f.name] = f"shroodler-rl-probe-wrong-{attempt}"
        else:
            values[f.name] = "shroodler-rl-probe"
    return values


def check_form_rate_limit(
    fetcher,
    action: str,
    form: Form,
    *,
    attempts: int = DEFAULT_ATTEMPTS,
) -> list[Finding]:
    """Fire `attempts` rapid requests at a login-shaped form and flag it if
    nothing in the response stream (status, body) suggests any throttling,
    lockout, or CAPTCHA kicked in.

    This is opt-in (--check-rate-limit) and off by default: it deliberately
    sends multiple bad-credential attempts at a real endpoint, which has
    real consequences (account lockout, alerting, log noise) against a
    production target. Only call this against systems you're authorized to
    load-test this way.
    """
    method = (form.method or "POST").upper()
    statuses: list[int] = []
    bodies: list[str] = []
    for i in range(attempts):
        data = _probe_values(form, i)
        if method == "GET":
            resp = fetcher.request("GET", action)
        else:
            resp = fetcher.post_form(action, data)
        if resp.error:
            return []
        statuses.append(resp.status_code)
        bodies.append(resp.text or "")

    if any(s == 429 for s in statuses):
        return []
    lowered = [b.lower() for b in bodies]
    if any(kw in b for b in lowered for kw in _LOCKOUT_KEYWORDS):
        return []
    if len(set(statuses)) > 1:
        # Status changed partway through (e.g. first attempts 200, later
        # ones 403/423) -- treat that as a throttling/lockout signal.
        return []

    ev = f"{attempts} requests, all status {statuses[0] if statuses else '?'}, no lockout/CAPTCHA signal"
    return [
        Finding(
            id="missing-rate-limit",
            severity="medium",
            category="auth",
            url=action,
            description=(
                f"Sent {attempts} rapid requests to this login/auth-shaped form with "
                "bad credentials and saw no rate-limiting, lockout, or CAPTCHA response -- "
                "the endpoint may be brute-forceable."
            ),
            evidence=ev,
        )
    ]


def check_rate_limits(fetcher, origin: str, pages, *, attempts: int = DEFAULT_ATTEMPTS) -> list[Finding]:
    findings: list[Finding] = []
    seen_actions: set[str] = set()
    for page in pages:
        for form in page.forms:
            if not is_login_shaped(form):
                continue
            action = form.action or page.url
            if action.startswith("/"):
                p = urlparse(page.url)
                action = f"{p.scheme}://{p.netloc}{action}"
            if action in seen_actions:
                continue
            seen_actions.add(action)
            findings.extend(check_form_rate_limit(fetcher, action, form, attempts=attempts))
    return findings
