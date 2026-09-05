from __future__ import annotations

from shroodler.extractors.rate_limit import (
    check_form_rate_limit,
    check_rate_limits,
    is_login_shaped,
)
from shroodler.models import Form, FormField, Page
from shroodler.modes.static import FetchResult


def _login_form(action: str = "/login") -> Form:
    return Form(
        action=action,
        method="POST",
        fields=[
            FormField(name="username", type="text", hidden=False),
            FormField(name="password", type="password", hidden=False),
        ],
    )


class _FakeFetcher:
    def __init__(self, results: list[FetchResult]):
        self._results = list(results)
        self.calls: list[tuple[str, str, dict | None]] = []

    def request(self, method: str, url: str) -> FetchResult:
        self.calls.append((method, url, None))
        return self._results.pop(0)

    def post_form(self, url: str, data: dict) -> FetchResult:
        self.calls.append(("POST", url, data))
        return self._results.pop(0)


def _fr(status: int, text: str = "invalid credentials") -> FetchResult:
    return FetchResult(
        url="http://127.0.0.1/login",
        status_code=status,
        headers={},
        body=text.encode(),
        text=text,
        redirect_to=None,
    )


def test_is_login_shaped_detects_password_field():
    assert is_login_shaped(_login_form())


def test_is_login_shaped_detects_action_hint():
    field = FormField(name="q", type="text", hidden=False)
    form = Form(action="/api/authenticate", method="POST", fields=[field])
    assert is_login_shaped(form)


def test_is_login_shaped_false_for_unrelated_form():
    field = FormField(name="q", type="text", hidden=False)
    form = Form(action="/search", method="GET", fields=[field])
    assert not is_login_shaped(form)


def test_flags_missing_rate_limit_when_all_identical():
    fetcher = _FakeFetcher([_fr(200) for _ in range(6)])
    findings = check_form_rate_limit(fetcher, "http://127.0.0.1/login", _login_form(), attempts=6)
    assert len(findings) == 1
    assert findings[0].id == "missing-rate-limit"
    assert findings[0].category == "auth"
    assert len(fetcher.calls) == 6


def test_no_finding_when_429_seen():
    results = [_fr(200), _fr(200), _fr(429, "too many requests")] + [_fr(200)] * 3
    fetcher = _FakeFetcher(results)
    findings = check_form_rate_limit(fetcher, "http://127.0.0.1/login", _login_form(), attempts=6)
    assert findings == []


def test_no_finding_when_lockout_keyword_present():
    lockout = _fr(200, "Account temporarily locked, try again later")
    results = [_fr(200)] * 3 + [lockout] + [_fr(200)] * 2
    fetcher = _FakeFetcher(results)
    findings = check_form_rate_limit(fetcher, "http://127.0.0.1/login", _login_form(), attempts=6)
    assert findings == []


def test_no_finding_when_status_changes():
    results = [_fr(200)] * 3 + [_fr(403)] * 3
    fetcher = _FakeFetcher(results)
    findings = check_form_rate_limit(fetcher, "http://127.0.0.1/login", _login_form(), attempts=6)
    assert findings == []


def test_no_finding_on_transport_error():
    err = FetchResult(
        url="http://127.0.0.1/login", status_code=0, headers={}, body=b"", text="",
        redirect_to=None, error="connection refused",
    )
    fetcher = _FakeFetcher([err])
    findings = check_form_rate_limit(fetcher, "http://127.0.0.1/login", _login_form(), attempts=6)
    assert findings == []


def test_check_rate_limits_skips_non_login_forms_and_dedupes_actions():
    q_field = FormField(name="q", type="text", hidden=False)
    other_form = Form(action="/search", method="GET", fields=[q_field])
    login_form_a = _login_form("/login")
    login_form_b = _login_form("/login")  # same action, seen on two pages
    pages = [
        Page(
            url="http://127.0.0.1/",
            status_code=200,
            forms=[other_form, login_form_a],
            params=[],
            cookies=[],
            headers={"present": [], "missing": []},
            js_files=[],
        ),
        Page(
            url="http://127.0.0.1/account",
            status_code=200,
            forms=[login_form_b],
            params=[],
            cookies=[],
            headers={"present": [], "missing": []},
            js_files=[],
        ),
    ]
    fetcher = _FakeFetcher([_fr(200) for _ in range(6)])
    findings = check_rate_limits(fetcher, "http://127.0.0.1/", pages, attempts=6)
    assert len(findings) == 1
    assert len(fetcher.calls) == 6  # only probed the /login action once, not twice
