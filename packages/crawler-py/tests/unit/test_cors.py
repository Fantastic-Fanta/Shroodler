from __future__ import annotations

from shroodler.extractors.cors import (
    ATTACKER_ORIGIN,
    _attacker_origins_for,
    findings_from_cors_headers,
    is_api_ish,
    is_static_asset,
    probe_cors,
)


def _ids(findings) -> list[str]:
    return [f.id for f in findings]


def test_cors_wildcard_credentials():
    findings = findings_from_cors_headers(
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        "http://127.0.0.1/api/x",
    )
    assert _ids(findings) == ["cors-wildcard-credentials"]
    assert findings[0].category == "header"
    assert findings[0].severity == "high"


def test_cors_reflect_origin():
    findings = findings_from_cors_headers(
        {"Access-Control-Allow-Origin": ATTACKER_ORIGIN},
        "http://127.0.0.1/api/x",
    )
    assert _ids(findings) == ["cors-reflect-origin"]
    assert findings[0].severity == "medium"
    creds = findings_from_cors_headers(
        {
            "Access-Control-Allow-Origin": ATTACKER_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        },
        "http://127.0.0.1/api/x",
    )
    assert _ids(creds) == ["cors-reflect-origin"]
    assert creds[0].severity == "high"


def test_cors_allow_any():
    findings = findings_from_cors_headers(
        {"Access-Control-Allow-Origin": "*"},
        "http://127.0.0.1/api/x",
    )
    assert _ids(findings) == ["cors-allow-any"]
    assert findings[0].severity == "info"
    assert findings[0].category == "header"


def test_cors_negative_allowlist_and_absent():
    locked = findings_from_cors_headers(
        {"Access-Control-Allow-Origin": "https://app.example"},
        "http://127.0.0.1/api/x",
    )
    assert locked == []
    assert findings_from_cors_headers({}, "http://127.0.0.1/api/x") == []
    assert findings_from_cors_headers(
        {"Access-Control-Allow-Credentials": "true"},
        "http://127.0.0.1/api/x",
    ) == []


def test_api_ish_skips_static():
    assert is_static_asset("http://127.0.0.1/static/app.js")
    assert not is_api_ish("http://127.0.0.1/static/app.js", "application/javascript")
    assert is_api_ish("http://127.0.0.1/api/users", "text/plain")
    assert is_api_ish("http://127.0.0.1/users", "application/json")
    assert not is_api_ish("http://127.0.0.1/login", "text/html")


def test_skips_non_local_origin_without_allow_external():
    class Boom:
        def request(self, *args, **kwargs):
            raise AssertionError("must not probe off-local hosts")

    findings = probe_cors("http://example.com/", Boom(), ["http://example.com/api/x"])
    assert len(findings) == 1
    assert findings[0].id == "cors-probe-skipped"
    assert findings[0].category == "scan-note"


def test_allow_external_permits_non_local_origin():
    calls = []

    class Recorder:
        def request(self, method, url, headers=None):
            calls.append((method, url))

            class Resp:
                headers: dict[str, str] = {}

            return Resp()

    out = probe_cors(
        "http://example.com/",
        Recorder(),
        ["http://example.com/api/x"],
        allow_external=True,
    )
    assert out == []
    assert calls, "expected the probe to actually fire when allow_external=True"


def test_attacker_origins_for_variants():
    origins = _attacker_origins_for("https://api.foo.com")
    assert ATTACKER_ORIGIN in origins         # baseline
    assert "https://evil.api.foo.com" in origins  # suffix-append bypass
    assert "https://api.foo.com.evil.example" in origins  # prefix-append bypass
    assert "https://shroodler-test.foo.com" in origins  # subdomain bypass
    assert "null" in origins                  # sandboxed iframe


def test_bypass_variant_detected():
    # Server reflects back a bypass-variant origin — must still fire
    bypass = "https://evil.api.foo.com"
    findings = findings_from_cors_headers(
        {"Access-Control-Allow-Origin": bypass, "Access-Control-Allow-Credentials": "true"},
        "https://api.foo.com/v1/me",
        probed_origin=bypass,
    )
    assert findings
    assert findings[0].id == "cors-reflect-origin"
    assert findings[0].severity == "high"
    assert bypass in (findings[0].evidence or "")


def test_null_origin_detected():
    findings = findings_from_cors_headers(
        {"Access-Control-Allow-Origin": "null"},
        "https://api.foo.com/v1/me",
        probed_origin="null",
    )
    assert findings
    assert findings[0].id == "cors-reflect-origin"
    assert "null" in findings[0].description


def test_probe_cors_stops_on_first_bypass(fx):
    """Once a bypass is found for a URL, remaining origin variants are skipped."""
    calls = []

    class Recorder:
        def request(self, method, url, headers=None):
            calls.append((method, url, (headers or {}).get("Origin", "")))

            class Resp:
                headers: dict[str, str] = {}

                def __init__(self, origin):
                    if origin == ATTACKER_ORIGIN:
                        self.headers = {"Access-Control-Allow-Origin": ATTACKER_ORIGIN}

            return Resp((headers or {}).get("Origin", ""))

    probe_cors(
        "http://127.0.0.1:9999/",
        Recorder(),
        ["http://127.0.0.1:9999/api/me"],
        allow_external=True,
    )
    origins_tried = [h for _m, _u, h in calls]
    # First origin (evil.example) triggers a finding — later variants not tried
    assert ATTACKER_ORIGIN in origins_tried
    assert not any("evil.127" in o for o in origins_tried), (
        "should have stopped after first bypass"
    )


