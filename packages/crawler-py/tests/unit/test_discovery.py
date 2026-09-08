from __future__ import annotations

from pathlib import Path

import httpx

from shroodler.discovery import (
    DiscoveryConfig,
    apex_domain,
    discover,
    parse_crtsh_names,
    probe_subdomains,
)
from shroodler.modes.static import FetchResult
from shroodler.program import ProgramState


def _fetch_result(url: str, status_code: int, text: str = "") -> FetchResult:
    return FetchResult(
        url=url,
        status_code=status_code,
        headers={},
        body=text.encode(),
        text=text,
        redirect_to=None,
    )


def test_crtsh_parse_filters_wildcards():
    import json

    raw = [
        {"name_value": "www.example.com"},
        {"name_value": "*.example.com"},
        {"name_value": "api.example.com\nmail.example.com"},
        {"name_value": "evil.other.test"},
        {"name_value": "example.com"},
        {"name_value": "foo*.example.com"},
        {"name_value": "staging.example.com"},
    ]
    names = parse_crtsh_names(raw, "example.com")
    assert "www.example.com" in names
    assert "example.com" in names
    assert "staging.example.com" in names
    assert "*.example.com" not in names
    assert "api.example.com" not in names
    assert "mail.example.com" not in names
    assert "evil.other.test" not in names
    assert "foo*.example.com" not in names
    assert parse_crtsh_names(json.dumps(raw), "example.com") == names


def test_probe_counts_4xx_as_live(monkeypatch):
    class FakeFetcher:
        def __init__(self, timeout=5.0, **kwargs):
            self.timeout = timeout

        def fetch(self, url):
            return _fetch_result(url, 404)

        def close(self):
            pass

    monkeypatch.setattr("shroodler.discovery.StaticFetcher", FakeFetcher)
    live = probe_subdomains(["dead.example.com"], timeout=5.0, workers=2)
    assert live == ["dead.example.com"]


def test_probe_skips_connection_errors(monkeypatch):
    class FakeFetcher:
        def __init__(self, timeout=5.0, **kwargs):
            pass

        def fetch(self, url):
            raise httpx.ConnectError("refused")

        def close(self):
            pass

    monkeypatch.setattr("shroodler.discovery.StaticFetcher", FakeFetcher)
    live = probe_subdomains(["gone.example.com"], timeout=5.0, workers=2)
    assert live == []


def test_discovery_adds_new_subdomains_to_state(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    saves: list[str] = []

    def fake_save(state):
        saves.append(state.slug)
        return Path("/dev/null")

    monkeypatch.setattr("shroodler.discovery.program.save", fake_save)
    monkeypatch.setattr(
        "shroodler.discovery.fetch_crtsh_candidates",
        lambda apex, timeout=5.0: ["www.example.com", "api.example.com"],
    )

    class FakeFetcher:
        def __init__(self, timeout=5.0, **kwargs):
            pass

        def fetch(self, url):
            return _fetch_result(url, 200)

        def close(self):
            pass

    monkeypatch.setattr("shroodler.discovery.StaticFetcher", FakeFetcher)
    state = ProgramState(slug="lab", scope_urls=["https://example.com/"])
    result = discover(
        state,
        "https://api.example.com/",
        DiscoveryConfig(target="https://api.example.com/", skip_js_surface=True),
    )
    assert "www.example.com" in result.subdomains_found
    assert result.subdomains_added_to_state == 2
    assert "https://www.example.com/" in state.scope_urls
    assert "https://api.example.com/" in state.scope_urls
    assert "https://www.example.com/" in state.endpoints
    assert saves == ["lab"]


def test_discovery_deduplicates_existing_scope(monkeypatch):
    monkeypatch.setattr(
        "shroodler.discovery.fetch_crtsh_candidates",
        lambda apex, timeout=5.0: ["www.example.com"],
    )

    class FakeFetcher:
        def __init__(self, timeout=5.0, **kwargs):
            pass

        def fetch(self, url):
            return _fetch_result(url, 200)

        def close(self):
            pass

    monkeypatch.setattr("shroodler.discovery.StaticFetcher", FakeFetcher)
    saves: list[str] = []
    monkeypatch.setattr("shroodler.discovery.program.save", lambda state: saves.append(state.slug))
    state = ProgramState(slug="lab", scope_urls=["https://www.example.com/"])
    result = discover(
        state,
        "https://www.example.com/",
        DiscoveryConfig(target="https://www.example.com/", skip_js_surface=True),
    )
    assert result.subdomains_added_to_state == 0
    assert state.scope_urls == ["https://www.example.com/"]
    assert saves == ["lab"]


def test_skip_crtsh_flag(monkeypatch):
    calls: list[str] = []

    def boom(*args, **kwargs):
        calls.append("crtsh")
        raise AssertionError("crt.sh must not be contacted")

    monkeypatch.setattr("shroodler.discovery.fetch_crtsh_candidates", boom)
    monkeypatch.setattr("shroodler.discovery.program.save", lambda state: None)
    state = ProgramState(slug="lab")
    result = discover(
        state,
        "https://example.com/",
        DiscoveryConfig(
            target="https://example.com/",
            skip_crtsh=True,
            skip_js_surface=True,
        ),
    )
    assert calls == []
    assert result.subdomains_found == []


def test_dry_run_does_not_write_state(monkeypatch):
    monkeypatch.setattr(
        "shroodler.discovery.fetch_crtsh_candidates",
        lambda apex, timeout=5.0: ["www.example.com"],
    )

    class FakeFetcher:
        def __init__(self, timeout=5.0, **kwargs):
            pass

        def fetch(self, url):
            return _fetch_result(url, 200)

        def close(self):
            pass

    monkeypatch.setattr("shroodler.discovery.StaticFetcher", FakeFetcher)
    saves: list[str] = []
    monkeypatch.setattr(
        "shroodler.discovery.program.save",
        lambda state: saves.append("saved") or (_ for _ in ()).throw(AssertionError("save")),
    )
    state = ProgramState(slug="lab")
    result = discover(
        state,
        "https://example.com/",
        DiscoveryConfig(
            target="https://example.com/",
            skip_js_surface=True,
            dry_run=True,
        ),
    )
    assert result.subdomains_added_to_state == 1
    assert state.scope_urls == []
    assert state.endpoints == {}
    assert saves == []


def test_js_surface_adds_same_origin_endpoints(monkeypatch):
    monkeypatch.setattr(
        "shroodler.discovery.extract_endpoints",
        lambda js_text: ["/api/folders", "https://api.example.com/trpc/user.get"],
    )

    class FakeFetcher:
        def __init__(self, timeout=5.0, **kwargs):
            pass

        def fetch(self, url):
            return _fetch_result(url, 200, "fetch('/api/folders')")

        def close(self):
            pass

    monkeypatch.setattr("shroodler.discovery.StaticFetcher", FakeFetcher)
    monkeypatch.setattr("shroodler.discovery.fetch_crtsh_candidates", lambda *a, **k: [])
    monkeypatch.setattr("shroodler.discovery.program.save", lambda state: None)
    state = ProgramState(
        slug="lab",
        scans=[
            {
                "pages": [
                    {
                        "url": "https://api.example.com/",
                        "js_files": ["https://api.example.com/app.js"],
                    }
                ]
            }
        ],
    )
    result = discover(
        state,
        "https://api.example.com/",
        DiscoveryConfig(target="https://api.example.com/", skip_crtsh=True),
    )
    assert "https://api.example.com/api/folders" in result.endpoints_found
    assert "https://api.example.com/trpc/user.get" in result.endpoints_found
    assert "https://api.example.com/api/folders" in state.endpoints


def test_js_surface_filters_cross_origin(monkeypatch):
    monkeypatch.setattr(
        "shroodler.discovery.extract_endpoints",
        lambda js_text: ["https://evil.example/api/steal"],
    )

    class FakeFetcher:
        def __init__(self, timeout=5.0, **kwargs):
            pass

        def fetch(self, url):
            return _fetch_result(url, 200, "ok")

        def close(self):
            pass

    monkeypatch.setattr("shroodler.discovery.StaticFetcher", FakeFetcher)
    monkeypatch.setattr("shroodler.discovery.program.save", lambda state: None)
    state = ProgramState(
        slug="lab",
        scans=[
            {
                "pages": [
                    {
                        "url": "https://api.example.com/",
                        "js_files": ["https://api.example.com/app.js"],
                    }
                ]
            }
        ],
    )
    result = discover(
        state,
        "https://api.example.com/",
        DiscoveryConfig(target="https://api.example.com/", skip_crtsh=True),
    )
    assert result.endpoints_found == []
    assert "https://evil.example/api/steal" not in state.endpoints


def test_max_subdomains_cap(monkeypatch):
    names = [f"h{i}.example.com" for i in range(500)]
    monkeypatch.setattr(
        "shroodler.discovery.fetch_crtsh_candidates",
        lambda apex, timeout=5.0: names,
    )
    probed: list[str] = []

    def fake_probe(candidates, timeout=5.0, workers=20, enforcer=None):
        probed.extend(candidates)
        return list(candidates)

    monkeypatch.setattr("shroodler.discovery.probe_subdomains", fake_probe)
    monkeypatch.setattr("shroodler.discovery.program.save", lambda state: None)
    state = ProgramState(slug="lab")
    discover(
        state,
        "https://example.com/",
        DiscoveryConfig(
            target="https://example.com/",
            skip_js_surface=True,
            max_subdomains=300,
        ),
    )
    assert len(probed) == 300


def test_apex_domain_from_api_host():
    assert apex_domain("https://api.example.com") == "example.com"
    assert apex_domain("https://www.example.com/app") == "example.com"


def test_crtsh_timeout_returns_empty(monkeypatch):
    class BoomClient:
        def __init__(self, *args, **kwargs):
            raise httpx.TimeoutException("timed out")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr("shroodler.discovery.httpx.Client", BoomClient)
    from shroodler.discovery import fetch_crtsh_candidates

    assert fetch_crtsh_candidates("example.com", timeout=1.0) == []
