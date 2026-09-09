from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from shroodler.agent import (
    AgentConfig,
    ProbeAction,
    WafDetectAction,
    decide_next_action,
    execute_action,
)
from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.program import ProgramState
from shroodler.waf_detect import WafResult, detect_waf, finding_from_result, mutate_payload


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _endpoint() -> dict:
    return {
        "last_seen": _now(),
        "tested_authz": True,
        "tested_peer_write": True,
        "tested_payload": False,
    }


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        timeout=2.0,
        follow_redirects=False,
    )


def _detect(handler, base: str = "http://waf.test/") -> WafResult:
    async def _run() -> WafResult:
        async with _client(handler) as session:
            return await detect_waf(base, session, pacer=Pacer(0))

    return asyncio.run(_run())


def test_cloudflare_via_cf_ray_header():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"CF-RAY": "7a1b2c3d4e5f-SJC"}, text="ok")

    result = _detect(handler)
    assert result.detected is True
    assert result.vendor == "cloudflare"
    assert result.confidence == 90
    assert "CF-RAY" in result.evidence


def test_cloudflare_via_body_text():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("X-Scanner-Test"):
            return httpx.Response(403, text="Attention Required! | Cloudflare")
        return httpx.Response(200, text="ok")

    result = _detect(handler)
    assert result.detected is True
    assert result.vendor == "cloudflare"
    assert result.confidence == 70
    assert "cloudflare" in result.evidence.lower()


def test_akamai_via_header():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Via": "1.1 AkamaiGHost"}, text="ok")

    result = _detect(handler)
    assert result.detected is True
    assert result.vendor == "akamai"
    assert result.confidence == 90


def test_aws_waf_via_body():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("X-Scanner-Test"):
            return httpx.Response(403, text="Request blocked by AWS WAF")
        return httpx.Response(200, text="ok")

    result = _detect(handler)
    assert result.detected is True
    assert result.vendor == "aws"
    assert result.confidence == 70
    assert "AWS WAF" in result.evidence


def test_generic_403_on_canary():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("X-Scanner-Test"):
            return httpx.Response(403, text="Forbidden")
        return httpx.Response(200, text="ok")

    result = _detect(handler)
    assert result.detected is True
    assert result.vendor is None
    assert result.confidence == 50
    assert result.block_status == 403


def test_no_waf_clean_200():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Server": "nginx"}, text="welcome")

    result = _detect(handler)
    assert result.detected is False
    assert result.vendor is None
    assert result.confidence == 0
    assert result.block_status is None


def test_cloudflare_cf_ray_on_fingerprint_only():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("X-Scanner-Test"):
            return httpx.Response(200, text="ok")
        if "waf_test" in str(request.url):
            return httpx.Response(200, text="ok")
        return httpx.Response(200, headers={"cf-ray": "abc-IAD"}, text="ok")

    result = _detect(handler)
    assert result.detected is True
    assert result.vendor == "cloudflare"
    assert result.confidence == 90


def test_waf_result_fields_populated():
    result = WafResult(
        detected=True,
        vendor="cloudflare",
        confidence=90,
        block_status=403,
        evidence="CF-RAY header",
    )
    assert result.detected is True
    assert result.vendor == "cloudflare"
    assert result.confidence == 90
    assert result.block_status == 403
    assert result.evidence == "CF-RAY header"


def test_mutate_payload_original_first():
    original = "' OR '1'='1"
    variants = mutate_payload(original, None)
    assert variants[0] == original


def test_mutate_payload_double_url_encode():
    variants = mutate_payload("<script>alert(1)</script>", None)
    assert any("%253C" in item for item in variants)


def test_mutate_payload_case_variation():
    variants = mutate_payload("SELECT 1 FROM users", None)
    blob = " ".join(variants)
    assert "SeLeCt" in blob or "ScRiPt" in blob


def test_mutate_payload_cloudflare_svg():
    variants = mutate_payload("' OR 1=1", "cloudflare")
    assert "<svg/onload=alert(1)>" in variants


def test_mutate_payload_capped_at_eight():
    variants = mutate_payload("<script>alert(1)</script>", "cloudflare")
    assert 1 <= len(variants) <= 8


def test_mutate_payload_length_cap():
    original = "A" * 20
    for vendor in (None, "cloudflare", "akamai", "aws"):
        for item in mutate_payload(original, vendor):
            assert len(item) <= 4 * len(original)


def test_finding_from_result_validates_schema():
    detected = finding_from_result(
        WafResult(True, "cloudflare", 90, 403, "CF-RAY header"),
        "https://example.com/",
    )
    Finding.model_validate(detected.model_dump())
    assert detected.id == "waf-detected"
    assert detected.severity == "info"
    assert detected.category == "waf-challenge"
    assert detected.confidence == "confirmed"

    missed = finding_from_result(
        WafResult(False, None, 0, None, ""),
        "https://example.com/",
    )
    Finding.model_validate(missed.model_dump())
    assert missed.id == "waf-not-detected"
    assert missed.confidence == "heuristic"


def test_program_state_waf_defaults():
    state = ProgramState(slug="lab")
    assert state.waf_vendor is None
    assert state.waf_detected is False


def test_path_probe_does_not_double_slash():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, text="ok")

    _detect(handler, base="http://waf.test/")
    path_urls = [u for u in seen if "waf_test" in u]
    assert path_urls
    assert "waf.test//" not in path_urls[0]


def _live_cfg(**kwargs) -> AgentConfig:
    defaults = {
        "program": "lab",
        "target": "http://127.0.0.1/",
        "dry_run": False,
        "run_tls_check": False,
        "run_content_discovery": False,
        "run_openapi_discovery": False,
        "run_openapi_probes": False,
        "run_js_analysis": False,
    }
    defaults.update(kwargs)
    return AgentConfig(**defaults)


def test_decide_waf_detect_after_crawl_when_not_dry_run():
    state = ProgramState(
        slug="lab",
        endpoints={"http://127.0.0.1/a": _endpoint()},
    )
    action = decide_next_action(state, _live_cfg())
    assert isinstance(action, WafDetectAction)


def test_decide_skips_waf_detect_when_disabled():
    state = ProgramState(
        slug="lab",
        endpoints={"http://127.0.0.1/a": _endpoint()},
    )
    action = decide_next_action(state, _live_cfg(run_waf_detect=False, run_probes=True))
    assert isinstance(action, ProbeAction)


def test_decide_skips_waf_detect_in_dry_run():
    state = ProgramState(
        slug="lab",
        endpoints={"http://127.0.0.1/a": _endpoint()},
    )
    action = decide_next_action(state, _live_cfg(dry_run=True, run_probes=True))
    assert isinstance(action, ProbeAction)


def test_execute_waf_detect_sets_state(monkeypatch):
    async def fake_detect(base, session, pacer=None):
        return WafResult(True, "cloudflare", 90, None, "CF-RAY header")

    monkeypatch.setattr("shroodler.waf_detect.detect_waf", fake_detect)
    state = ProgramState(slug="lab")
    result = execute_action(
        WafDetectAction(),
        state,
        _live_cfg(),
        pacer=Pacer(0),
    )
    assert state.waf_detected is True
    assert state.waf_vendor == "cloudflare"
    assert result["waf_detected"] is True
    ids = {f.id for f in state.findings}
    assert "waf-detected" in ids
    Finding.model_validate(state.findings[0].model_dump())


def test_sqli_mutates_when_waf_detected(monkeypatch):
    from shroodler.probes.sqli import probe_sqli

    injected: list[str] = []

    def fake_inject(url, method, params, name, payload, **kw):
        injected.append(payload)

        class Resp:
            status_code = 200
            text = ""
            content = b""
            elapsed = 0.01

        return Resp()

    monkeypatch.setattr("shroodler.probes.sqli.inject", fake_inject)
    monkeypatch.setattr("shroodler.probes.sqli.request", lambda *a, **k: None)
    state = ProgramState(slug="lab", waf_detected=True, waf_vendor="cloudflare")
    probe_sqli(
        "http://127.0.0.1/q",
        "GET",
        [{"name": "q", "value": "1", "in": "query"}],
        "",
        state=state,
    )
    assert injected
    assert "<svg/onload=alert(1)>" in injected or any("%253C" in p or "SeLeCt" in p for p in injected)
    assert len(injected) > 4
