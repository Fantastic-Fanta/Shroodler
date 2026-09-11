from __future__ import annotations

import inspect

from shroodler import idor_engine
from shroodler.agent import AgentConfig
from shroodler.idor_engine import looks_like_idor_url
from shroodler.llm_agent.executor import execute_tool
from shroodler.llm_agent.planner import PlannerDecision, _probe_memory_block
from shroodler.llm_agent.probe_memory import (
    ProbeMemory,
    ProbeRecord,
    normalise_url,
)
from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.program import ProgramState

_TS = "2026-01-01T00:00:00Z"
_UUID = "550e8400-e29b-41d4-a716-446655440000"


def _rec(
    endpoint: str,
    probe_type: str,
    *,
    param: str | None = "q",
    result: str = "no-finding",
    finding_id: str | None = None,
) -> ProbeRecord:
    return ProbeRecord(
        endpoint_pattern=endpoint,
        probe_type=probe_type,
        param_name=param,
        result=result,
        tried_at=_TS,
        finding_id=finding_id,
    )


def test_record_then_already_tried(tmp_path):
    mem = ProbeMemory(str(tmp_path / "probe_memory.db"))
    try:
        assert mem.already_tried("/users/{id}", "sqli", "id") is False
        mem.record(_rec("/users/{id}", "sqli", param="id", result="no-finding"))
        assert mem.already_tried("/users/{id}", "sqli", "id") is True
    finally:
        mem.close()


def test_already_tried_false_before_insert():
    mem = ProbeMemory(":memory:")
    try:
        assert mem.already_tried("/search", "xss", "q") is False
    finally:
        mem.close()


def test_already_tried_false_for_error():
    mem = ProbeMemory(":memory:")
    try:
        mem.record(_rec("/search", "sqli", result="error"))
        assert mem.already_tried("/search", "sqli", "q") is False
    finally:
        mem.close()


def test_already_tried_false_for_timeout():
    mem = ProbeMemory(":memory:")
    try:
        mem.record(_rec("/search", "sqli", result="timeout"))
        assert mem.already_tried("/search", "sqli", "q") is False
    finally:
        mem.close()


def test_already_tried_true_for_finding():
    mem = ProbeMemory(":memory:")
    try:
        mem.record(
            _rec("/search", "xss", result="finding", finding_id="xss-reflected")
        )
        assert mem.already_tried("/search", "xss", "q") is True
    finally:
        mem.close()


def test_duplicate_insert_ignored():
    mem = ProbeMemory(":memory:")
    try:
        mem.record(_rec("/api/{id}", "idor", param=None, result="no-finding"))
        mem.record(
            _rec(
                "/api/{id}",
                "idor",
                param=None,
                result="finding",
                finding_id="idor-cross-account",
            )
        )
        assert mem.already_tried("/api/{id}", "idor", None) is True
        assert mem.get_productive_probes() == []
    finally:
        mem.close()


def test_none_param_name_deduped():
    mem = ProbeMemory(":memory:")
    try:
        mem.record(_rec("/jwt", "jwt", param=None, result="no-finding"))
        mem.record(_rec("/jwt", "jwt", param="", result="finding", finding_id="x"))
        assert mem.already_tried("/jwt", "jwt", None) is True
        assert mem.already_tried("/jwt", "jwt", "") is True
        assert mem.get_productive_probes() == []
    finally:
        mem.close()


def test_get_productive_probes_sorted_by_frequency():
    mem = ProbeMemory(":memory:")
    try:
        mem.record(_rec("/a", "xss", result="finding", finding_id="xss-1"))
        mem.record(_rec("/b", "xss", result="finding", finding_id="xss-2"))
        mem.record(_rec("/c", "sqli", result="finding", finding_id="sqli-1"))
        mem.record(_rec("/d", "sqli", result="no-finding"))
        assert mem.get_productive_probes() == ["xss", "sqli"]
    finally:
        mem.close()


def test_get_barren_probes_threshold():
    mem = ProbeMemory(":memory:")
    try:
        for i in range(4):
            mem.record(_rec(f"/ep{i}", "ssti", result="no-finding"))
        assert mem.get_barren_probes() == []
        mem.record(_rec("/ep4", "ssti", result="no-finding"))
        assert mem.get_barren_probes() == ["ssti"]
    finally:
        mem.close()


def test_get_barren_excludes_probes_with_a_finding():
    mem = ProbeMemory(":memory:")
    try:
        for i in range(5):
            result = "finding" if i == 0 else "no-finding"
            mem.record(
                _rec(
                    f"/ep{i}",
                    "ssrf",
                    result=result,
                    finding_id="ssrf-1" if result == "finding" else None,
                )
            )
        assert "ssrf" not in mem.get_barren_probes()
        assert "ssrf" in mem.get_productive_probes()
    finally:
        mem.close()


def test_summary_contains_tried_and_probe_types():
    mem = ProbeMemory(":memory:")
    try:
        mem.record(_rec("/a", "sqli", result="finding", finding_id="sqli-error"))
        for i in range(5):
            mem.record(_rec(f"/b{i}", "jwt", param=None, result="no-finding"))
        text = mem.summary()
        assert "tried" in text
        assert "sqli" in text
        assert "jwt" in text
        assert "productive" in text
        assert "barren" in text
    finally:
        mem.close()


def test_creates_parent_directories(tmp_path):
    db = tmp_path / "nested" / "dir" / "probe_memory.db"
    mem = ProbeMemory(str(db))
    try:
        mem.record(_rec("/x", "xss"))
        assert db.is_file()
        assert mem.already_tried("/x", "xss", "q") is True
    finally:
        mem.close()


def test_memory_path_keeps_data_on_same_connection():
    mem = ProbeMemory(":memory:")
    try:
        mem.record(_rec("/x", "xss"))
        assert mem.already_tried("/x", "xss", "q") is True
    finally:
        mem.close()


def test_normalise_url_numeric_segment():
    out = normalise_url("http://example.com/api/users/12345")
    assert "{id}" in out
    assert "12345" not in out
    assert "/v2/" in normalise_url("http://example.com/v2/users")


def test_normalise_url_uuid():
    out = normalise_url(f"http://example.com/users/{_UUID}")
    assert "{uuid}" in out
    assert _UUID not in out


def test_normalise_url_query_value():
    out = normalise_url("http://example.com/search?q=hello&page=2")
    assert "q={val}" in out
    assert "page={val}" in out
    assert "hello" not in out


def test_normalise_url_short_segment_unchanged():
    out = normalise_url("http://example.com/v2/users/12")
    assert "/v2/" in out
    assert out.endswith("/users/12") or "/users/12" in out


def test_normalise_url_token():
    token = "aB3dE5fG7hI9jK1L"
    out = normalise_url(f"http://example.com/obj/{token}")
    assert "{token}" in out
    assert token not in out


def test_idor_engine_imports_normalise_url_from_probe_memory():
    src = inspect.getsource(idor_engine)
    assert "probe_memory" in src
    assert "normalise_url" in src
    assert idor_engine.normalise_url is normalise_url
    uuid_pat = (
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{12}"
    )
    assert uuid_pat not in src
    assert looks_like_idor_url("http://127.0.0.1/api/users/123")
    assert looks_like_idor_url(f"http://127.0.0.1/api/users/{_UUID}")


def test_probe_memory_block_includes_summary():
    mem = ProbeMemory(":memory:")
    try:
        mem.record(
            _rec("/api/{id}", "sqli", result="finding", finding_id="sqli-error")
        )
        block = _probe_memory_block(mem)
        assert "<probe_memory>" in block
        assert "</probe_memory>" in block
        assert "tried" in block
        assert "sqli" in block
        assert "Productive probes" in block
        assert "Barren probes" in block
    finally:
        mem.close()


def test_execute_skips_already_tried_probe(monkeypatch):
    mem = ProbeMemory(":memory:")
    url = "http://127.0.0.1/search?q=1"
    try:
        mem.record(
            _rec(normalise_url(url), "sqli", param="q", result="no-finding")
        )

        def boom(*_a, **_k):
            raise AssertionError("must not run probe for an already-tried combo")

        monkeypatch.setattr("shroodler.probes.sqli.probe_sqli", boom)
        result = execute_tool(
            PlannerDecision(
                action="probe_sqli",
                params={"url": url, "param": "q", "method": "GET"},
            ),
            ProgramState(slug="lab"),
            AgentConfig(program="lab", target="http://127.0.0.1/"),
            None,
            None,
            Pacer(0),
            probe_memory=mem,
        )
        assert result.findings_added == 0
        assert "skipped" in result.summary.lower()
        assert result.raw_output.get("skipped") is True
    finally:
        mem.close()


def test_execute_records_finding(monkeypatch):
    mem = ProbeMemory(":memory:")
    url = "http://127.0.0.1/search"

    def fake_sqli(_url, _method, _params, _cookie, client=None, pacer=None):
        return [
            Finding(
                id="sqli-error",
                severity="high",
                category="payload",
                url=_url,
                description="error-based",
                confidence="confirmed",
            )
        ]

    monkeypatch.setattr("shroodler.probes.sqli.probe_sqli", fake_sqli)
    try:
        result = execute_tool(
            PlannerDecision(
                action="probe_sqli",
                params={"url": url, "param": "q", "method": "GET"},
            ),
            ProgramState(slug="lab"),
            AgentConfig(program="lab", target="http://127.0.0.1/"),
            None,
            None,
            Pacer(0),
            probe_memory=mem,
        )
        assert result.findings_added == 1
        assert mem.already_tried(normalise_url(url), "sqli", "q") is True
        assert "sqli" in mem.get_productive_probes()
    finally:
        mem.close()


def test_execute_without_probe_memory_still_runs(monkeypatch):
    called = {"n": 0}

    def fake_sqli(_url, _method, _params, _cookie, client=None, pacer=None):
        called["n"] += 1
        return []

    monkeypatch.setattr("shroodler.probes.sqli.probe_sqli", fake_sqli)
    result = execute_tool(
        PlannerDecision(
            action="probe_sqli",
            params={"url": "http://127.0.0.1/search", "param": "q"},
        ),
        ProgramState(slug="lab"),
        AgentConfig(program="lab", target="http://127.0.0.1/"),
        None,
        None,
        Pacer(0),
    )
    assert called["n"] == 1
    assert result.findings_added == 0
    assert "skipped" not in result.summary.lower()
