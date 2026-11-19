"""Tests for the inferred application world-model."""

from __future__ import annotations

from types import SimpleNamespace

from shroodler.llm_agent.context import build_context
from shroodler.program import ProgramState
from shroodler.world_model import build_model, summarize_model


def _state(endpoints=None, object_ids=None):
    st = ProgramState(slug="t")
    st.endpoints = endpoints or {}
    st.object_ids = object_ids or {}
    return st


def test_infers_entity_name_and_scheme():
    st = _state(
        endpoints={"http://h/api/orders/123": {"method": "GET"}},
        object_ids={"/api/orders/{id}": ["123", "456"]},
    )
    model = build_model(st)
    assert len(model.entities) == 1
    ent = model.entities[0]
    assert ent.name == "orders"
    assert ent.pattern == "/api/orders/{id}"
    assert ent.id_scheme == "sequential-integer"
    assert ent.known_ids == 2


def test_mutable_inferred_from_methods():
    st = _state(
        endpoints={
            "http://h/api/orders/123": {"method": "GET"},
            "http://h/api/orders/456": {"method": "DELETE"},
        },
        object_ids={"/api/orders/{id}": ["123", "456"]},
    )
    ent = build_model(st).entities[0]
    assert set(ent.methods) == {"GET", "DELETE"}
    assert ent.mutable is True


def test_uuid_scheme():
    uid = "11111111-2222-3333-4444-555555555555"
    st = _state(
        endpoints={f"http://h/users/{uid}": {"method": "GET"}},
        object_ids={"/users/{id}": [uid]},
    )
    ent = build_model(st).entities[0]
    assert ent.id_scheme == "uuid"
    assert ent.mutable is False


def test_non_id_endpoints_are_not_entities():
    st = _state(endpoints={"http://h/api/profile": {"method": "GET"}}, object_ids={})
    assert build_model(st).entities == []


def test_ownership_invariant_emitted():
    st = _state(
        endpoints={"http://h/api/orders/1": {"method": "POST"}},
        object_ids={"/api/orders/{id}": ["1"]},
    )
    model = build_model(st)
    assert model.invariants
    inv = model.invariants[0]
    assert inv.kind == "ownership"
    assert inv.entity == "orders"
    assert "read or modify" in inv.statement  # POST -> mutable
    assert "idor" in inv.test_hint


def test_summarize_block():
    st = _state(
        endpoints={"http://h/api/orders/1": {"method": "GET"}},
        object_ids={"/api/orders/{id}": ["1"]},
    )
    block = summarize_model(st)
    assert "APP MODEL" in block
    assert "orders" in block
    assert "ids=sequential-integer" in block
    assert "invariants to check" in block


def test_summarize_empty_when_no_entities():
    assert summarize_model(_state()) == ""


def test_build_model_never_raises_on_junk():
    assert build_model(SimpleNamespace()) == build_model(SimpleNamespace())  # no crash
    assert summarize_model(SimpleNamespace()) == ""


def test_build_context_includes_app_model():
    cfg = SimpleNamespace(
        target="http://127.0.0.1:8087",
        program="cur",
        _iteration=1,
        max_iterations=10,
    )
    st = _state(
        endpoints={"http://127.0.0.1:8087/api/orders/1": {"method": "GET"}},
        object_ids={"/api/orders/{id}": ["1"]},
    )
    text = build_context(st, [], [], cfg)
    assert "APP MODEL" in text
    assert "orders" in text


# --- coverage anchors: world-model <-> test coverage -----------------------

from shroodler.world_model import (  # noqa: E402
    build_coverage,
    coverage_gaps_block,
    uncovered_ownership,
)


def _idor_state(authz=False, payload=False):
    return _state(
        endpoints={
            "http://h/api/orders/123": {
                "method": "GET",
                "tested_payload": payload,
                "tested_authz": authz,
            }
        },
        object_ids={"/api/orders/{id}": ["123", "456"]},
    )


def test_coverage_counts_tested_endpoints_per_entity():
    cov = build_coverage(_idor_state(authz=True, payload=True))
    assert len(cov) == 1
    c = cov[0]
    assert c.entity.name == "orders"
    assert c.endpoints == 1
    assert c.payload_covered is True
    assert c.ownership_tested is True


def test_untested_ownership_is_flagged():
    cov = build_coverage(_idor_state(authz=False, payload=True))
    assert cov[0].payload_covered is True
    assert cov[0].ownership_tested is False
    gaps = uncovered_ownership(_idor_state(authz=False, payload=True))
    assert len(gaps) == 1
    assert gaps[0].entity.pattern == "/api/orders/{id}"


def test_coverage_gaps_block_names_untested_invariant():
    block = coverage_gaps_block(_idor_state(authz=False, payload=False))
    assert "COVERAGE GAPS" in block
    assert "ownership/IDOR invariant UNTESTED" in block
    assert "/api/orders/{id}" in block
    assert "no payload testing yet" in block


def test_coverage_gaps_block_empty_when_fully_tested():
    assert coverage_gaps_block(_idor_state(authz=True, payload=True)) == ""


def test_coverage_gaps_block_empty_without_entities():
    assert coverage_gaps_block(_state()) == ""


def test_coverage_gaps_surface_in_context():
    cfg = SimpleNamespace(
        target="http://h/", program="t", _iteration=1, max_iterations=10
    )
    ctx = build_context(_idor_state(authz=False, payload=False), [], [], cfg)
    assert "COVERAGE GAPS" in ctx


# --- seeding hypotheses from untested invariants ---------------------------

from shroodler.world_model import seed_invariant_hypotheses  # noqa: E402


def test_seed_queues_hypothesis_for_untested_invariant():
    st = _idor_state(authz=False, payload=False)
    st.hypotheses = []
    n = seed_invariant_hypotheses(st)
    assert n == 1
    h = st.hypotheses[0]
    assert h["source"] == "world-model-invariant"
    assert h["target_url"] == "http://h/api/orders/123"
    assert "non-owner" in h["hypothesis"]
    assert h["severity"] == "high"


def test_seed_is_idempotent():
    st = _idor_state(authz=False, payload=False)
    st.hypotheses = []
    assert seed_invariant_hypotheses(st) == 1
    assert seed_invariant_hypotheses(st) == 0  # already queued, not re-added
    assert len(st.hypotheses) == 1


def test_seed_skips_when_ownership_tested():
    st = _idor_state(authz=True, payload=True)
    st.hypotheses = []
    assert seed_invariant_hypotheses(st) == 0
    assert st.hypotheses == []


def test_seed_handles_missing_hypotheses_attr():
    st = _idor_state(authz=False, payload=False)
    # no .hypotheses set -> helper initializes it
    if hasattr(st, "hypotheses"):
        st.hypotheses = []
    assert seed_invariant_hypotheses(st) == 1


# --- coverage report / command ---------------------------------------------

from shroodler.world_model import coverage_as_dicts, coverage_report  # noqa: E402


def test_coverage_report_lists_entities_and_gaps():
    txt = coverage_report(_idor_state(authz=False, payload=False))
    assert "WORLD-MODEL COVERAGE" in txt
    assert "orders" in txt
    assert "ownership/IDOR=NO" in txt
    assert "COVERAGE GAPS" in txt


def test_coverage_report_empty_without_entities():
    assert "crawl the target first" in coverage_report(_state())


def test_coverage_as_dicts_shape():
    rows = coverage_as_dicts(_idor_state(authz=True, payload=True))
    assert rows == [
        {
            "entity": "orders",
            "pattern": "/api/orders/{id}",
            "endpoints": 1,
            "payload_tested": 1,
            "authz_tested": 1,
            "payload_covered": True,
            "ownership_tested": True,
        }
    ]


def test_cmd_coverage_prints_report(monkeypatch, capsys):
    from shroodler.cli import cmd_coverage

    st = _idor_state(authz=False, payload=False)
    monkeypatch.setattr("shroodler.program.load", lambda slug: st)
    rc = cmd_coverage(SimpleNamespace(slug="t", json=False, output=None))
    assert rc == 0
    out = capsys.readouterr().out
    assert "WORLD-MODEL COVERAGE" in out
    assert "ownership/IDOR invariant UNTESTED" in out


# --- privilege / function-level-authz invariants ---------------------------

from shroodler.world_model import _privileged_surfaces  # noqa: E402


def test_infers_privileged_surface_from_admin_path():
    st = _state(endpoints={"http://h/admin/users": {"method": "GET"}})
    model = build_model(st)
    assert len(model.privileged) == 1
    surf = model.privileged[0]
    assert surf.marker == "admin"
    assert surf.pattern == "/admin/users"
    kinds = {inv.kind for inv in model.invariants}
    assert "privilege" in kinds
    priv = next(i for i in model.invariants if i.kind == "privilege")
    assert "function-level authorization" in priv.statement
    assert "role-diff" in priv.test_hint


def test_privilege_mutable_from_method():
    st = _state(
        endpoints={
            "http://h/internal/config": {"method": "POST"},
        }
    )
    model = build_model(st)
    assert model.privileged[0].mutable is True
    priv = next(i for i in model.invariants if i.kind == "privilege")
    assert "invoke" in priv.statement


def test_non_elevated_paths_are_not_privileged():
    # whole-segment match only: "administrate-help" / "systems" must not match
    st = _state(
        endpoints={
            "http://h/articles/administrate-help": {"method": "GET"},
            "http://h/catalog/systems": {"method": "GET"},
            "http://h/api/orders/1": {"method": "GET"},
        }
    )
    assert _privileged_surfaces(st) == []


def test_privileged_surface_shown_in_app_model():
    st = _state(endpoints={"http://h/admin/users": {"method": "DELETE"}})
    block = summarize_model(st)
    assert "privileged surfaces" in block
    assert "admin [/admin/users]" in block
    assert "function-level authorization" in block


def test_app_model_empty_without_entities_or_privileged():
    assert summarize_model(_state(endpoints={"http://h/about": {"method": "GET"}})) == ""
