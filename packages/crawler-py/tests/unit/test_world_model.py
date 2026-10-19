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
