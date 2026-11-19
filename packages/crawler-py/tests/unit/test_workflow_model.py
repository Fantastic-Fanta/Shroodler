from __future__ import annotations

from types import SimpleNamespace

from shroodler.workflow_model import (
    infer_workflows,
    summarize_workflows,
    workflow_invariants,
    workflows_as_dicts,
)


def _doc(forms_by_page):
    pages = []
    for url, forms in forms_by_page.items():
        pages.append({"url": url, "forms": forms})
    return {"pages": pages}


def _form(action, method="POST", fields=()):
    return {
        "action": action,
        "method": method,
        "fields": [{"name": n} for n in fields],
    }


def test_groups_multistep_flow_and_orders_by_verb():
    doc = _doc(
        {
            "http://t/checkout": [
                _form("/checkout/confirm", fields=["card"]),
                _form("/checkout/add", fields=["item"]),
            ]
        }
    )
    wfs = infer_workflows(doc)
    assert len(wfs) == 1
    wf = wfs[0]
    assert wf.name == "checkout"
    # add (rank 0) orders before confirm (rank 3)
    assert [s.action for s in wf.steps] == ["/checkout/add", "/checkout/confirm"]
    assert wf.terminal.action == "/checkout/confirm"


def test_single_step_is_not_a_workflow():
    doc = _doc({"http://t/x": [_form("/checkout/confirm")]})
    assert infer_workflows(doc) == []


def test_get_forms_are_ignored():
    doc = _doc(
        {
            "http://t/s": [
                _form("/search", method="GET"),
                _form("/search/filter", method="GET"),
            ]
        }
    )
    assert infer_workflows(doc) == []


def test_sequence_invariant_targets_terminal_step():
    doc = _doc(
        {
            "http://t/c": [
                _form("/checkout/add"),
                _form("/checkout/pay"),
            ]
        }
    )
    invs = workflow_invariants(doc)
    assert len(invs) == 1
    inv = invs[0]
    assert inv.kind == "sequence"
    assert "/checkout/pay" in inv.statement
    assert "step-skipping" in inv.statement
    assert "/checkout/add" in inv.statement
    assert "replay" in inv.test_hint or "replay" in inv.statement


def test_no_invariant_without_a_terminal_commit_step():
    # two early-rank steps, no confirm/pay -> no confident sequence claim
    doc = _doc(
        {
            "http://t/p": [
                _form("/profile/add"),
                _form("/profile/new"),
            ]
        }
    )
    assert infer_workflows(doc)  # it is still a grouped flow
    assert workflow_invariants(doc) == []


def test_summarize_and_json():
    doc = _doc(
        {
            "http://t/c": [
                _form("/checkout/add", fields=["item"]),
                _form("/checkout/confirm", fields=["card"]),
            ]
        }
    )
    text = summarize_workflows(doc)
    assert "WORKFLOWS" in text
    assert "checkout:" in text
    assert "sequence invariants" in text
    rows = workflows_as_dicts(doc)
    assert rows[0]["name"] == "checkout"
    assert rows[0]["steps"][0]["action"] == "/checkout/add"


def test_summarize_empty_when_no_workflows():
    assert summarize_workflows({"pages": []}) == ""


def test_cmd_workflows_prints(tmp_path, capsys):
    import json

    from shroodler.cli import cmd_workflows

    scan = tmp_path / "scan.json"
    scan.write_text(
        json.dumps(
            _doc({"http://t/c": [_form("/checkout/add"), _form("/checkout/pay")]})
        ),
        encoding="utf-8",
    )
    rc = cmd_workflows(SimpleNamespace(scan=str(scan), json=False, output=None))
    assert rc == 0
    out = capsys.readouterr().out
    assert "WORKFLOWS" in out
    assert "checkout" in out


# --- state-based inference + hypothesis seeding ----------------------------

from shroodler.workflow_model import (  # noqa: E402
    infer_workflows_from_state,
    seed_workflow_hypotheses,
)


def _state_with(endpoints):
    return SimpleNamespace(endpoints=endpoints, hypotheses=[])


def test_infer_from_state_groups_mutating_endpoints():
    st = _state_with(
        {
            "http://t/checkout/add": {"method": "POST"},
            "http://t/checkout/pay": {"method": "POST"},
            "http://t/about": {"method": "GET"},  # read-only, ignored
        }
    )
    wfs = infer_workflows_from_state(st)
    assert len(wfs) == 1
    assert wfs[0].name == "checkout"
    assert wfs[0].terminal.action == "http://t/checkout/pay"


def test_seed_workflow_hypothesis_targets_terminal():
    st = _state_with(
        {
            "http://t/checkout/add": {"method": "POST"},
            "http://t/checkout/confirm": {"method": "POST"},
        }
    )
    n = seed_workflow_hypotheses(st)
    assert n == 1
    h = st.hypotheses[0]
    assert h["source"] == "world-model-workflow"
    assert h["target_url"] == "http://t/checkout/confirm"
    assert "broken" in h["hypothesis"]


def test_seed_workflow_is_idempotent():
    st = _state_with(
        {
            "http://t/checkout/add": {"method": "POST"},
            "http://t/checkout/pay": {"method": "POST"},
        }
    )
    assert seed_workflow_hypotheses(st) == 1
    assert seed_workflow_hypotheses(st) == 0
    assert len(st.hypotheses) == 1


def test_seed_workflow_skips_without_terminal_commit():
    st = _state_with(
        {
            "http://t/profile/add": {"method": "POST"},
            "http://t/profile/new": {"method": "POST"},
        }
    )
    assert seed_workflow_hypotheses(st) == 0


# --- regression: /api/ prefix grouping (found testing celestial.construction) ---

from shroodler.workflow_model import _group_key  # noqa: E402


def test_group_key_skips_api_and_version_prefixes():
    assert _group_key("/api/checkout/add") == "checkout"
    assert _group_key("/api/v2/checkout/confirm") == "checkout"
    assert _group_key("/api/me/saves") == "me"
    assert _group_key("/api/accounts/login") == "accounts"
    assert _group_key("/checkout/add") == "checkout"  # unchanged
    assert _group_key("/api") == "api"  # nothing after the prefix


def test_api_prefixed_flows_group_by_resource_not_api():
    # Regression: previously every /api/* path collapsed into one "api" workflow.
    st = _state_with(
        {
            "https://h/api/me/saves": {"method": "POST"},
            "https://h/api/me/uploads": {"method": "POST"},
            "https://h/api/accounts/login": {"method": "POST"},
            "https://h/api/accounts/logout": {"method": "POST"},
        }
    )
    names = {w.name for w in infer_workflows_from_state(st)}
    assert "api" not in names
    assert names == {"me", "accounts"}
