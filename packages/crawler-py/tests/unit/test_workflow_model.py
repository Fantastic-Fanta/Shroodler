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
