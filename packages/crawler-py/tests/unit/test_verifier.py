from __future__ import annotations

from types import SimpleNamespace

from shroodler.verifier import (
    verdict_as_dict,
    verify_finding,
    verify_findings,
)


def _f(**kw):
    base = {
        "id": "payload-xss",
        "severity": "high",
        "category": "payload",
        "url": "http://t/s?q=1",
        "description": "reflected",
        "evidence": "payload reflected into page",
        "confidence": "confirmed",
    }
    base.update(kw)
    return base


def test_scan_note_is_refuted():
    v = verify_finding(_f(id="cors-skipped", category="scan-note"))
    assert v.stands is False
    assert v.strength == "refuted"
    assert v.suggested_severity == "info"


def test_evidence_bound_finding_is_proven():
    proof = {"url": "http://t/s?q=1", "quotes": [{"source": "response", "text": "X"}]}
    v = verify_finding(_f(verified=True, proof=proof, evidence="SHRDLRIMPACT8.0"))
    assert v.strength == "proven"
    assert v.stands is True
    assert v.counterarguments == []


def test_confirmed_without_proof_is_solid_but_flagged():
    v = verify_finding(_f(confidence="confirmed", id="sqli", evidence="db error"))
    assert v.strength == "solid"
    assert v.stands is True
    assert any("not evidence-bound" in a for a in v.counterarguments)


def test_heuristic_high_severity_is_weak_and_downgraded():
    v = verify_finding(
        _f(id="missing-csp", category="header", confidence="heuristic", severity="high")
    )
    assert v.strength == "weak"
    assert v.suggested_severity == "medium"
    assert any("passive heuristic" in a for a in v.counterarguments)


def test_reflected_not_executed_is_weak():
    v = verify_finding(
        _f(id="xss-reflected", confidence="heuristic", evidence="value reflected in body")
    )
    assert v.strength == "weak"
    assert any("not shown to execute" in a for a in v.counterarguments)


def test_reflected_but_proven_execution_is_not_downgraded():
    proof = {"url": "http://t/s?q=1", "quotes": [{"source": "request", "text": "s-x"}]}
    v = verify_finding(
        _f(id="xss-reflected", verified=True, proof=proof, evidence="executed alert() fired")
    )
    assert v.strength == "proven"


def test_waf_interstitial_is_flagged_and_weak():
    v = verify_finding(
        _f(id="sqli", category="waf-challenge", evidence="Cloudflare attention required")
    )
    assert v.strength == "weak"
    assert any("WAF" in a for a in v.counterarguments)


def test_waf_caveat_applies_even_to_evidence_bound():
    proof = {"url": "http://t/x", "quotes": [{"source": "response", "text": "challenge"}]}
    v = verify_finding(
        _f(id="sqli", verified=True, proof=proof, evidence="cloudflare challenge page")
    )
    assert v.strength == "weak"
    assert v.stands is True


def test_verify_finding_accepts_objects():
    obj = SimpleNamespace(
        id="sqli",
        severity="high",
        category="payload",
        url="http://t/x",
        evidence="db error",
        confidence="confirmed",
        verified=False,
        proof=None,
    )
    v = verify_finding(obj)
    assert v.finding_id == "sqli"
    assert v.strength == "solid"


def test_verify_findings_batch_and_dict():
    verdicts = verify_findings([_f(), _f(id="note", category="scan-note")])
    assert len(verdicts) == 2
    d = verdict_as_dict(verdicts[0])
    assert set(d) == {
        "finding_id",
        "url",
        "stands",
        "strength",
        "suggested_severity",
        "counterarguments",
        "reason",
    }


def test_cmd_verify_text_and_exit(tmp_path, capsys):
    import json

    from shroodler.cli import cmd_verify

    scan = tmp_path / "scan.json"
    scan.write_text(
        json.dumps(
            {
                "findings": [
                    _f(id="sqli", confidence="confirmed"),
                    {"id": "cors-skipped", "category": "scan-note", "url": "http://t/",
                     "severity": "info", "description": "skipped", "evidence": ""},
                ]
            }
        ),
        encoding="utf-8",
    )
    rc = cmd_verify(
        SimpleNamespace(scan=str(scan), flagged=False, json=False, output=None)
    )
    out = capsys.readouterr().out
    assert "ADVERSARIAL VERIFICATION" in out
    assert "REFUTED" in out
    assert rc == 1  # a scan-note was refuted outright
