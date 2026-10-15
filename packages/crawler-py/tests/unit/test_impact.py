from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

from shroodler.impact import annotate_impact, prove_sqli
from shroodler.pacer import Pacer


class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.elapsed = timedelta(seconds=0.0)
        self.headers = {}


class FakeClient:
    def __init__(self, handler):
        self.handler = handler

    def request(self, method, url, **kw):
        vals = []
        for key in ("params", "data"):
            blob = kw.get(key) or {}
            if isinstance(blob, dict):
                vals.extend(str(v) for v in blob.values())
        return self.handler(" ".join(vals))

    def close(self):
        pass


def _vuln_handler(value: str) -> FakeResp:
    # A real DB concatenates the split sentinel halves and appends version().
    if "SHRDLR" in value and "IMPACT" in value and ("concat" in value or "extractvalue" in value):
        return FakeResp(200, "<p>result: SHRDLRIMPACTMySQL-8.0.33-log</p>")
    return FakeResp(200, "<p>no rows</p>")


def _reflecting_handler(value: str) -> FakeResp:
    # Only reflects the raw payload (sentinel halves stay separate) -> no join.
    return FakeResp(200, f"<p>you searched for {value}</p>")


def test_prove_sqli_extracts_version():
    proof = prove_sqli(
        "http://t/search", "q", client=FakeClient(_vuln_handler), pacer=Pacer(0)
    )
    assert proof is not None
    assert "MySQL-8.0.33" in proof


def test_prove_sqli_no_false_positive_on_reflection():
    # A reflecting-but-not-injectable endpoint must not yield a proof.
    proof = prove_sqli(
        "http://t/search", "q", client=FakeClient(_reflecting_handler), pacer=Pacer(0)
    )
    assert proof is None


def test_prove_sqli_requires_url_and_param():
    assert prove_sqli("", "q", client=FakeClient(_vuln_handler), pacer=Pacer(0)) is None
    assert prove_sqli("http://t/x", "", client=FakeClient(_vuln_handler), pacer=Pacer(0)) is None


def test_annotate_impact_annotates_confirmed_sqli():
    finding = SimpleNamespace(
        id="sqli",
        confidence="confirmed",
        url="http://t/search",
        evidence="param=q payload=\"'\"",
    )
    n = annotate_impact([finding], client=FakeClient(_vuln_handler), pacer=Pacer(0))
    assert n == 1
    assert "IMPACT:" in finding.evidence
    assert "MySQL-8.0.33" in finding.evidence


def test_annotate_impact_skips_non_sqli_and_unconfirmed():
    xss = SimpleNamespace(
        id="xss-reflected", confidence="confirmed", url="http://t/", evidence="param=q"
    )
    heuristic = SimpleNamespace(
        id="sqli", confidence="heuristic", url="http://t/", evidence="param=q"
    )
    assert annotate_impact([xss, heuristic], client=FakeClient(_vuln_handler), pacer=Pacer(0)) == 0


def test_annotate_impact_skips_when_no_param_in_evidence():
    finding = SimpleNamespace(
        id="sqli", confidence="confirmed", url="http://t/", evidence="no param here"
    )
    assert annotate_impact([finding], client=FakeClient(_vuln_handler), pacer=Pacer(0)) == 0
