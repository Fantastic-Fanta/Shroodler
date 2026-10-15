"""In-repo recall gate: prove the deterministic probes still find planted bugs.

The real planted-bug labs live in the private Shroodler-Tests submodule, which
CI does not check out, so end-to-end detection recall was never gated. This
test stands up a tiny intentionally-vulnerable WSGI app (stdlib only -- no
browser, LLM, Docker, or submodule), runs the deterministic probes against it,
and scores the findings through the real eval_harness. If a change regresses a
probe so a planted bug is missed, recall drops below 1.0 and CI fails.
"""

from __future__ import annotations

import threading
from wsgiref.simple_server import WSGIServer, make_server

import pytest

from shroodler import eval_harness as ev
from shroodler.pacer import Pacer
from shroodler.probes.path_traversal import probe_path_traversal
from shroodler.probes.sqli import probe_sqli
from shroodler.probes.xss import probe_xss


def _vuln_app(environ, start_response):
    from urllib.parse import parse_qs

    path = environ.get("PATH_INFO", "")
    qs = parse_qs(environ.get("QUERY_STRING", ""))

    def respond(body: str, ctype: str = "text/plain"):
        start_response("200 OK", [("Content-Type", ctype)])
        return [body.encode()]

    if path == "/sqli":
        q = (qs.get("q") or [""])[0]
        if "'" in q:
            # Error-based SQLi: a DB error only on a quote, absent from baseline.
            return respond("You have an error in your SQL syntax near '" + q + "'")
        return respond("ok")
    if path == "/xss":
        q = (qs.get("q") or [""])[0]
        # Reflect the value verbatim into an HTML response (reflected XSS).
        return respond(f"<html><body>results for {q}</body></html>", "text/html")
    if path == "/lfi":
        f = (qs.get("file") or [""])[0]
        if "etc/passwd" in f:
            return respond("root:x:0:0:root:/root:/bin/sh\n")
        return respond("not found")
    return respond("home")


@pytest.fixture
def origin():
    httpd: WSGIServer = make_server("127.0.0.1", 0, _vuln_app)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_probes_recall_planted_bugs(origin):
    pacer = Pacer(0)
    q = [{"name": "q", "value": "x"}]
    f = [{"name": "file", "value": "x"}]
    findings = []
    findings += probe_sqli(f"{origin}/sqli", "GET", q, "", pacer=pacer)
    findings += probe_xss(f"{origin}/xss", "GET", q, "", pacer=pacer)
    findings += probe_path_traversal(f"{origin}/lfi", f, "", pacer=pacer)

    ids = {f.id for f in findings}
    # Each planted class must be found, confirmed.
    assert "sqli" in ids
    assert "xss-reflected" in ids
    assert "path-traversal" in ids

    # Score through the real harness: recall must be perfect against the
    # curated ground truth (this is the gate).
    actual = {"findings": [{"id": f.id, "url": f.url} for f in findings]}
    expected = {
        "expected_findings": [
            {"id": "sqli", "url": f"{origin}/sqli"},
            {"id": "xss-reflected", "url": f"{origin}/xss"},
            {"id": "path-traversal", "url": f"{origin}/lfi"},
        ]
    }
    card = ev.score(actual, expected, label="in-repo-recall")
    assert card.recall == 1.0, f"recall {card.recall}; missed {card.missed}"
