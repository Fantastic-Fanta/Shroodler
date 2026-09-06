from __future__ import annotations

import argparse
import threading
from wsgiref.simple_server import make_server

from shroodler.cli import cmd_reverify
from shroodler.reverify import reverify


def test_verified_fixed_when_finding_no_longer_present(fx):
    fx.on("GET", "/search", lambda inc: (200, {}, b"<html>no injection here</html>"))
    result = reverify(fx.origin + "/search", "payload-sql-error", run_payloads=False)
    assert result["verified_fixed"] is True
    assert result["still_present"] is False
    assert result["matching_findings"] == []


def test_still_present_when_finding_reappears(fx):
    fx.on(
        "GET",
        "/leak",
        lambda inc: (200, {"X-Powered-By": "PHP/5.2.1"}, b"ok"),
    )
    result = reverify(fx.origin + "/leak", "x-powered-by", run_payloads=False)
    assert result["still_present"] is True
    assert result["verified_fixed"] is False
    assert result["matching_findings"][0]["id"] == "x-powered-by"


def test_matches_only_the_same_url_path(fx):
    fx.on("GET", "/a", lambda inc: (200, {"X-Powered-By": "PHP"}, b"ok"))
    fx.on("GET", "/b", lambda inc: (200, {}, b"ok"))
    # Reverifying /b should not be confused by an unrelated finding at /a.
    result = reverify(fx.origin + "/b", "x-powered-by", run_payloads=False)
    assert result["verified_fixed"] is True


def test_no_query_string_warns_for_payload_findings(fx):
    fx.on("GET", "/search", lambda inc: (200, {}, b"clean"))
    result = reverify(fx.origin + "/search", "payload-sql-error", run_payloads=False)
    # run_payloads=False means no active re-scan happened at all -- the
    # warning is specifically about the active-payload re-run's ability
    # to rediscover query parameters, so it's conditioned on run_payloads.
    assert result["warnings"] == []


def test_no_query_string_warns_when_payloads_run(fx):
    fx.on("GET", "/search", lambda inc: (200, {}, b"clean"))
    result = reverify(fx.origin + "/search", "payload-sql-error", run_payloads=True)
    assert any("query string" in w for w in result["warnings"])


def test_query_string_present_does_not_warn(fx):
    fx.on("GET", "/search", lambda inc: (200, {}, b"clean"))
    result = reverify(fx.origin + "/search?q=x", "payload-sql-error", run_payloads=True)
    assert result["warnings"] == []


def test_warns_regardless_of_finding_id_prefix(fx):
    # Deliberately not scoped to ids that look like built-in
    # "payload-*" findings -- a custom pack's id might not follow that
    # convention and would otherwise be silently exempted from a
    # warning that's just as relevant to it.
    fx.on("GET", "/search", lambda inc: (200, {}, b"clean"))
    result = reverify(fx.origin + "/search", "missing-hsts", run_payloads=True)
    assert any("query string" in w for w in result["warnings"])


def test_active_rerun_still_detects_a_second_vulnerable_param_sharing_one_pack(fx):
    # Two query params on the same page both trip the SAME pack (so they
    # share one finding_id). If only one is fixed, the active re-run
    # must still report still_present=True: it re-fuzzes EVERY parameter
    # the page exposes, not just whichever one the caller happens to
    # remember -- this is what makes reverify() safe against the
    # "which param was it again" ambiguity the finding-id-per-pack
    # design would otherwise create. Only vuln_param reflects its input
    # verbatim (a real `reflected: true` match); safe_param never does.
    # (Uses a raw WSGI app, not the `fx` fixture -- FixtureServer's `.on()`
    # handlers only see the path, not the query string.)
    def app(environ, start_response):
        from urllib.parse import parse_qs

        qs = parse_qs(environ.get("QUERY_STRING", ""))
        vuln_value = qs.get("vuln_param", [""])[0]
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [f"echo: {vuln_value}".encode()]

    httpd = make_server("127.0.0.1", 0, app)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        result = reverify(
            f"http://127.0.0.1:{port}/search?safe_param=1&vuln_param=2",
            "payload-xss-reflect",
            run_payloads=True,
        )
    finally:
        httpd.shutdown()
    assert result["still_present"] is True


def test_cmd_reverify_prints_warnings_to_stderr(fx, capsys):
    fx.on("GET", "/search", lambda inc: (200, {}, b"clean"))
    ns = argparse.Namespace(
        url=fx.origin + "/search",
        finding_id="payload-sql-error",
        mode="static",
        allow_external=False,
        no_payloads=False,
        output=None,
    )
    assert cmd_reverify(ns) == 0
    assert "warning:" in capsys.readouterr().err
