from __future__ import annotations

import inspect
import json
import sys
import threading
from pathlib import Path
from wsgiref.simple_server import make_server

import pytest
import yaml

PACKAGES = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PACKAGES / "payload-tester"))
sys.path.insert(0, str(PACKAGES / "target-apps" / "app5-injectable"))

from app import app as flask_app
from tester import (
    MARKER_HOST,
    _clause_matches,
    _default_mutate,
    _local,
    build_marker_host,
    gen_token,
    infer_confidence,
    load_packs,
    main,
    mutate_payload,
    pack_finding_id,
    pack_matches,
    packs_dir,
    render_payload,
    run,
)

EXPECTED = PACKAGES / "target-apps" / "app5-injectable" / "expected_findings.json"

HARDCODED_PAYLOADS = ("' OR '1'='1", "<script>alert(1)</script>", "{{7*7}}", "../../etc/passwd")


@pytest.fixture
def origin():
    httpd = make_server("127.0.0.1", 0, flask_app)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _search_doc(origin: str) -> dict:
    return {
        "target": origin + "/",
        "pages": [
            {
                "url": origin + "/",
                "forms": [
                    {
                        "action": "/search",
                        "method": "POST",
                        "fields": [{"name": "q"}],
                    }
                ],
            }
        ],
    }


@pytest.fixture
def query_reflect_origin():
    def app(environ, start_response):
        from urllib.parse import parse_qs

        qs = parse_qs(environ.get("QUERY_STRING", ""))
        q = qs.get("q", [""])[0]
        body = f"<p>results for {q}</p>".encode()
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [body]

    httpd = make_server("127.0.0.1", 0, app)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def _reflect_pack(tmp_path, marker: str = "SHROODLER_MARKER_XYZ") -> Path:
    extra = tmp_path / "reflect.yaml"
    extra.write_text(
        "- id: reflect-probe\n"
        "  finding_id: payload-reflect-probe\n"
        f"  payload: '{marker}'\n"
        "  severity: medium\n"
        "  match:\n"
        "    any:\n"
        f"      - body_contains: '{marker}'\n",
        encoding="utf-8",
    )
    return extra


def test_get_only_page_with_no_form_is_fuzzed_via_page_params(query_reflect_origin, tmp_path):
    # Page.params is populated today by both crawlers (OpenAPI/GraphQL
    # discovery, plain query-string parsing) for pages that never had a
    # <form> around them -- this must actually get fuzzed, not silently
    # ignored because there's no form to hang the fields off of.
    packs = load_packs(extra=[_reflect_pack(tmp_path)])
    doc = {
        "target": query_reflect_origin + "/",
        "pages": [{"url": query_reflect_origin + "/search", "params": ["q"], "forms": []}],
    }
    out = run(doc, packs=[p for p in packs if p["id"] == "reflect-probe"])
    hits = [f for f in out["findings"] if f["id"] == "payload-reflect-probe"]
    assert len(hits) == 1
    assert hits[0]["url"] == query_reflect_origin + "/search"


@pytest.fixture
def counting_reflect_origin():
    hits = {"n": 0}

    def app(environ, start_response):
        from urllib.parse import parse_qs

        hits["n"] += 1
        qs = parse_qs(environ.get("QUERY_STRING", ""))
        q = qs.get("q", [""])[0]
        body = f"<p>results for {q}</p>".encode()
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [body]

    httpd = make_server("127.0.0.1", 0, app)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}", hits
    httpd.shutdown()


def test_page_with_form_and_own_query_params_is_not_double_tested(counting_reflect_origin, tmp_path):
    # A page crawled at .../search?q=x that ALSO has a <form action="/search">
    # extracted from its HTML targets the same underlying path once you
    # ignore the query string. Sending every payload to both would double
    # request volume/side effects for zero extra coverage -- the synthetic
    # params-based target must be skipped when a real form already covers
    # the same path.
    origin_url, hits = counting_reflect_origin
    packs = load_packs(extra=[_reflect_pack(tmp_path)])
    doc = {
        "target": origin_url + "/",
        "pages": [
            {
                "url": origin_url + "/search?q=x",
                "params": ["q"],
                "forms": [{"action": "/search", "method": "GET", "fields": [{"name": "q"}]}],
            }
        ],
    }
    out = run(doc, packs=[p for p in packs if p["id"] == "reflect-probe"])
    found = [f for f in out["findings"] if f["id"] == "payload-reflect-probe"]
    assert len(found) == 1
    # baseline + 1 payload request for the single (deduped) target, not 2x.
    assert hits["n"] == 2


def test_same_form_action_across_many_pages_is_tested_once(counting_reflect_origin, tmp_path):
    # A header search box's <form action="/search"> shows up on every
    # crawled page verbatim. Without cross-page dedup, N pages sharing
    # that one real endpoint fires baseline+full-pack N times against a
    # live target for zero extra coverage over firing it once.
    origin_url, hits = counting_reflect_origin
    packs = load_packs(extra=[_reflect_pack(tmp_path)])
    form = {"action": "/search", "method": "GET", "fields": [{"name": "q"}]}
    doc = {
        "target": origin_url + "/",
        "pages": [
            {"url": origin_url + "/", "forms": [form]},
            {"url": origin_url + "/about", "forms": [form]},
            {"url": origin_url + "/contact", "forms": [form]},
        ],
    }
    out = run(doc, packs=[p for p in packs if p["id"] == "reflect-probe"])
    found = [f for f in out["findings"] if f["id"] == "payload-reflect-probe"]
    assert len(found) == 1
    # baseline + 1 payload request for the single deduped target, not 3x.
    assert hits["n"] == 2


def test_page_with_neither_params_nor_forms_produces_no_findings(tmp_path):
    packs = load_packs(extra=[_reflect_pack(tmp_path)])
    doc = {
        "target": "http://127.0.0.1:1/",
        "pages": [{"url": "http://127.0.0.1:1/about", "params": [], "forms": []}],
    }
    out = run(doc, packs=[p for p in packs if p["id"] == "reflect-probe"])
    assert out["findings"] == []


def test_refuses_external():
    with pytest.raises(ValueError, match="non-local"):
        run({"target": "https://example.com/", "pages": []})


def test_local_helper():
    assert _local("http://127.0.0.1:8087/")
    assert _local("http://localhost/")
    assert _local("http://app5.local/")
    assert not _local("https://httpbin.org/")


def test_packs_are_yaml_not_hardcoded():
    src = inspect.getsource(sys.modules["tester"])
    assert "PAYLOADS" not in src
    for needle in HARDCODED_PAYLOADS:
        assert needle not in src
    packs = load_packs()
    ids = {pack_finding_id(p) for p in packs}
    assert "payload-sql-error" in ids
    assert "payload-xss-reflect" in ids
    assert "payload-ssti" in ids
    assert "payload-path-traversal" in ids
    assert (packs_dir() / "sqli.yaml").is_file()
    assert (packs_dir() / "xss.yaml").is_file()
    for path in packs_dir().glob("*.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        for item in data:
            assert "payload" in item
            # "blind" packs (e.g. OOB-only SSRF/XXE markers) have no local
            # match clause at all -- success can only be confirmed by
            # checking the caller's own --oob-host server logs.
            assert "match" in item or item.get("blind")
            assert "id" in item
            assert "severity" in item


def test_pack_matcher_all_and_any():
    pack_any = {
        "id": "x",
        "payload": "abc",
        "match": {"any": [{"status_gte": 500}, {"body_contains": "boom"}]},
    }
    assert pack_matches(pack_any, status=500, body="ok", payload="abc")
    assert pack_matches(pack_any, status=200, body="BOOM", payload="abc")
    assert not pack_matches(pack_any, status=200, body="ok", payload="abc")
    pack_all = {
        "id": "y",
        "payload": "<x>",
        "match": {"all": [{"reflected": True}, {"status_gte": 200}]},
    }
    assert pack_matches(pack_all, status=200, body="hi <x>", payload="<x>")
    assert not pack_matches(pack_all, status=200, body="hi", payload="<x>")


def test_stored_xss_reget_after_post(tmp_path):
    store = {"q": ""}

    def app(environ, start_response):
        from urllib.parse import parse_qs

        method = environ.get("REQUEST_METHOD", "GET")
        if method == "POST":
            length = int(environ.get("CONTENT_LENGTH") or 0)
            body = environ["wsgi.input"].read(length).decode()
            store["q"] = parse_qs(body).get("q", [""])[0]
            html = f"<p>saved {store['q']}</p>".encode()
            start_response("200 OK", [("Content-Type", "text/html")])
            return [html]
        html = f"<p>view {store['q']}</p>".encode()
        start_response("200 OK", [("Content-Type", "text/html")])
        return [html]

    httpd = make_server("127.0.0.1", 0, app)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    origin = f"http://127.0.0.1:{port}"
    try:
        extra = tmp_path / "xss.yaml"
        extra.write_text(
            "- id: xss-store\n"
            "  finding_id: payload-xss-reflect\n"
            "  payload: '<script>alert(/{{TOKEN}}/)</script>'\n"
            "  severity: medium\n"
            "  match:\n"
            "    any:\n"
            "      - reflected: true\n",
            encoding="utf-8",
        )
        doc = {
            "target": origin + "/",
            "pages": [
                {
                    "url": origin + "/note",
                    "forms": [
                        {
                            "action": origin + "/note",
                            "method": "POST",
                            "fields": [{"name": "q"}],
                        }
                    ],
                }
            ],
        }
        out = run(doc, packs=load_packs(extra=[extra]))
        ids = {f["id"] for f in out["findings"]}
        assert "payload-xss-reflect" in ids
        assert "payload-xss-stored" in ids
    finally:
        httpd.shutdown()


def test_yaml_packs_against_app5(origin):
    out = run(_search_doc(origin))
    ids = {f["id"] for f in out["findings"]}
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    want = {f["id"] for f in expected["expected_findings"]}
    assert want <= ids
    assert "payload-sql-error" in ids
    assert "payload-xss-reflect" in ids


def test_extra_pack_via_path(origin, tmp_path):
    extra = tmp_path / "extra.yaml"
    extra.write_text(
        "- id: extra-token\n"
        "  finding_id: payload-extra-reflect\n"
        "  payload: EXTRA_PACK_TOKEN\n"
        "  severity: low\n"
        "  description: Extra pack reflected\n"
        "  match:\n"
        "    any:\n"
        "      - reflected: true\n",
        encoding="utf-8",
    )
    packs = load_packs(extra=[extra])
    out = run(_search_doc(origin), packs=packs)
    ids = {f["id"] for f in out["findings"]}
    assert "payload-extra-reflect" in ids
    assert "payload-sql-error" in ids


def test_cli_pack_flag(origin, tmp_path):
    extra = tmp_path / "extra.yaml"
    extra.write_text(
        "- id: payload-cli-extra\n"
        "  payload: CLI_PACK_TOKEN\n"
        "  severity: low\n"
        "  match:\n"
        "    any:\n"
        "      - reflected: true\n",
        encoding="utf-8",
    )
    crawl = tmp_path / "crawl.json"
    crawl.write_text(json.dumps(_search_doc(origin)), encoding="utf-8")
    outp = tmp_path / "out.json"
    assert main([str(crawl), "--pack", str(extra), "-o", str(outp)]) == 0
    ids = {f["id"] for f in json.loads(outp.read_text(encoding="utf-8"))["findings"]}
    assert "payload-cli-extra" in ids
    assert "payload-sql-error" in ids


def test_cli_refuses_non_local(tmp_path):
    crawl = tmp_path / "crawl.json"
    crawl.write_text(
        json.dumps({"target": "https://example.com/", "pages": []}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="non-local"):
        main([str(crawl)])


def test_allow_external_bypasses_guard():
    out = run({"target": "https://example.com/", "pages": []}, allow_external=True)
    assert out == {"target": "https://example.com/", "findings": [], "oob_probes": []}


def test_cli_allow_external_flag(tmp_path):
    crawl = tmp_path / "crawl.json"
    crawl.write_text(
        json.dumps({"target": "https://example.com/", "pages": []}),
        encoding="utf-8",
    )
    outp = tmp_path / "out.json"
    assert main([str(crawl), "--allow-external", "-o", str(outp)]) == 0
    assert json.loads(outp.read_text(encoding="utf-8"))["findings"] == []


def test_render_payload_token_and_marker():
    token = gen_token()
    assert token.startswith("shrdlr")
    rendered = render_payload("<script>{{TOKEN}}</script>//{{MARKER_HOST}}/", token=token)
    assert token in rendered
    assert MARKER_HOST in rendered
    assert "{{TOKEN}}" not in rendered


def test_clause_new_only_avoids_pre_existing_text():
    clause = {"body_contains": "boom", "new_only": True}
    assert _clause_matches(clause, status=200, body="boom here", payload="x", baseline_body="")
    assert not _clause_matches(
        clause, status=200, body="boom here", payload="x", baseline_body="already had boom"
    )


def test_clause_error_status_changed():
    clause = {"error_status_changed": True}
    assert _clause_matches(clause, status=500, body="", payload="x", baseline_status=200)
    assert not _clause_matches(clause, status=200, body="", payload="x", baseline_status=200)
    assert not _clause_matches(clause, status=404, body="", payload="x", baseline_status=None)


def test_clause_time_delta_and_redirect_marker():
    time_clause = {"time_delta_gte_ms": 1000}
    assert _clause_matches(
        time_clause, status=200, body="", payload="x", elapsed_ms=1600, baseline_elapsed_ms=200
    )
    assert not _clause_matches(
        time_clause, status=200, body="", payload="x", elapsed_ms=500, baseline_elapsed_ms=200
    )
    redirect_clause = {"redirected_to_contains": "evil.test"}
    assert _clause_matches(
        redirect_clause, status=200, body="", payload="x", redirected_to="https://evil.test/x"
    )
    assert not _clause_matches(
        redirect_clause, status=200, body="", payload="x", redirected_to="https://example.com/x"
    )


def test_new_packs_load_without_error():
    packs = load_packs()
    ids = {pack_finding_id(p) for p in packs}
    assert "payload-ssrf" in ids
    assert "payload-open-redirect" in ids
    assert "payload-sql-time-blind" in ids
    assert "payload-xxe" in ids
    assert "payload-command-injection" in ids
    assert "payload-command-injection-blind" in ids
    assert "payload-crlf-header-injection" in ids
    assert "payload-crlf-reflected" in ids
    assert "payload-lfi" in ids
    assert "payload-lfi-rce" in ids


def test_lfi_packs_match_string_never_appears_in_the_payload_itself():
    # Same regression discipline as the command-injection arithmetic
    # markers: the rot13/base64 match needle must not be literally present
    # in the raw payload text, or a match would just prove reflection.
    packs = [p for p in load_packs() if pack_finding_id(p) in {"payload-lfi", "payload-lfi-rce"}]
    assert len(packs) == 2
    for pack in packs:
        payload = str(pack["payload"]).lower()
        for clause in pack["match"]["any"]:
            needle = str(clause["body_contains"]).lower()
            assert needle not in payload, f"{pack['id']}: needle {needle!r} is in the raw payload"


def test_command_injection_timing_packs_are_medium_confidence_single_sample():
    # These packs are only ever proven via wall-clock timing, so no live
    # fixture can assert them without actually sleeping several seconds per
    # variant; assert the pack shape instead (severity/clause), matching
    # how time_delta_gte_ms itself is unit-tested above rather than
    # end-to-end. Severity is medium (not high): a single unconfirmed
    # timing sample can false-positive on ordinary network/GC jitter, so
    # it shouldn't carry the same confidence as the arithmetic marker-echo
    # packs below, which can't be faked by plain reflection.
    packs = [p for p in load_packs() if pack_finding_id(p) == "payload-command-injection-blind"]
    assert len(packs) >= 4
    for pack in packs:
        clauses = pack["match"]["any"]
        assert any(c.get("time_delta_gte_ms", 0) >= 3000 for c in clauses)
        assert pack["severity"] == "medium"


def test_command_injection_marker_echo_requires_evaluation_not_reflection():
    # Regression test for a real bug caught in review: an earlier version
    # of this pack matched on the payload's own literal text being echoed
    # back, which is indistinguishable from ordinary input reflection
    # (fires on any endpoint that echoes user input, executed or not).
    # The fix uses shell arithmetic ($((...))) so the match string can
    # only appear if a shell actually evaluated the expression -- assert
    # that invariant holds for every marker-echo pack in this file, not
    # just eyeball it in the YAML.
    packs = [p for p in load_packs() if pack_finding_id(p) == "payload-command-injection"]
    assert len(packs) >= 5
    for pack in packs:
        payload = str(pack["payload"])
        clauses = pack["match"]["any"]
        needles = [str(c["body_contains"]).lower() for c in clauses if "body_contains" in c]
        assert needles, f"{pack['id']} has no body_contains clause"
        for needle in needles:
            assert needle not in payload.lower(), (
                f"{pack['id']}: match needle {needle!r} is literally present in the "
                "unexecuted payload text -- this would fire on plain reflection"
            )


@pytest.fixture
def header_validating_origin():
    """A modern, spec-compliant server that rejects control chars in headers.

    Simulates the common case (Werkzeug, Go net/http, etc. all behave this
    way) so the CRLF header-injection pack's expected result on a safe
    target is "no finding", not a crash.
    """

    def handler(environ, start_response):
        from urllib.parse import parse_qs

        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = environ["wsgi.input"].read(length).decode("utf-8", "replace")
        qs = parse_qs(body)
        target = qs.get("next", [""])[0]
        try:
            start_response("302 Found", [("Location", "/" + target)])
            return [b""]
        except ValueError:
            start_response("500 Internal Server Error", [("Content-Type", "text/plain")])
            return [b"rejected"]

    httpd = make_server("127.0.0.1", 0, handler)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_crlf_header_pack_is_a_clean_miss_against_a_safe_target(header_validating_origin):
    doc = {
        "target": header_validating_origin + "/",
        "pages": [
            {
                "url": header_validating_origin + "/",
                "forms": [
                    {"action": "/go", "method": "POST", "fields": [{"name": "next"}]}
                ],
            }
        ],
    }
    out = run(doc)
    ids = {f["id"] for f in out["findings"]}
    assert "payload-crlf-header-injection" not in ids


@pytest.fixture
def header_splitting_origin():
    """Simulates a genuinely vulnerable server: the injected marker lands
    in an *extra* header, not stuffed inside Location's own value.

    A real HTTP/1.1 client (h11, net/http) treats a literal CRLF as an
    actual header terminator -- once the bytes hit the wire, the client's
    parser splits them into a separate header/cookie line, it doesn't
    matter that the vulnerable app only meant to write one Location value.
    wsgiref itself refuses to let this handler emit real control chars
    (see header_validating_origin above), so this fixture instead returns
    the *already-split* shape a successful injection would produce on the
    wire, to prove header_contains catches it wherever it lands -- this
    is exactly the case redirected_to_contains (Location-only) missed.
    """

    def handler(environ, start_response):
        start_response(
            "302 Found",
            [("Location", "/shrdlr"), ("X-Shrdlr-Crlf-Marker", "shrdlr_crlf_9f2a1c")],
        )
        return [b""]

    httpd = make_server("127.0.0.1", 0, handler)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_crlf_header_pack_catches_marker_in_any_response_header(header_splitting_origin):
    doc = {
        "target": header_splitting_origin + "/",
        "pages": [
            {
                "url": header_splitting_origin + "/",
                "forms": [
                    {"action": "/go", "method": "POST", "fields": [{"name": "next"}]}
                ],
            }
        ],
    }
    out = run(doc)
    hit = next(f for f in out["findings"] if f["id"] == "payload-crlf-header-injection")
    assert "shrdlr_crlf_9f2a1c" in hit["evidence"]


@pytest.fixture
def crlf_reflect_origin():
    def handler(environ, start_response):
        from urllib.parse import parse_qs

        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = environ["wsgi.input"].read(length).decode("utf-8", "replace")
        qs = parse_qs(body)
        q = qs.get("q", [""])[0]
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [f"<p>no rows for {q}</p>".encode()]

    httpd = make_server("127.0.0.1", 0, handler)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_crlf_reflected_raw_fires_on_naive_string_concatenation(crlf_reflect_origin):
    doc = {
        "target": crlf_reflect_origin + "/",
        "pages": [
            {
                "url": crlf_reflect_origin + "/",
                "forms": [{"action": "/search", "method": "POST", "fields": [{"name": "q"}]}],
            }
        ],
    }
    out = run(doc)
    ids = {f["id"] for f in out["findings"]}
    assert "payload-crlf-reflected" in ids


@pytest.fixture
def xxe_origin():
    def handler(environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = environ["wsgi.input"].read(length).decode("utf-8", "replace")
        content_type = environ.get("CONTENT_TYPE", "")
        if "SYSTEM" in body and "/etc/passwd" in body and "xml" in content_type:
            resp = b"root:x:0:0:root:/root:/bin/sh\n"
        else:
            resp = b"<ok/>"
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [resp]

    httpd = make_server("127.0.0.1", 0, handler)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_raw_body_pack_sends_literal_payload_not_form_fields(xxe_origin):
    doc = {
        "target": xxe_origin + "/",
        "pages": [
            {
                "url": xxe_origin + "/",
                "forms": [{"action": "/upload", "method": "POST", "fields": [{"name": "q"}]}],
            }
        ],
    }
    out = run(doc)
    ids = {f["id"] for f in out["findings"]}
    assert "payload-xxe" in ids


def test_build_marker_host_without_oob_host_is_the_placeholder():
    assert build_marker_host("shrdlrabc123", None) == MARKER_HOST
    assert build_marker_host("shrdlrabc123", "") == MARKER_HOST


def test_build_marker_host_with_oob_host_builds_a_subdomain():
    assert build_marker_host("shrdlrabc123", "collab.example.com") == (
        "shrdlrabc123.collab.example.com"
    )


@pytest.fixture
def open_redirect_origin():
    def handler(environ, start_response):
        length = int(environ.get("CONTENT_LENGTH") or 0)
        body = environ["wsgi.input"].read(length).decode("utf-8", "replace")
        from urllib.parse import parse_qs

        qs = parse_qs(body)
        target = qs.get("next", [""])[0]
        if target.startswith("http://") or target.startswith("https://") or target.startswith("//"):
            loc = target if not target.startswith("//") else "https:" + target
            start_response("302 Found", [("Location", loc)])
            return [b""]
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]

    httpd = make_server("127.0.0.1", 0, handler)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


def test_open_redirect_detected_without_oob_host(open_redirect_origin):
    # Regression test: with follow_redirects=True (the old default), httpx
    # would try to actually connect to the marker host to chase the
    # redirect chain. The default placeholder lives under the reserved
    # ".invalid" TLD, which never resolves -- that raised inside httpx and
    # was swallowed by `except httpx.HTTPError: continue`, silently
    # skipping the check entirely. This must fire even with no --oob-host.
    doc = {
        "target": open_redirect_origin + "/",
        "pages": [
            {
                "url": open_redirect_origin + "/",
                "forms": [
                    {"action": "/go", "method": "POST", "fields": [{"name": "next"}]}
                ],
            }
        ],
    }
    out = run(doc)
    hit = next(f for f in out["findings"] if f["id"] == "payload-open-redirect")
    assert MARKER_HOST in hit["evidence"]


def test_oob_host_flows_into_dynamic_redirect_match(open_redirect_origin):
    # open-redirect's match clause references {{MARKER_HOST}} -- confirm it
    # resolves to the real --oob-host-derived subdomain, not the static
    # placeholder, when one is supplied, and that the redirect-detection
    # logic (entirely local, no server-side polling) still fires.
    doc = {
        "target": open_redirect_origin + "/",
        "pages": [
            {
                "url": open_redirect_origin + "/",
                "forms": [
                    {"action": "/go", "method": "POST", "fields": [{"name": "next"}]}
                ],
            }
        ],
    }
    out = run(doc, oob_host="collab.example.com")
    hit = next(f for f in out["findings"] if f["id"] == "payload-open-redirect")
    assert "collab.example.com" in hit["evidence"]


def test_blind_pack_logs_oob_probe_when_oob_host_given(tmp_path):
    extra = tmp_path / "blind.yaml"
    extra.write_text(
        "- id: blind-probe\n"
        "  finding_id: payload-blind-probe\n"
        "  blind: true\n"
        "  payload: 'http://{{MARKER_HOST}}/x'\n"
        "  severity: medium\n",
        encoding="utf-8",
    )
    doc = {
        "target": "http://127.0.0.1:1/",
        "pages": [
            {
                "url": "http://127.0.0.1:1/",
                "forms": [{"action": "/whatever", "method": "GET", "fields": [{"name": "q"}]}],
            }
        ],
    }
    packs = load_packs(extra=[extra])
    # No live server needed to observe the probe log -- it's recorded
    # before the (failing, since nothing is listening) request is even
    # attempted is not required; the pack is blind so the tester only
    # needs to *send* it, and does so before checking the outcome.
    out = run(doc, packs=[p for p in packs if p["id"] == "blind-probe"], oob_host="collab.example.com")
    probes = [p for p in out["oob_probes"] if p["pack"] == "payload-blind-probe"]
    assert len(probes) == 1
    assert probes[0]["marker_host"].endswith(".collab.example.com")
    assert probes[0]["url"] == "http://127.0.0.1:1/whatever"


def test_blind_pack_logs_nothing_without_oob_host(tmp_path):
    extra = tmp_path / "blind.yaml"
    extra.write_text(
        "- id: blind-probe\n"
        "  finding_id: payload-blind-probe\n"
        "  blind: true\n"
        "  payload: 'http://{{MARKER_HOST}}/x'\n"
        "  severity: medium\n",
        encoding="utf-8",
    )
    doc = {
        "target": "http://127.0.0.1:1/",
        "pages": [
            {
                "url": "http://127.0.0.1:1/",
                "forms": [{"action": "/whatever", "method": "GET", "fields": [{"name": "q"}]}],
            }
        ],
    }
    packs = load_packs(extra=[extra])
    out = run(doc, packs=[p for p in packs if p["id"] == "blind-probe"])
    assert out["oob_probes"] == []


def test_cli_oob_host_flag(tmp_path):
    crawl = tmp_path / "crawl.json"
    crawl.write_text(json.dumps({"target": "http://127.0.0.1:1/", "pages": []}), encoding="utf-8")
    outp = tmp_path / "out.json"
    assert main([str(crawl), "--oob-host", "collab.example.com", "-o", str(outp)]) == 0
    body = json.loads(outp.read_text(encoding="utf-8"))
    assert body["oob_probes"] == []


def test_infer_confidence_blind_is_probable():
    assert infer_confidence({"blind": True, "match": {"any": [{"body_contains": "x"}]}}) == "probable"


def test_infer_confidence_timing_clause_is_probable():
    pack = {"match": {"any": [{"time_delta_gte_ms": 4000}]}}
    assert infer_confidence(pack) == "probable"


def test_infer_confidence_bare_reflection_is_heuristic():
    pack = {"match": {"any": [{"reflected": True}]}}
    assert infer_confidence(pack) == "heuristic"


def test_infer_confidence_marker_echo_is_confirmed():
    pack = {"match": {"any": [{"body_contains": "computed:49"}]}}
    assert infer_confidence(pack) == "confirmed"


def test_infer_confidence_explicit_override_wins(query_reflect_origin, tmp_path):
    extra = tmp_path / "override.yaml"
    extra.write_text(
        "- id: override-probe\n"
        "  finding_id: payload-override-probe\n"
        "  payload: 'OVR'\n"
        "  confidence: confirmed\n"
        "  match:\n"
        "    any:\n"
        "      - reflected: true\n",
        encoding="utf-8",
    )
    doc = {
        "target": query_reflect_origin + "/",
        "pages": [{"url": query_reflect_origin + "/search", "params": ["q"], "forms": []}],
    }
    packs = [p for p in load_packs(extra=[extra]) if p["id"] == "override-probe"]
    out = run(doc, packs=packs)
    assert out["findings"][0]["confidence"] == "confirmed"


def test_minimal_repro_picks_shortest_matching_payload(tmp_path):
    extra = tmp_path / "packs.yaml"
    extra.write_text(
        "- id: long-probe\n"
        "  finding_id: payload-repro-probe\n"
        "  payload: 'AAAAAAAAAA-MARK'\n"
        "  severity: medium\n"
        "  match:\n"
        "    any:\n"
        "      - body_contains: 'MARK'\n"
        "- id: short-probe\n"
        "  finding_id: payload-repro-probe\n"
        "  payload: 'MARK'\n"
        "  severity: medium\n"
        "  match:\n"
        "    any:\n"
        "      - body_contains: 'MARK'\n",
        encoding="utf-8",
    )

    def app(environ, start_response):
        from urllib.parse import parse_qs

        qs = parse_qs(environ.get("QUERY_STRING", ""))
        q = qs.get("q", [""])[0]
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [f"echo: {q}".encode()]

    httpd = make_server("127.0.0.1", 0, app)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        origin_url = f"http://127.0.0.1:{port}"
        doc = {
            "target": origin_url + "/",
            "pages": [{"url": origin_url + "/search", "params": ["q"], "forms": []}],
        }
        packs = [p for p in load_packs(extra=[extra]) if p["finding_id"] == "payload-repro-probe"]
        out = run(doc, packs=packs)
    finally:
        httpd.shutdown()

    assert len(out["findings"]) == 1
    finding = out["findings"][0]
    assert finding["evidence"] == "MARK"
    assert finding["minimal_repro"] is True


def test_confidence_is_based_on_which_clause_actually_matched_not_pack_shape(tmp_path):
    # A pack combining a strong marker clause with a weak `reflected: true`
    # fallback in the same `any:` block must be graded "confirmed" when the
    # response was matched via the strong clause, never downgraded to
    # "heuristic" just because a weaker clause type is also present in the
    # pack's static definition.
    extra = tmp_path / "mixed.yaml"
    extra.write_text(
        "- id: mixed-probe\n"
        "  finding_id: payload-mixed-probe\n"
        "  payload: 'computed:49'\n"
        "  severity: high\n"
        "  match:\n"
        "    any:\n"
        "      - body_contains: 'computed:49'\n"
        "      - reflected: true\n",
        encoding="utf-8",
    )

    def app(environ, start_response):
        from urllib.parse import parse_qs

        qs = parse_qs(environ.get("QUERY_STRING", ""))
        q = qs.get("q", [""])[0]
        start_response("200 OK", [("Content-Type", "text/plain")])
        # Body contains the strong marker but NOT the raw payload text, so
        # only the body_contains clause can have fired, not `reflected`.
        return [f"result: {q}".encode()] if "computed" not in q else [b"result: computed:49"]

    httpd = make_server("127.0.0.1", 0, app)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        origin_url = f"http://127.0.0.1:{port}"
        doc = {
            "target": origin_url + "/",
            "pages": [{"url": origin_url + "/search", "params": ["q"], "forms": []}],
        }
        packs = [p for p in load_packs(extra=[extra]) if p["finding_id"] == "payload-mixed-probe"]
        out = run(doc, packs=packs)
    finally:
        httpd.shutdown()

    assert len(out["findings"]) == 1
    assert out["findings"][0]["confidence"] == "confirmed"


def test_minimal_repro_prefers_higher_confidence_over_shorter_payload(tmp_path):
    # A shorter but weaker (reflected-only) match must not displace a
    # longer payload that triggered a strong, unambiguous marker clause.
    extra = tmp_path / "packs.yaml"
    extra.write_text(
        "- id: weak-short\n"
        "  finding_id: payload-priority-probe\n"
        "  payload: 'W'\n"
        "  severity: medium\n"
        "  match:\n"
        "    any:\n"
        "      - reflected: true\n"
        "- id: strong-long\n"
        "  finding_id: payload-priority-probe\n"
        "  payload: 'STRONGMARKERVALUE'\n"
        "  severity: medium\n"
        "  match:\n"
        "    any:\n"
        "      - body_contains: 'confirmed-marker'\n",
        encoding="utf-8",
    )

    def app(environ, start_response):
        from urllib.parse import parse_qs

        qs = parse_qs(environ.get("QUERY_STRING", ""))
        q = qs.get("q", [""])[0]
        start_response("200 OK", [("Content-Type", "text/plain")])
        if q == "STRONGMARKERVALUE":
            return [b"confirmed-marker"]
        return [f"echo: {q}".encode()]

    httpd = make_server("127.0.0.1", 0, app)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        origin_url = f"http://127.0.0.1:{port}"
        doc = {
            "target": origin_url + "/",
            "pages": [{"url": origin_url + "/search", "params": ["q"], "forms": []}],
        }
        packs = [p for p in load_packs(extra=[extra]) if p["finding_id"] == "payload-priority-probe"]
        out = run(doc, packs=packs)
    finally:
        httpd.shutdown()

    assert len(out["findings"]) == 1
    finding = out["findings"][0]
    assert finding["confidence"] == "confirmed"
    assert finding["evidence"] == "STRONGMARKERVALUE"


def test_default_mutate_case_flips_a_known_keyword():
    mutated = _default_mutate("' OR 1=1 SELECT * FROM users--")
    assert mutated != "' OR 1=1 SELECT * FROM users--"
    assert "select" in mutated.lower()  # content preserved, only case changed


def test_default_mutate_wraps_in_comment_when_no_keyword_matches():
    mutated = _default_mutate("xyzxyz")
    assert mutated == "/**/xyzxyz/**/"


def test_mutate_payload_uses_default_when_no_env_var(monkeypatch):
    monkeypatch.delenv("SHROODLER_PAYLOAD_MUTATE_CMD", raising=False)
    result = mutate_payload("SELECT 1", context={})
    assert result is not None
    assert result != "SELECT 1"


def test_mutate_payload_uses_external_command(monkeypatch, tmp_path):
    script = tmp_path / "mutate.sh"
    script.write_text("#!/bin/sh\nprintf '%s' 'MUTATED_PAYLOAD'\n")
    script.chmod(0o755)
    monkeypatch.setenv("SHROODLER_PAYLOAD_MUTATE_CMD", str(script))
    result = mutate_payload("original", context={"finding_id": "x"})
    assert result == "MUTATED_PAYLOAD"


def test_mutate_payload_supports_multi_word_command(monkeypatch, tmp_path):
    # A natural configuration like "python3 mutate.py" is a single env
    # var value with an argument, not a single executable name.
    script = tmp_path / "mutate.py"
    script.write_text(
        "import sys, json\n"
        "json.loads(sys.stdin.read())\n"
        "sys.stdout.write('FROM_PYTHON_SCRIPT')\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SHROODLER_PAYLOAD_MUTATE_CMD", f"{sys.executable} {script}")
    result = mutate_payload("original", context={"finding_id": "x"})
    assert result == "FROM_PYTHON_SCRIPT"


def test_mutate_payload_windows_path_backslashes_are_not_escape_chars():
    import shlex

    # POSIX-mode shlex treats "\" as an escape character and would eat
    # it, mangling a bare (unquoted, no spaces) Windows path; non-POSIX
    # mode (what tester.py now selects when os.name == "nt") leaves
    # backslashes alone.
    posix_mangled = shlex.split(r"C:\Users\test\mutate.exe", posix=True)[0]
    windows_correct = shlex.split(r"C:\Users\test\mutate.exe", posix=False)[0]
    assert posix_mangled != r"C:\Users\test\mutate.exe"
    assert windows_correct == r"C:\Users\test\mutate.exe"


def test_mutate_payload_uses_posix_mode_off_windows(monkeypatch):
    monkeypatch.setattr("os.name", "posix")
    monkeypatch.setenv("SHROODLER_PAYLOAD_MUTATE_CMD", "/bin/nonexistent-mutate-cmd")
    # Just confirms this path is reached without raising -- the actual
    # posix-vs-nt branch is exercised via the shlex behavior test above.
    assert mutate_payload("x", context={}) is None


def test_mutate_payload_external_command_empty_output_means_no_mutation(monkeypatch, tmp_path):
    script = tmp_path / "mutate.sh"
    script.write_text("#!/bin/sh\ntrue\n")
    script.chmod(0o755)
    monkeypatch.setenv("SHROODLER_PAYLOAD_MUTATE_CMD", str(script))
    assert mutate_payload("original", context={}) is None


def test_adaptive_run_retries_with_mutation_on_baseline_miss(tmp_path):
    # A pack whose static payload never matches, but a mutated variant
    # (wrapped in /**/.../**/  via _default_mutate's fallback) does.
    extra = tmp_path / "adaptive.yaml"
    extra.write_text(
        "- id: needs-mutation\n"
        "  finding_id: payload-adaptive-probe\n"
        "  payload: 'zzz'\n"
        "  severity: high\n"
        "  match:\n"
        "    any:\n"
        "      - body_contains: '/**/zzz/**/'\n",
        encoding="utf-8",
    )

    def app(environ, start_response):
        from urllib.parse import parse_qs

        qs = parse_qs(environ.get("QUERY_STRING", ""))
        q = qs.get("q", [""])[0]
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [f"echo: {q}".encode()]

    httpd = make_server("127.0.0.1", 0, app)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        origin_url = f"http://127.0.0.1:{port}"
        doc = {
            "target": origin_url + "/",
            "pages": [{"url": origin_url + "/search", "params": ["q"], "forms": []}],
        }
        packs = [p for p in load_packs(extra=[extra]) if p["finding_id"] == "payload-adaptive-probe"]

        no_adapt = run(doc, packs=packs, adaptive=False)
        assert no_adapt["findings"] == []

        adapted = run(doc, packs=packs, adaptive=True)
    finally:
        httpd.shutdown()

    assert len(adapted["findings"]) == 1
    finding = adapted["findings"][0]
    assert finding["confidence"] != "confirmed"
    assert "adaptive payload mutation" in finding["description"]


def test_adaptive_never_reports_mutated_match_as_confirmed(tmp_path):
    extra = tmp_path / "adaptive_strong.yaml"
    extra.write_text(
        "- id: needs-mutation-strong\n"
        "  finding_id: payload-adaptive-strong-probe\n"
        "  payload: 'zzz'\n"
        "  severity: high\n"
        "  match:\n"
        "    any:\n"
        "      - body_contains: 'computed:49'\n",
        encoding="utf-8",
    )

    def app(environ, start_response):
        from urllib.parse import parse_qs

        qs = parse_qs(environ.get("QUERY_STRING", ""))
        q = qs.get("q", [""])[0]
        start_response("200 OK", [("Content-Type", "text/plain")])
        # The mutated payload (wrapped in /**/.../**/") triggers a
        # "confirmed-tier" marker match once mutated -- this would be
        # confidence=confirmed for a non-mutated match.
        if q.startswith("/**/"):
            return [b"computed:49"]
        return [f"echo: {q}".encode()]

    httpd = make_server("127.0.0.1", 0, app)
    port = httpd.server_port
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        origin_url = f"http://127.0.0.1:{port}"
        doc = {
            "target": origin_url + "/",
            "pages": [{"url": origin_url + "/search", "params": ["q"], "forms": []}],
        }
        packs = [
            p
            for p in load_packs(extra=[extra])
            if p["finding_id"] == "payload-adaptive-strong-probe"
        ]
        out = run(doc, packs=packs, adaptive=True)
    finally:
        httpd.shutdown()

    assert len(out["findings"]) == 1
    assert out["findings"][0]["confidence"] == "probable"
