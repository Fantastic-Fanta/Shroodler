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

from app import app as flask_app  # noqa: E402
from tester import (  # noqa: E402
    _local,
    load_packs,
    main,
    pack_finding_id,
    pack_matches,
    packs_dir,
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
            assert "payload" in item and "match" in item
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
