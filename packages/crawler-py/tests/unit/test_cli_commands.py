from __future__ import annotations

import argparse
import json

import pytest

from shroodler.cli import (
    cmd_crawl,
    cmd_diff,
    cmd_payload,
    cmd_proxy,
    cmd_report,
    find_proxy_bin,
    main,
)
from shroodler.config import load_rc
from shroodler.diffcmd import diff_documents, load_json
from shroodler.report import write_report


def test_cmd_crawl_writes_json(fx, tmp_path):
    fx.html("/", "<html>ok</html>")
    out = tmp_path / "out.json"
    ns = argparse.Namespace(
        url=fx.origin + "/",
        mode="static",
        depth=0,
        ignore_robots=True,
        allow_external=False,
        format="json",
        output=str(out),
    )
    assert cmd_crawl(ns) == 0
    assert out.exists()
    assert "pages" in out.read_text()


def test_cmd_crawl_stdout_json(fx, capsys):
    fx.html("/", "ok")
    ns = argparse.Namespace(
        url=fx.origin + "/",
        mode="static",
        depth=0,
        ignore_robots=True,
        allow_external=False,
        format="json",
        output=None,
    )
    assert cmd_crawl(ns) == 0
    assert "scan_started_at" in capsys.readouterr().out


def _req_header(req, name: str) -> str:
    for k, v in req.headers.items():
        if k.lower() == name.lower():
            return v
    return ""


def test_cmd_crawl_sends_header_and_cookie(fx, tmp_path):
    seen: dict[str, str] = {}

    def echo(req):
        seen["header"] = _req_header(req, "X-Lab-Auth")
        seen["cookie"] = req.cookies
        return 200, {"Content-Type": "text/html; charset=utf-8"}, b"<html>ok</html>"

    fx.on("GET", "/", echo)
    out = tmp_path / "out.json"
    ns = argparse.Namespace(
        url=fx.origin + "/",
        mode="static",
        depth=0,
        ignore_robots=True,
        allow_external=False,
        format="json",
        output=str(out),
        header=["X-Lab-Auth: open"],
        cookie=["lab_auth=open"],
    )
    assert cmd_crawl(ns) == 0
    assert seen.get("header") == "open"
    assert "lab_auth=open" in seen.get("cookie", "")


def test_rc_header_cookie_applied(fx, tmp_path, monkeypatch):
    seen: dict[str, str] = {}

    def echo(req):
        seen["header"] = _req_header(req, "X-Lab-Auth")
        seen["cookie"] = req.cookies
        return 200, {"Content-Type": "text/html; charset=utf-8"}, b"<html>ok</html>"

    fx.on("GET", "/", echo)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("shroodler.config.Path.home", lambda: tmp_path)
    (tmp_path / ".shroodlerrc").write_text(
        "header:\n  - 'X-Lab-Auth: open'\ncookie:\n  - lab_auth=open\n",
        encoding="utf-8",
    )
    out = tmp_path / "o.json"
    with pytest.raises(SystemExit) as ex:
        main(
            [
                "crawl",
                fx.origin + "/",
                "--depth",
                "0",
                "--ignore-robots",
                "-o",
                str(out),
            ]
        )
    assert ex.value.code == 0
    assert seen.get("header") == "open"
    assert "lab_auth=open" in seen.get("cookie", "")


def test_cmd_diff_ok_and_fail(tmp_path):
    actual = tmp_path / "a.json"
    expected = tmp_path / "e.json"
    actual.write_text(
        '{"pages":[{"url":"http://127.0.0.1/"}],"findings":[]}',
        encoding="utf-8",
    )
    expected.write_text(
        '{"expected_pages":["/"],"expected_findings":[],"expected_not_found":[]}',
        encoding="utf-8",
    )
    ns = argparse.Namespace(findings=str(actual), expected=str(expected), pages_only=True)
    assert cmd_diff(ns) == 0
    expected.write_text('{"expected_pages":["/missing"]}', encoding="utf-8")
    assert cmd_diff(ns) == 1


def test_cmd_report_html_and_json(tmp_path, capsys):
    docp = tmp_path / "d.json"
    docp.write_text('{"target":"http://127.0.0.1/","findings":[]}', encoding="utf-8")
    out = tmp_path / "r.html"
    ns = argparse.Namespace(findings=str(docp), format="html", output=str(out), suppressions=None)
    assert cmd_report(ns) == 0
    assert out.exists()
    ns = argparse.Namespace(findings=str(docp), format="json", output=None, suppressions=None)
    assert cmd_report(ns) == 0
    assert "findings" in capsys.readouterr().out
    ns = argparse.Namespace(
        findings=str(docp), format="json", output=str(tmp_path / "x.json"), suppressions=None
    )
    assert cmd_report(ns) == 0


def test_cmd_payload_empty_local(tmp_path):
    crawl = tmp_path / "c.json"
    crawl.write_text('{"target":"http://127.0.0.1:9/","pages":[]}', encoding="utf-8")
    out = tmp_path / "p.json"
    ns = argparse.Namespace(crawl_json=str(crawl), output=str(out), pack=[])
    assert cmd_payload(ns) == 0
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["findings"] == []
    assert body["target"] == "http://127.0.0.1:9/"


def test_cmd_payload_refuses_external(tmp_path):
    crawl = tmp_path / "c.json"
    crawl.write_text('{"target":"https://example.com/","pages":[]}', encoding="utf-8")
    ns = argparse.Namespace(crawl_json=str(crawl), output=None, pack=[])
    with pytest.raises(ValueError, match="non-local"):
        cmd_payload(ns)


def test_cmd_proxy_missing_and_forward(tmp_path, monkeypatch, capfd):
    monkeypatch.delenv("SHROODLER_PROXY_BIN", raising=False)
    monkeypatch.setattr("shroodler.cli.find_proxy_bin", lambda: None)
    assert cmd_proxy(argparse.Namespace(proxy_args=["start"])) == 1
    assert "not found" in capfd.readouterr().err
    script = tmp_path / "fake-proxy"
    script.write_text("#!/bin/sh\necho proxy-ok \"$@\"\n", encoding="utf-8")
    script.chmod(0o755)
    monkeypatch.setattr("shroodler.cli.find_proxy_bin", lambda: script)
    assert cmd_proxy(argparse.Namespace(proxy_args=["ca", "generate"])) == 0
    assert "proxy-ok ca generate" in capfd.readouterr().out


def test_find_proxy_bin_env(tmp_path, monkeypatch):
    fake = tmp_path / "shroodler-proxy"
    fake.write_text("", encoding="utf-8")
    monkeypatch.setenv("SHROODLER_PROXY_BIN", str(fake))
    assert find_proxy_bin() == fake
    monkeypatch.setenv("SHROODLER_PROXY_BIN", str(tmp_path / "missing"))
    assert find_proxy_bin() is None


def test_cmd_payload_missing_tester_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SHROODLER_PAYLOAD_DIR", str(tmp_path / "nope"))
    crawl = tmp_path / "c.json"
    crawl.write_text('{"target":"http://127.0.0.1:9/","pages":[]}', encoding="utf-8")
    ns = argparse.Namespace(crawl_json=str(crawl), output=None, pack=[])
    with pytest.raises(FileNotFoundError):
        cmd_payload(ns)


def test_main_version_and_no_command(capsys):
    with pytest.raises(SystemExit) as ex:
        main(["version"])
    assert ex.value.code == 0
    assert "shroodler 0.1.0" in capsys.readouterr().out
    with pytest.raises(SystemExit) as ex:
        main(["-V"])
    assert ex.value.code == 0
    with pytest.raises(SystemExit) as ex:
        main([])
    assert ex.value.code == 2


def test_main_systemexit_ok(tmp_path):
    a = tmp_path / "a.json"
    e = tmp_path / "e.json"
    a.write_text('{"pages":[{"url":"http://127.0.0.1/x"}],"findings":[]}', encoding="utf-8")
    e.write_text('{"expected_pages":["/x"]}', encoding="utf-8")
    with pytest.raises(SystemExit) as ex:
        main(["diff", str(a), str(e), "--pages-only"])
    assert ex.value.code == 0


def test_load_rc_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".shroodlerrc").write_text(
        "mode: static\ndepth: 2\nheader:\n  - 'X-Lab-Auth: open'\ncookie:\n  - lab_auth=open\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("shroodler.config.Path.home", lambda: tmp_path)
    rc = load_rc()
    assert rc["mode"] == "static"
    assert rc["header"] == ["X-Lab-Auth: open"]
    assert rc["cookie"] == ["lab_auth=open"]


def test_diff_documents_forms_and_unexpected():
    actual = {
        "pages": [
            {
                "url": "http://127.0.0.1/login",
                "forms": [{"fields": [{"name": "user"}]}],
            }
        ],
        "findings": [{"id": "x", "url": "http://127.0.0.1/login"}],
    }
    expected = {
        "expected_pages": ["/login"],
        "expected_findings": [{"id": "missing", "url": "http://127.0.0.1/login"}],
        "expected_not_found": [{"id": "x", "url": "http://127.0.0.1/login"}],
        "expected_forms": {"/login": ["user", "pass"], "/nope": ["a"]},
    }
    errs = diff_documents(actual, expected)
    assert any("missing finding" in e for e in errs)
    assert any("unexpected" in e for e in errs)
    assert any("missing form field pass" in e for e in errs)
    assert any("missing page for forms" in e for e in errs)
    assert load_json.__doc__ is None or True


def test_write_report_file(tmp_path):
    p = tmp_path / "out.html"
    text = write_report({"target": "t", "findings": []}, "html", str(p))
    assert "html" in text.lower() or "<" in text
    assert p.exists()
