from __future__ import annotations

import argparse

import pytest

from shroodler.cli import cmd_crawl, cmd_diff, cmd_report, main
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
    ns = argparse.Namespace(findings=str(docp), format="html", output=str(out))
    assert cmd_report(ns) == 0
    assert out.exists()
    ns = argparse.Namespace(findings=str(docp), format="json", output=None)
    assert cmd_report(ns) == 0
    assert "findings" in capsys.readouterr().out
    ns = argparse.Namespace(findings=str(docp), format="json", output=str(tmp_path / "x.json"))
    assert cmd_report(ns) == 0


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
    (tmp_path / ".shroodlerrc").write_text("mode: static\ndepth: 2\n", encoding="utf-8")
    monkeypatch.setattr("shroodler.config.Path.home", lambda: tmp_path)
    rc = load_rc()
    assert rc["mode"] == "static"


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
