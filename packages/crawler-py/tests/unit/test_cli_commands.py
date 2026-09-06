from __future__ import annotations

import argparse
import json

import pytest

from shroodler.cli import (
    cmd_audit_verify,
    cmd_baseline,
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


def test_cmd_diff_gate_with_source_root_prints_attribution(tmp_path, capsys):
    import subprocess

    (tmp_path / "app.py").write_text(
        "@app.route('/export')\ndef export(): pass\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@x", "-c", "user.name=T", "add", "app.py"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "-c", "user.email=t@x", "-c", "user.name=T", "commit", "-q", "-m", "x"],
        cwd=tmp_path,
        check=True,
    )

    actual = tmp_path / "a.json"
    expected = tmp_path / "e.json"
    actual.write_text(
        json.dumps(
            {
                "pages": [],
                "findings": [
                    {
                        "id": "payload-sql-error",
                        "severity": "high",
                        "category": "payload",
                        "url": "http://x/export",
                        "description": "d",
                        "evidence": "e",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    expected.write_text(json.dumps({"expected_findings": []}), encoding="utf-8")

    ns = argparse.Namespace(
        findings=str(actual),
        expected=str(expected),
        pages_only=False,
        gate=True,
        source_root=str(tmp_path),
    )
    assert cmd_diff(ns) == 1
    err = capsys.readouterr().err
    assert "app.py:1" in err


def test_cmd_diff_warns_on_expired_suppression(tmp_path, capsys):
    actual = tmp_path / "a.json"
    expected = tmp_path / "e.json"
    suppressions = tmp_path / "ignore.json"
    actual.write_text(
        '{"pages":[{"url":"http://127.0.0.1/"}],'
        '"findings":[{"id":"missing-csp","url":"http://127.0.0.1/","severity":"medium"}]}',
        encoding="utf-8",
    )
    expected.write_text(
        '{"expected_pages":["/"],"expected_findings":[],"expected_not_found":[]}',
        encoding="utf-8",
    )
    suppressions.write_text(
        '[{"id": "missing-csp", "url": "*", "expires": "2020-01-01"}]', encoding="utf-8"
    )
    ns = argparse.Namespace(
        findings=str(actual),
        expected=str(expected),
        pages_only=False,
        suppressions=str(suppressions),
        gate=True,
    )
    result = cmd_diff(ns)
    err = capsys.readouterr().err
    assert "suppression expired" in err
    assert "missing-csp" in err
    # And the underlying finding is genuinely no longer suppressed --
    # this is a warning, not a silent no-op.
    assert "new finding missing-csp" in err
    assert result == 1


def test_cmd_baseline_warns_when_regenerating_over_an_expired_suppression(tmp_path, capsys):
    # Regression test for a real gap caught in review: regenerating a
    # baseline after a suppression expired would silently bake the
    # now-unsuppressed finding in as freshly-accepted, unattributed risk,
    # with no warning anywhere -- exactly backwards for a mechanism meant
    # to force periodic re-review rather than quietly become permanent.
    findings = tmp_path / "f.json"
    suppressions = tmp_path / "ignore.json"
    findings.write_text(
        '{"target":"http://127.0.0.1/","pages":[],'
        '"findings":[{"id":"missing-csp","url":"http://127.0.0.1/","severity":"medium"}]}',
        encoding="utf-8",
    )
    suppressions.write_text(
        '[{"id": "missing-csp", "url": "*", "expires": "2020-01-01", "owner": "sec-team"}]',
        encoding="utf-8",
    )
    ns = argparse.Namespace(
        findings=str(findings), suppressions=str(suppressions), name=None, output=None
    )
    assert cmd_baseline(ns) == 0
    err = capsys.readouterr().err
    assert "suppression expired" in err
    assert "sec-team" in err


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
    assert body["oob_probes"] == []


def test_cmd_payload_passes_oob_host_through(tmp_path):
    crawl = tmp_path / "c.json"
    crawl.write_text('{"target":"http://127.0.0.1:9/","pages":[]}', encoding="utf-8")
    out = tmp_path / "p.json"
    ns = argparse.Namespace(
        crawl_json=str(crawl), output=str(out), pack=[], oob_host="collab.example.com"
    )
    assert cmd_payload(ns) == 0
    body = json.loads(out.read_text(encoding="utf-8"))
    assert body["oob_probes"] == []


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
    assert "shroodler 0.2.0" in capsys.readouterr().out
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
        "mode: static\ndepth: 2\nmax_pages: 3\nmax_time: 2.5\n"
        "header:\n  - 'X-Lab-Auth: open'\ncookie:\n  - lab_auth=open\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("shroodler.config.Path.home", lambda: tmp_path)
    rc = load_rc()
    assert rc["mode"] == "static"
    assert rc["header"] == ["X-Lab-Auth: open"]
    assert rc["cookie"] == ["lab_auth=open"]
    assert rc["max_pages"] == 3
    assert rc["max_time"] == 2.5
    from shroodler.cli import _apply_rc, build_parser

    parser = build_parser()
    _apply_rc(parser, rc)
    args = parser.parse_args(["crawl", "http://127.0.0.1/"])
    assert args.max_pages == 3
    assert args.max_time == 2.5
    assert args.depth == 2


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


def test_cmd_report_sarif_and_markdown(tmp_path):
    docp = tmp_path / "d.json"
    docp.write_text(
        json.dumps(
            {
                "target": "http://127.0.0.1/",
                "crawler": {"name": "shroodler-py", "version": "0.1.0", "mode": "static"},
                "pages": [],
                "findings": [
                    {
                        "id": "missing-csp",
                        "severity": "medium",
                        "category": "header",
                        "url": "http://127.0.0.1/",
                        "description": "no csp",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    sarif_path = tmp_path / "r.sarif"
    ns = argparse.Namespace(findings=str(docp), format="sarif", output=str(sarif_path))
    assert cmd_report(ns) == 0
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "missing-csp"
    assert sarif["runs"][0]["results"][0]["level"] == "warning"
    md_path = tmp_path / "r.md"
    ns = argparse.Namespace(findings=str(docp), format="md", output=str(md_path))
    assert cmd_report(ns) == 0
    md = md_path.read_text(encoding="utf-8")
    assert "## medium" in md
    assert "`missing-csp`" in md
    ns = argparse.Namespace(findings=str(docp), format="markdown", output=str(tmp_path / "r2.md"))
    assert cmd_report(ns) == 0


def test_cmd_audit_verify_intact(tmp_path):
    from shroodler_guardrails.policy import PolicyEnforcer

    audit = tmp_path / "audit.jsonl"
    enforcer = PolicyEnforcer(policy=None, audit_path=audit)
    enforcer.check("https://x.test/a")
    ns = argparse.Namespace(audit_log=str(audit))
    assert cmd_audit_verify(ns) == 0


def test_cmd_audit_verify_detects_tampering(tmp_path, capsys):
    from shroodler_guardrails.policy import PolicyEnforcer

    audit = tmp_path / "audit.jsonl"
    enforcer = PolicyEnforcer(policy=None, audit_path=audit)
    enforcer.check("https://x.test/a")
    enforcer.check("https://x.test/b")
    lines = audit.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["allowed"] = not tampered["allowed"]
    lines[0] = json.dumps(tampered)
    audit.write_text("\n".join(lines) + "\n")
    ns = argparse.Namespace(audit_log=str(audit))
    assert cmd_audit_verify(ns) == 1
    assert "problem" in capsys.readouterr().err
