from __future__ import annotations

import argparse

from shroodler.cli import cmd_gen_regression_test
from shroodler.gen_regression_test import render_regression_test


def test_render_regression_test_is_valid_python_and_calls_reverify():
    text = render_regression_test("http://x/export", "payload-sql-error")
    compile(text, "<generated>", "exec")
    assert "from shroodler.reverify import reverify" in text
    assert "URL = 'http://x/export'" in text
    assert "FINDING_ID = 'payload-sql-error'" in text
    assert "def test_regression_payload_sql_error_http_x_export" in text
    assert 'result["verified_fixed"]' in text


def test_cmd_gen_regression_test_refuses_when_still_present(fx, capsys):
    fx.on("GET", "/leak", lambda inc: (200, {"X-Powered-By": "PHP"}, b"ok"))
    ns = argparse.Namespace(
        url=fx.origin + "/leak",
        finding_id="x-powered-by",
        mode="static",
        allow_external=False,
        no_payloads=True,
        output=None,
    )
    assert cmd_gen_regression_test(ns) == 1
    assert "still present" in capsys.readouterr().err


def test_cmd_gen_regression_test_writes_file_when_fixed(fx, tmp_path):
    fx.on("GET", "/clean", lambda inc: (200, {}, b"ok"))
    out = tmp_path / "test_regression_generated.py"
    ns = argparse.Namespace(
        url=fx.origin + "/clean",
        finding_id="x-powered-by",
        mode="static",
        allow_external=False,
        no_payloads=True,
        output=str(out),
    )
    assert cmd_gen_regression_test(ns) == 0
    assert out.is_file()
    compile(out.read_text(encoding="utf-8"), "<generated>", "exec")


def test_cmd_gen_regression_test_refuses_on_unverified_warning_without_force(fx, tmp_path, capsys):
    # run_payloads=True (the default) + a bare-path URL (no query string)
    # triggers reverify's "couldn't necessarily re-fuzz a GET parameter"
    # warning -- generating a regression test off that should require
    # an explicit override, not proceed silently.
    fx.on("GET", "/clean", lambda inc: (200, {}, b"ok"))
    out = tmp_path / "test_regression_generated.py"
    ns = argparse.Namespace(
        url=fx.origin + "/clean",
        finding_id="payload-sql-error",
        mode="static",
        allow_external=False,
        no_payloads=False,
        output=str(out),
        force=False,
    )
    assert cmd_gen_regression_test(ns) == 1
    assert not out.exists()
    assert "query string" in capsys.readouterr().err


def test_cmd_gen_regression_test_force_overrides_warning(fx, tmp_path):
    fx.on("GET", "/clean", lambda inc: (200, {}, b"ok"))
    out = tmp_path / "test_regression_generated.py"
    ns = argparse.Namespace(
        url=fx.origin + "/clean",
        finding_id="payload-sql-error",
        mode="static",
        allow_external=False,
        no_payloads=False,
        output=str(out),
        force=True,
    )
    assert cmd_gen_regression_test(ns) == 0
    assert out.is_file()
