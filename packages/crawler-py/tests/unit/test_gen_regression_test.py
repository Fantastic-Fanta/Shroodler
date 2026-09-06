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
