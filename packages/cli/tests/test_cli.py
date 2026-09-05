from __future__ import annotations

import pytest
from shroodler.cli import build_parser
from shroodler_cli.main import main


def test_version(capsys):
    with pytest.raises(SystemExit) as ex:
        main(["version"])
    assert ex.value.code == 0
    assert "shroodler 0.2.0" in capsys.readouterr().out


def test_help_lists_product_commands():
    text = build_parser().format_help()
    assert "crawl" in text
    assert "payload" in text
    assert "proxy" in text
    assert "version" in text
