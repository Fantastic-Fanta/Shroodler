from __future__ import annotations

import subprocess

import pytest

from shroodler.code_attribution import (
    _MAX_FILE_BYTES,
    SourceIndex,
    attribute_finding,
    attribute_findings,
    find_route_source,
)


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def flask_repo(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/export')\n"
        "def export():\n"
        "    return do_export()\n"
        "\n"
        "@app.route('/users/<int:id>')\n"
        "def user_detail(id):\n"
        "    return get_user(id)\n",
        encoding="utf-8",
    )
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "Tester")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-q", "-m", "add routes")
    return tmp_path


def test_find_route_source_matches_literal_path(flask_repo):
    loc = find_route_source(flask_repo, "/export")
    assert loc is not None
    assert loc.file == "app.py"
    assert loc.line == 4


def test_find_route_source_matches_numeric_segment_via_placeholder(flask_repo):
    loc = find_route_source(flask_repo, "/users/42")
    assert loc is not None
    assert loc.line == 8


def test_find_route_source_returns_none_for_unknown_path(flask_repo):
    assert find_route_source(flask_repo, "/nope") is None


def test_find_route_source_ignores_lines_without_route_keyword(tmp_path):
    (tmp_path / "app.py").write_text("MESSAGE = '/export'\n", encoding="utf-8")
    assert find_route_source(tmp_path, "/export") is None


def test_attribute_finding_includes_blame_info(flask_repo):
    result = attribute_finding(flask_repo, "http://x/export")
    assert result is not None
    assert result["file"] == "app.py"
    assert result["line"] == 4
    assert "commit" in result
    assert result["author"] == "Tester"


def test_attribute_finding_returns_none_when_unresolvable(flask_repo):
    assert attribute_finding(flask_repo, "http://x/totally-unknown-route") is None


def test_attribute_finding_without_git_repo_still_resolves_source(tmp_path):
    (tmp_path / "app.py").write_text("@app.route('/export')\n", encoding="utf-8")
    result = attribute_finding(tmp_path, "http://x/export")
    assert result is not None
    assert result["file"] == "app.py"
    assert "commit" not in result


def test_source_index_only_reads_files_once(flask_repo, monkeypatch):
    from pathlib import Path as _Path

    calls = {"n": 0}
    original_read_text = _Path.read_text

    def counting_read_text(self, *args, **kwargs):
        if self.suffix == ".py":
            calls["n"] += 1
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(_Path, "read_text", counting_read_text)
    index = SourceIndex(flask_repo)
    index.find("/export")
    index.find("/users/42")
    index.find("/nope")
    assert calls["n"] == 1, "each source file should be read at most once per SourceIndex"


def test_attribute_findings_batches_multiple_urls_with_one_index(flask_repo):
    results = attribute_findings(
        flask_repo,
        ["http://x/export", "http://x/users/42", "http://x/nope"],
    )
    assert set(results) == {"http://x/export", "http://x/users/42"}
    assert results["http://x/export"]["file"] == "app.py"


def test_oversized_file_is_skipped(tmp_path):
    big = tmp_path / "big.py"
    big.write_text("@app.route('/export')\n" + ("x" * (_MAX_FILE_BYTES + 1)), encoding="utf-8")
    assert find_route_source(tmp_path, "/export") is None
