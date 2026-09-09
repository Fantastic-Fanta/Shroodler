from __future__ import annotations

import yaml

from shroodler.ci_templates import PLATFORMS, render_ci_template


def test_github_template_is_valid_yaml_and_has_required_fields():
    text = render_ci_template("github", program="lab", target="http://127.0.0.1/")
    data = yaml.safe_load(text)
    assert data["name"] == "shroodler"
    triggers = data.get("on") or data.get(True)
    assert "pull_request" in triggers
    assert "schedule" in triggers
    assert "3.12" in text
    assert "shroodler crawl" in text
    assert "--program lab" in text
    assert "--max-pages 50" in text
    assert "-o scan.json" in text
    assert "diff scan.json expected_findings.json --gate --format github-annotations" in text
    assert "secrets.SHROODLER_SESSION_COOKIE" in text
    assert "secrets.ANTHROPIC_API_KEY" in text
    assert "actions/upload-artifact" in text
    assert "actions/cache" in text
    assert ".venv" in text


def test_gitlab_and_bitbucket_are_valid_yaml():
    for platform in ("gitlab", "bitbucket"):
        text = render_ci_template(platform, program="lab", target="https://example.com")
        data = yaml.safe_load(text)
        assert data is not None
        assert "shroodler crawl" in text
        assert "--program lab" in text
        assert "github-annotations" in text


def test_unknown_platform_raises():
    try:
        render_ci_template("azure")
    except ValueError as exc:
        assert "azure" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_all_platforms_registered():
    assert set(PLATFORMS) == {"github", "gitlab", "bitbucket"}
