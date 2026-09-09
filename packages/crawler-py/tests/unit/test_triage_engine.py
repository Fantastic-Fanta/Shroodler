"""Finding triage / submit-report scoring.

Finding has no reproduction, param_name, or tags fields. Reproduction
for scoring is a curl block in description (len>20); param_name is
parsed from evidence `param=` or the URL query string.
"""

from __future__ import annotations

from shroodler.cli import build_parser
from shroodler.models import Finding
from shroodler.pentest_report import format_submit
from shroodler.triage_engine import score_finding, severity_label, triage_findings

_CURL = "curl -sS -i 'http://127.0.0.1/search?q=1'"


def _finding(**kwargs) -> Finding:
    data = {
        "id": "missing-csp",
        "severity": "medium",
        "category": "payload",
        "url": "http://127.0.0.1/search",
        "description": "test finding",
        "evidence": None,
    }
    data.update(kwargs)
    return Finding(**data)


def test_sqli_error_with_reproduction_modifier():
    # id `sqli` (and `sqli-error`) is treated as error-based: base 80.
    # Finding.reproduction does not exist — a long curl in description
    # is the +5 reproduction modifier. param= in evidence is +5.
    finding = _finding(
        id="sqli-error",
        description=f"Error-based SQLi. Reproduce with: {_CURL}",
        evidence="param=q payload='",
        url="http://127.0.0.1/search",
    )
    result = score_finding(finding)
    assert result.exploitability == 90
    assert result.confidence == 90
    assert result.worth_submitting is True


def test_xss_reflected_base_worth_submitting():
    finding = _finding(
        id="xss-reflected",
        description="Reflected XSS marker echoed in the response body.",
        evidence="marker echoed",
        url="http://127.0.0.1/search",
    )
    result = score_finding(finding)
    assert result.exploitability == 65
    assert result.confidence == 85
    assert result.worth_submitting is True


def test_js_api_endpoint_found_not_worth():
    finding = _finding(
        id="js-api-endpoint-found",
        severity="medium",
        category="js-endpoint",
        url="http://127.0.0.1/app.js",
        description="JS bundle references API endpoint /api/users",
        evidence="/api/users",
    )
    result = score_finding(finding)
    assert result.exploitability == 10
    assert result.worth_submitting is False


def test_login_recipe_failed_zero_not_worth():
    finding = _finding(
        id="login-recipe-failed",
        category="scan-note",
        url="http://127.0.0.1/login",
        description="Login recipe failed; probes continue without a session.",
        evidence="login failed",
    )
    result = score_finding(finding)
    assert result.exploitability == 0
    assert result.worth_submitting is False


def test_sqli_time_based_confidence_under_threshold():
    finding = _finding(
        id="sqli-time-based",
        description="Time-based SQLi delay observed against the search form.",
        evidence="elapsed_ms=5200",
        url="http://127.0.0.1/search",
    )
    result = score_finding(finding)
    assert result.confidence == 60
    assert result.exploitability >= 50
    assert result.worth_submitting is False


def test_suggested_title_xss_stored_and_idor():
    xss = score_finding(
        _finding(
            id="xss-stored",
            url="http://127.0.0.1/comment?q=1",
            description="Stored XSS in the comment field.",
            evidence="param=q payload=<script>",
        )
    )
    assert xss.suggested_title == "Stored XSS on /comment via q parameter"
    idor = score_finding(
        _finding(
            id="idor-cross-account",
            category="auth",
            url="http://127.0.0.1/api/users/2",
            description="Peer session can read another user's object.",
            evidence="owner=200 peer=200",
        )
    )
    assert idor.suggested_title == (
        "Cross-Account IDOR on /api/users/2 via unknown parameter"
    )


def test_suggested_severity_mapping():
    assert severity_label(92) == "critical"
    assert severity_label(71) == "high"
    assert severity_label(55) == "medium"
    assert severity_label(30) == "low"
    assert severity_label(10) == "informational"


def test_triage_findings_sorted_by_exploitability_desc():
    findings = [
        _finding(id="js-api-endpoint-found", category="js-endpoint", description="info"),
        _finding(
            id="xss-reflected",
            description="reflected xss",
            evidence="marker",
        ),
        _finding(
            id="idor-cross-account",
            category="auth",
            url="http://127.0.0.1/api/users/2",
            description="cross account",
        ),
    ]
    results = triage_findings(findings)
    scores = [item.exploitability for item in results]
    assert scores == sorted(scores, reverse=True)
    assert results[0].finding.id == "idor-cross-account"


def test_triage_findings_dedup_keeps_highest():
    high = _finding(
        id="xss-reflected",
        severity="high",
        url="http://127.0.0.1/search?q=1",
        description="reflected xss high",
        evidence="param=q payload=<script>",
    )
    low = _finding(
        id="xss-reflected",
        severity="medium",
        url="http://127.0.0.1/search?q=2",
        description="reflected xss low",
        evidence="param=q payload=<script>",
    )
    results = triage_findings([low, high])
    assert len(results) == 2
    winners = [item for item in results if item.worth_submitting]
    losers = [item for item in results if not item.worth_submitting]
    assert len(winners) == 1
    assert winners[0].finding.severity == "high"
    assert losers[0].finding.severity == "medium"
    assert losers[0].worth_submitting is False


def test_reproduction_steps_from_description_curl():
    # Finding.reproduction does not exist; curl is parsed from description.
    finding = _finding(
        id="xss-reflected",
        description=f"Reflected XSS. Replay: {_CURL}",
        evidence="param=q payload=<script>",
        url="http://127.0.0.1/search?q=1",
    )
    result = score_finding(finding)
    joined = " ".join(result.reproduction_steps)
    assert any(step.startswith("Send the following request:") for step in result.reproduction_steps)
    assert "curl" in joined
    assert any(step.startswith("Observe:") for step in result.reproduction_steps)
    assert any("Reflected XSS" in step for step in result.reproduction_steps)


def test_reproduction_steps_generic_replay_without_curl():
    finding = _finding(
        id="xss-reflected",
        description="Reflected XSS marker echoed.",
        evidence="marker",
        url="http://127.0.0.1/search",
    )
    result = score_finding(finding)
    assert result.reproduction_steps[0] == "Replay the request to http://127.0.0.1/search"


def test_format_submit_has_header_and_steps():
    finding = _finding(
        id="xss-reflected",
        url="http://127.0.0.1/search?q=1",
        description=f"Reflected XSS. Replay: {_CURL}",
        evidence="param=q payload=<script>",
    )
    md = format_submit([finding])
    assert "## " in md
    assert "Steps to Reproduce" in md
    assert "Suggested Remediation" in md
    assert "Reflected XSS" in md


def test_cli_triage_findings_parses_min_score_and_format():
    p = build_parser()
    args = p.parse_args(
        ["triage-findings", "state.json", "--min-score", "50", "--format", "text"]
    )
    assert args.command == "triage-findings"
    assert args.min_score == 50
    assert args.format == "text"
    args = p.parse_args(
        [
            "triage-findings",
            "state.json",
            "--min-confidence",
            "70",
            "--format",
            "submit",
            "--output",
            "out.md",
        ]
    )
    assert args.min_confidence == 70
    assert args.format == "submit"
    assert args.output == "out.md"
    args = p.parse_args(["report", "out.json", "--format", "submit"])
    assert args.format == "submit"
