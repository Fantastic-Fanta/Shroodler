from __future__ import annotations

import json

from shroodler.tickets import (
    GhBackend,
    MemoryBackend,
    _issue_number_from_gh_output,
    load_state,
    plan_tickets,
    run_ticket_command,
    ticket_key,
)


def _finding(fid: str, url: str, *, severity: str = "medium") -> dict:
    return {
        "id": fid,
        "severity": severity,
        "category": "header",
        "url": url,
        "description": f"{fid} on {url}",
        "evidence": "e",
        "confidence": "confirmed",
    }


def _scan(*findings: dict) -> dict:
    return {"target": "http://127.0.0.1:9", "findings": list(findings)}


def _write(tmp_path, name: str, doc: dict) -> str:
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


def test_ticket_key_matches_diff_key():
    f = _finding("missing-csp", "http://127.0.0.1:9/login?x=1")
    assert ticket_key(f) == "missing-csp|/login"


def test_plan_files_new_findings_and_skips_known():
    current = _scan(
        _finding("missing-csp", "http://127.0.0.1:9/"),
        _finding("missing-hsts", "http://127.0.0.1:9/"),
    )
    baseline = {
        "expected_findings": [_finding("missing-csp", "http://127.0.0.1:9/")],
        "expected_pages": [],
    }
    plan = plan_tickets(
        current,
        baseline=baseline,
        state={"missing-hsts|/": {"number": 3, "url": "memory://issue/3"}},
    )
    assert [c["key"] for c in plan.create] == []
    assert plan.skip[0]["key"] == "missing-hsts|/"
    plan2 = plan_tickets(current, baseline=baseline, state={})
    assert [c["key"] for c in plan2.create] == ["missing-hsts|/"]


def test_sync_closes_resolved_and_apply_uses_fake_backend(tmp_path):
    current_path = _write(
        tmp_path, "scan.json", _scan(_finding("missing-csp", "http://127.0.0.1:9/"))
    )
    state_path = tmp_path / "tickets.json"
    state_path.write_text(
        json.dumps(
            {
                "issues": {
                    "missing-csp|/": {"number": 1, "url": "memory://issue/1"},
                    "missing-hsts|/": {"number": 2, "url": "memory://issue/2"},
                }
            }
        ),
        encoding="utf-8",
    )
    backend = MemoryBackend()
    out = run_ticket_command(
        findings_path=current_path,
        state_path=state_path,
        close_resolved=True,
        apply=True,
        backend=backend,
    )
    assert out["applied"] is True
    assert out["dry_run"] is False
    assert out["close"] == 1
    assert backend.closed == [2]
    assert "missing-hsts|/" not in load_state(state_path)
    assert "missing-csp|/" in load_state(state_path)


def test_dry_run_does_not_call_backend_or_write_state(tmp_path):
    current_path = _write(
        tmp_path, "scan.json", _scan(_finding("x-powered-by", "http://127.0.0.1:9/"))
    )
    state_path = tmp_path / "tickets.json"
    backend = MemoryBackend()
    out = run_ticket_command(
        findings_path=current_path,
        state_path=state_path,
        apply=False,
        backend=backend,
    )
    assert out["dry_run"] is True
    assert out["create"] == 1
    assert backend.created == []
    assert not state_path.exists()


def test_apply_files_once_then_skips_duplicate(tmp_path):
    current_path = _write(
        tmp_path,
        "scan.json",
        _scan(_finding("missing-csp", "http://127.0.0.1:9/", severity="high")),
    )
    state_path = tmp_path / "tickets.json"
    backend = MemoryBackend()
    owners = [{"id": "missing-csp", "url": "*", "owner": "platform"}]
    first = run_ticket_command(
        findings_path=current_path,
        state_path=state_path,
        owners=owners,
        apply=True,
        backend=backend,
    )
    assert first["create"] == 1
    assert backend.created[0]["assignee"] == "platform"
    assert "platform" in backend.created[0]["body"]
    second = run_ticket_command(
        findings_path=current_path,
        state_path=state_path,
        apply=True,
        backend=backend,
    )
    assert second["create"] == 0
    assert second["skip"] == 1
    assert len(backend.created) == 1


def test_gh_backend_parses_issue_url_and_never_used_in_unit_tests():
    assert _issue_number_from_gh_output("https://github.com/acme/app/issues/42\n") == 42
    calls: list[list[str]] = []

    class FakeProc:
        returncode = 0
        stdout = "https://github.com/acme/app/issues/9\n"
        stderr = ""

    def fake_run(cmd, **_kwargs):
        calls.append(cmd)
        return FakeProc()

    backend = GhBackend(repo="acme/app", run=fake_run, gh="gh")
    ref = backend.create("t", "b", labels=["shroodler"], assignee="alice")
    assert ref.number == 9
    assert calls[0][:3] == ["gh", "issue", "create"]
    assert "--repo" in calls[0]
    backend.close(9)
    assert calls[1][:3] == ["gh", "issue", "close"]


def test_cli_ticket_file_is_dry_run_by_default(tmp_path):
    from shroodler.cli import build_parser, cmd_ticket_file

    scan = _write(tmp_path, "scan.json", _scan(_finding("missing-csp", "http://127.0.0.1:9/")))
    parser = build_parser()
    args = parser.parse_args(
        [
            "ticket",
            "file",
            scan,
            "--state",
            str(tmp_path / "st.json"),
            "--output",
            str(tmp_path / "out.json"),
        ]
    )
    assert args.func is cmd_ticket_file
    assert args.apply is False
