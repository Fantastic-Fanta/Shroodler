from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from shroodler.program import (
    apply_program_ids,
    coverage_gaps,
    extract_object_ids,
    load,
    mark_tested,
    merge_crawl,
    merge_crawl_doc,
    save,
    stale_sessions,
    url_to_pattern,
)


def test_load_creates_missing_state(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("etoro-bugcrowd")
    assert state.slug == "etoro-bugcrowd"
    path = tmp_path / ".shroodler" / "programs" / "etoro-bugcrowd" / "state.json"
    assert path.is_file()


def test_save_is_atomic(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("p1")
    state.scope_urls = ["https://app.example/"]
    save(state)
    path = tmp_path / ".shroodler" / "programs" / "p1" / "state.json"
    assert path.is_file()
    assert not path.with_name("state.json.tmp").exists()
    data = json.loads(path.read_text())
    assert data["scope_urls"] == ["https://app.example/"]


def test_extract_object_ids_uuid_and_named_ints():
    body = json.dumps(
        {
            "id": 10464573,
            "user_id": "99",
            "accountId": "550e8400-e29b-41d4-a716-446655440000",
            "nested": {"order_id": 7, "name": "x"},
            "skip": True,
        }
    )
    ids = extract_object_ids(body)
    assert "10464573" in ids
    assert "99" in ids
    assert "550e8400-e29b-41d4-a716-446655440000" in ids
    assert "7" in ids


def test_merge_crawl_seeds_form_and_xhr_params(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    delta = merge_crawl_doc(
        state,
        {
            "scan_finished_at": "2026-09-01T00:00:00Z",
            "pages": [
                {
                    "url": "http://127.0.0.1:8080/WebGoat/start.mvc#SqlInjection",
                    "status_code": 200,
                    "params": ["tab"],
                    "forms": [
                        {
                            "action": "/WebGoat/SqlInjection/attack2",
                            "method": "POST",
                            "fields": [
                                {"name": "username", "type": "text", "hidden": False},
                                {"name": "password", "type": "password", "hidden": False},
                            ],
                        }
                    ],
                }
            ],
            "xhr_endpoints": [
                {
                    "url": "http://127.0.0.1:8080/WebGoat/SqlInjection/attack2",
                    "method": "POST",
                    "params": [
                        {"name": "username", "value": "guest", "in": "body"},
                        {"name": "query", "value": "select", "in": "body"},
                    ],
                }
            ],
        },
    )
    attack = "http://127.0.0.1:8080/WebGoat/SqlInjection/attack2"
    start = "http://127.0.0.1:8080/WebGoat/start.mvc"
    assert attack in state.endpoints
    assert start in state.endpoints
    assert state.endpoints[attack]["method"] == "POST"
    names = {p["name"] for p in state.endpoints[attack]["params"]}
    assert names == {"username", "password", "query"}
    assert delta["new_endpoints"] >= 2


def test_merge_crawl_dedup_and_object_ids(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    crawl = tmp_path / "crawl.json"
    uuid = "123e4567-e89b-12d3-a456-426614174000"
    doc = {
        "target": "http://127.0.0.1/",
        "scan_finished_at": "2026-09-01T00:00:00Z",
        "pages": [
            {
                "url": "http://127.0.0.1/api/users/1",
                "status_code": 200,
                "body": json.dumps({"id": 1, "user_id": 2, "uuid": uuid}),
            },
            {
                "url": "http://127.0.0.1/api/users/1",
                "status_code": 200,
                "body": json.dumps({"id": 1}),
            },
        ],
        "findings": [
            {
                "id": "missing-hsts",
                "severity": "medium",
                "category": "header",
                "url": "http://127.0.0.1/api/users/1",
                "description": "no hsts",
            },
            {
                "id": "missing-hsts",
                "severity": "medium",
                "category": "header",
                "url": "http://127.0.0.1/api/users/1",
                "description": "duplicate",
            },
        ],
    }
    crawl.write_text(json.dumps(doc), encoding="utf-8")
    delta = merge_crawl(state, crawl)
    assert delta["new_endpoints"] == 1
    assert delta["new_findings"] == 1
    assert len(state.findings) == 1
    pattern = url_to_pattern("http://127.0.0.1/api/users/1")
    assert pattern == "/api/users/{id}"
    assert "1" in state.object_ids[pattern]
    assert "2" in state.object_ids[pattern]
    assert uuid in state.object_ids[pattern]

    delta2 = merge_crawl_doc(state, doc)
    assert delta2["new_endpoints"] == 0
    assert delta2["new_findings"] == 0
    assert len(state.findings) == 1


def test_coverage_gaps_ordering_and_tested_flags(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    merge_crawl_doc(
        state,
        {
            "scan_finished_at": "2026-01-01T00:00:00Z",
            "pages": [
                {"url": "http://x/old", "status_code": 200},
            ],
        },
    )
    merge_crawl_doc(
        state,
        {
            "scan_finished_at": "2026-02-01T00:00:00Z",
            "pages": [
                {"url": "http://x/new", "status_code": 200},
            ],
        },
    )
    gaps = coverage_gaps(state)
    assert [g["url"] for g in gaps] == ["http://x/new", "http://x/old"]
    mark_tested(state, ["http://x/new"], "tested_authz")
    gaps = coverage_gaps(state)
    # still a gap: peer-write untested
    assert any(g["url"] == "http://x/new" and g["tested_authz"] for g in gaps)
    mark_tested(state, ["http://x/new"], "tested_peer_write")
    gaps = coverage_gaps(state)
    assert "http://x/new" not in [g["url"] for g in gaps]
    assert gaps[0]["url"] == "http://x/old"


def test_stale_sessions_older_than_24h(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    old = (datetime.now(timezone.utc) - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
    fresh = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    state.sessions = [
        {"label": "owner", "path": "/tmp/a.json", "captured_at": old, "expires_hint": None},
        {"label": "peer", "path": "/tmp/b.json", "captured_at": fresh, "expires_hint": None},
    ]
    stale = stale_sessions(state)
    assert [s["label"] for s in stale] == ["owner"]


def test_apply_program_ids_expands_writes(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    state = load("lab")
    state.object_ids["/api/orders/{id}"] = ["10", "20"]
    playbook = {
        "target": "http://x/",
        "writes": [
            {
                "method": "POST",
                "url": "http://x/api/orders/10",
                "body": '{"id":"10"}',
                "id_value": "10",
            }
        ],
    }
    out = apply_program_ids(playbook, state)
    ids = {w["id_value"] for w in out["writes"]}
    assert ids == {"10", "20"}
    assert any(w["url"].endswith("/api/orders/20") for w in out["writes"])


def test_program_cli_roundtrip(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    from shroodler.cli import build_parser

    scope = tmp_path / "scope.txt"
    scope.write_text("https://app.example/\n!https://out.example/\n", encoding="utf-8")
    parser = build_parser()

    args = parser.parse_args(["program", "init", "lab", "--scope-file", str(scope)])
    assert args.func(args) == 0
    capsys.readouterr()

    crawl = tmp_path / "crawl.json"
    crawl.write_text(
        json.dumps(
            {
                "scan_finished_at": "2026-09-01T00:00:00Z",
                "pages": [
                    {
                        "url": "https://app.example/api/x",
                        "status_code": 200,
                        "body": '{"id": 9}',
                    }
                ],
                "findings": [
                    {
                        "id": "missing-hsts",
                        "severity": "medium",
                        "category": "header",
                        "url": "https://app.example/api/x",
                        "description": "no hsts",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    args = parser.parse_args(["program", "merge", "lab", str(crawl)])
    assert args.func(args) == 0
    merged = json.loads(capsys.readouterr().out)
    assert merged["new_endpoints"] == 1
    assert merged["new_findings"] == 1

    args = parser.parse_args(
        ["program", "add-session", "lab", "/tmp/owner.json", "--label", "owner"]
    )
    assert args.func(args) == 0
    capsys.readouterr()

    args = parser.parse_args(["program", "status", "lab"])
    assert args.func(args) == 0
    status = capsys.readouterr().out
    assert "endpoints: 1" in status
    assert "findings: 1" in status
    assert "coverage gaps" in status
