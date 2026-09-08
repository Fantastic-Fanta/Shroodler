from __future__ import annotations

import json

from shroodler.cookie_source import (
    load_captured_sessions,
    load_cookie_header,
    merge_cookie_headers,
    resolve_cookie_header,
    sessions_from_har,
)
from shroodler.peer_write import infer_id_value, writes_from_sessions


def test_storage_state_and_name_value_pairs(tmp_path):
    path = tmp_path / "state.json"
    path.write_text(
        json.dumps({"cookies": [{"name": "sessionid", "value": "abc", "domain": "127.0.0.1"}]}),
        encoding="utf-8",
    )
    assert "sessionid=abc" in load_cookie_header(path, "http://127.0.0.1/")
    merged = resolve_cookie_header(
        pairs=["extra=1"],
        path=path,
        origin_url="http://127.0.0.1/",
    )
    assert "sessionid=abc" in merged
    assert "extra=1" in merged


def test_netscape_jar(tmp_path):
    path = tmp_path / "cookies.txt"
    path.write_text(
        "# Netscape HTTP Cookie File\n"
        "127.0.0.1\tFALSE\t/\tFALSE\t0\tsid\txyz\n",
        encoding="utf-8",
    )
    assert load_cookie_header(path, "http://127.0.0.1/") == "sid=xyz"


def test_sessions_jsonl(tmp_path):
    path = tmp_path / "sess.jsonl"
    path.write_text(
        json.dumps(
            {
                "request": {
                    "method": "GET",
                    "url": "http://127.0.0.1/me",
                    "headers": {"Cookie": "a=1"},
                },
                "response": {"status_code": 200, "headers": {}},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    assert load_cookie_header(path, "http://127.0.0.1/me") == "a=1"


def test_har_sessions_and_write_extract(tmp_path):
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "http://127.0.0.1/photo/10464573/",
                        "headers": [
                            {"name": "Cookie", "value": "s=owner"},
                            {"name": "Content-Type", "value": "application/json"},
                        ],
                        "postData": {"text": '{"title":"x"}'},
                    },
                    "response": {"status": 200, "headers": []},
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "http://127.0.0.1/photo/10464573/",
                        "headers": [],
                    },
                    "response": {"status": 200, "headers": []},
                },
            ]
        }
    }
    path = tmp_path / "cap.har"
    path.write_text(json.dumps(har), encoding="utf-8")
    sessions = load_captured_sessions(path)
    assert len(sessions) == 2
    writes = writes_from_sessions(sessions, target="http://127.0.0.1/")
    assert len(writes) == 1
    assert writes[0]["id_value"] == "10464573"
    assert writes[0]["method"] == "POST"
    assert "s=owner" in load_cookie_header(path, "http://127.0.0.1/photo/10464573/")
    assert sessions_from_har(har)[0]["request"]["url"].endswith("/10464573/")
    assert sessions_from_har(har)[0]["request"]["body"]["content"] == '{"title":"x"}'


def test_har_captures_response_body_and_skips_non_http():
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://127.0.0.1/note",
                        "headers": [{"name": "Accept", "value": "text/html"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "text/html"}],
                        "content": {"mimeType": "text/html", "text": "<html>secret</html>"},
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "chrome-extension://abc/page.html",
                        "headers": [],
                    },
                    "response": {"status": 200, "headers": [], "content": {"text": "nope"}},
                },
            ]
        }
    }
    sessions = sessions_from_har(har)
    assert len(sessions) == 1
    assert sessions[0]["response"]["body"]["content"] == "<html>secret</html>"
    assert sessions[0]["response"]["status_code"] == 200


def test_seed_urls_accepts_har(tmp_path):
    from shroodler.sessions import seed_urls

    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://127.0.0.1/hidden/api",
                        "headers": [],
                    },
                    "response": {"status": 200, "headers": [], "content": {"text": "ok"}},
                }
            ]
        }
    }
    path = tmp_path / "cap.har"
    path.write_text(json.dumps(har), encoding="utf-8")
    seeds = seed_urls(load_captured_sessions(path), "http://127.0.0.1/")
    assert seeds == ["http://127.0.0.1/hidden/api"]


def test_merge_cookie_headers_skips_junk():
    assert merge_cookie_headers("a=1; ; =x", "b=2") == "a=1; b=2"


def test_malformed_har_entries_are_skipped():
    assert sessions_from_har({"log": {"entries": ["nope"]}}) == []


def test_infer_id_skips_short_versions():
    assert infer_id_value("http://x/v1/photo/99") is None
    assert infer_id_value("http://x/v1/photo/10464573") == "10464573"
