from __future__ import annotations

import json

import pytest

from shroodler.pacer import Pacer
from shroodler.peer_write import (
    infer_id_value,
    json_write_rejected,
    load_playbook,
    run,
    swap_id_in_body,
    swap_object_id,
    writes_from_sessions,
)


def _pacer() -> Pacer:
    return Pacer(0)


def _playbook(origin: str, writes: list[dict]) -> dict:
    return {"target": origin + "/", "writes": writes}


def _write(origin: str, path: str = "/photo/10464573", **extra: object) -> dict:
    row = {
        "method": "POST",
        "url": origin + path,
        "body": "{}",
        "id_value": "10464573",
    }
    row.update(extra)
    return row


def test_refuses_external_without_allow_external():
    with pytest.raises(ValueError, match="non-local"):
        run({"target": "https://example.com/", "writes": []})


def test_allow_external_empty_writes():
    out = run({"target": "https://example.com/", "writes": []}, allow_external=True)
    assert out == {"target": "https://example.com/", "findings": [], "checked": []}


def test_swap_object_id_is_segment_exact():
    url = "http://x/photo/10464573/?next=10464573"
    assert swap_object_id(url, "10464573", "1").endswith("/photo/1/?next=1")
    assert swap_object_id("http://x/photo/104645730/", "10464573", "1") == "http://x/photo/104645730/"


def test_swap_id_in_body_replaces_json_values_only():
    assert swap_id_in_body("", "1", "2") == ""
    assert swap_id_in_body("not-json", "1", "2") == "not-json"
    assert '"id":2' in swap_id_in_body('{"id": 1, "name": "x1"}', "1", "2")
    assert "x1" in swap_id_in_body('{"id": 1, "name": "x1"}', "1", "2")


def test_infer_id_from_json_body():
    assert infer_id_value("http://x/save", '{"photo_id": 10464573}') == "10464573"
    assert infer_id_value("http://x/save", '{"id": "10464573"}') == "10464573"
    assert infer_id_value("http://x/save", "nope") is None


def test_json_write_rejected_error_field():
    assert json_write_rejected('{"error": "denied"}')


def test_writes_from_sessions_filters_and_caps():
    sessions = [
        {"request": {"method": "GET", "url": "http://127.0.0.1/photo/10464573"}},
        {
            "request": {
                "method": "POST",
                "url": "http://127.0.0.1/photo/10464573",
                "headers": {"Host": "127.0.0.1", "Content-Type": "application/json"},
                "body": {"encoding": "utf8", "content": "{}"},
            }
        },
        {
            "request": {
                "method": "POST",
                "url": "http://example.com/photo/10464573",
                "body": {"encoding": "utf8", "content": "{}"},
            }
        },
        {
            "request": {
                "method": "POST",
                "url": "http://127.0.0.1/photo/99999",
                "body": {"encoding": "utf8", "content": "{}"},
            }
        },
    ]
    writes = writes_from_sessions(sessions, target="http://127.0.0.1/", only_id="10464573")
    assert len(writes) == 1
    assert writes[0]["id_value"] == "10464573"
    assert "Host" not in writes[0]["headers"]
    many = [
        {
            "request": {
                "method": "POST",
                "url": f"http://127.0.0.1/photo/{1000 + i}",
                "body": {"encoding": "utf8", "content": "{}"},
            }
        }
        for i in range(3)
    ]
    assert len(writes_from_sessions(many, max_writes=2)) == 2


def test_load_playbook_from_sessions_infers_target(tmp_path):
    path = tmp_path / "s.jsonl"
    path.write_text(
        '{"request":{"method":"POST","url":"http://127.0.0.1/photo/10464573",'
        '"body":{"encoding":"utf8","content":"{}"}}}\n',
        encoding="utf-8",
    )
    doc = load_playbook(sessions_path=str(path))
    assert doc["target"].startswith("http://127.0.0.1")
    assert doc["writes"][0]["id_value"] == "10464573"


def test_run_requires_target():
    with pytest.raises(ValueError, match="target"):
        run({"writes": []})


def test_json_write_rejected():
    assert json_write_rejected('{"success": false}')
    assert json_write_rejected('{"ok": false}')
    assert not json_write_rejected('{"success": true}')
    assert not json_write_rejected("not json")


def test_denied(fx):
    fx.on("POST", "/photo/1", lambda inc: (404, {}, b'{"detail":"no"}'))
    fx.on("POST", "/photo/10464573", lambda inc: (403, {}, b"forbidden"))
    out = run(
        _playbook(fx.origin, [_write(fx.origin)]),
        peer_cookie="session=b",
        pacer=_pacer(),
    )
    assert out["findings"] == []
    assert out["checked"][0]["verdict"] == "denied"


def test_dummy_success_same_body_as_nonsense(fx):
    payload = b'{"reload": true, "tags": []}'
    headers = {"Content-Type": "application/json"}
    fx.on("POST", "/photo/1/tags", lambda inc: (200, headers, payload))
    fx.on("POST", "/photo/10464573/tags", lambda inc: (200, headers, payload))
    out = run(
        _playbook(fx.origin, [_write(fx.origin, "/photo/10464573/tags")]),
        peer_cookie="session=b",
        pacer=_pacer(),
    )
    assert out["findings"] == []
    assert out["checked"][0]["verdict"] == "dummy-success"


def test_success_false_is_write_failure(fx):
    fx.on("POST", "/photo/1", lambda inc: (200, {}, b'{"success": false}'))
    fx.on("POST", "/photo/10464573", lambda inc: (200, {}, b'{"success": false}'))
    out = run(_playbook(fx.origin, [_write(fx.origin)]), pacer=_pacer())
    assert out["findings"] == []
    assert out["checked"][0]["verdict"] == "write-failure"


def test_idor_confirmed_when_owner_reread_changes(fx):
    store = {"title": "owner-title"}

    def peer_write(inc):
        if "session=peer" not in inc.cookies:
            return 403, {}, b"no"
        if inc.path.endswith("/1"):
            return 404, {"Content-Type": "application/json"}, b'{"detail":"missing"}'
        store["title"] = json.loads(inc.body.decode() or "{}").get("title", store["title"])
        return 200, {"Content-Type": "application/json"}, b'{"ok":true}'

    def owner_get(inc):
        if "session=owner" not in inc.cookies:
            return 403, {}, b"no"
        return 200, {"Content-Type": "application/json"}, json.dumps(store).encode()

    fx.on("POST", "/photo/1", peer_write)
    fx.on("POST", "/photo/10464573", peer_write)
    fx.on("GET", "/photo/10464573", owner_get)
    out = run(
        _playbook(
            fx.origin,
            [
                {
                    "method": "POST",
                    "url": fx.origin + "/photo/10464573",
                    "body": '{"title":"pwned"}',
                    "id_value": "10464573",
                    "verify": {"method": "GET", "url": fx.origin + "/photo/10464573"},
                }
            ],
        ),
        owner_cookie="session=owner",
        peer_cookie="session=peer",
        pacer=_pacer(),
    )
    assert {f["id"] for f in out["findings"]} == {"peer-write-idor"}
    assert out["findings"][0]["confidence"] == "confirmed"
    assert out["checked"][0]["verdict"] == "idor"
    assert out["checked"][0]["owner_changed"] is True
    assert store["title"] == "pwned"


def test_idor_probable_without_owner_confirm(fx):
    fx.on("POST", "/photo/1", lambda inc: (404, {}, b"no"))
    fx.on("POST", "/photo/10464573", lambda inc: (200, {}, b'{"ok":true}'))
    out = run(
        _playbook(fx.origin, [_write(fx.origin)]),
        peer_cookie="session=b",
        pacer=_pacer(),
    )
    assert out["findings"][0]["id"] == "peer-write-idor"
    assert out["findings"][0]["confidence"] == "probable"


def test_enforcer_blocks_before_any_request(fx):
    from shroodler_guardrails.policy import PolicyEnforcer, origin_of, parse_policy

    calls = []
    fx.on("POST", "/photo/10464573", lambda inc: calls.append(1) or (200, {}, b"x"))
    policy = parse_policy({"allow": ["/nope/*"]}, origin=origin_of(fx.origin))
    out = run(
        _playbook(fx.origin, [_write(fx.origin)]),
        enforcer=PolicyEnforcer(policy=policy),
        pacer=_pacer(),
    )
    assert not calls
    assert out["findings"] == []
    assert out["checked"][0]["verdict"] == "skipped"


def test_skips_missing_url_and_id():
    out = run(
        {
            "target": "http://127.0.0.1/",
            "writes": [
                {"method": "POST", "url": "", "body": "{}"},
                {"method": "POST", "url": "http://127.0.0.1/save", "body": "{}"},
            ],
        },
        pacer=_pacer(),
    )
    assert {row["verdict"] for row in out["checked"]} == {"skipped"}


def test_error_status_is_not_a_finding(fx):
    fx.on("POST", "/photo/1", lambda inc: (404, {}, b"no"))
    fx.on("POST", "/photo/10464573", lambda inc: (500, {}, b"boom"))
    out = run(_playbook(fx.origin, [_write(fx.origin)]), pacer=_pacer())
    assert out["findings"] == []
    assert out["checked"][0]["verdict"] == "error"


def test_challenge_is_recorded_not_solved(fx):
    body = b"Just a moment... checking your browser before accessing"
    fx.on("POST", "/photo/1", lambda inc: (403, {}, body))
    out = run(_playbook(fx.origin, [_write(fx.origin)]), pacer=_pacer())
    assert out["findings"] == []
    assert out["checked"][0]["verdict"] == "challenge"
