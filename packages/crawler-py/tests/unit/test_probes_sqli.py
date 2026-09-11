from __future__ import annotations

from datetime import timedelta

from shroodler.pacer import Pacer
from shroodler.probes.sqli import probe_sqli


class FakeResp:
    def __init__(self, status=200, text="", elapsed=0.0):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.elapsed = timedelta(seconds=elapsed)
        self.headers = {}


class FakeClient:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.handler(method, url, kw)

    def close(self):
        pass


def _values(kw) -> list[str]:
    params = kw.get("params") or {}
    data = kw.get("data") or {}
    if isinstance(params, dict):
        out = [str(v) for v in params.values()]
    else:
        out = []
    if isinstance(data, dict):
        out.extend(str(v) for v in data.values())
    return out


def test_sqli_error_based_confirmed():
    def handler(method, url, kw):
        if any("'" in v for v in _values(kw)):
            return FakeResp(200, "You have an error in your SQL syntax")
        return FakeResp(200, "ok")

    findings = probe_sqli(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q", "value": "test"}],
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "sqli")
    assert hit.severity == "critical"
    assert hit.confidence == "confirmed"
    assert hit.url == "http://127.0.0.1/search"
    assert hit.category == "payload"


def test_sqli_skips_when_no_params():
    called = []

    def handler(method, url, kw):
        called.append(url)
        return FakeResp(200, "SQL syntax")

    findings = probe_sqli(
        "http://127.0.0.1/search",
        "GET",
        [],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert findings == []
    assert called == []


def test_sqli_blind_uses_response_elapsed_not_sleep():
    def handler(method, url, kw):
        if any("WAITFOR" in v for v in _values(kw)):
            return FakeResp(200, "ok", elapsed=2.4)
        return FakeResp(200, "ok", elapsed=0.1)

    findings = probe_sqli(
        "http://127.0.0.1/search",
        "POST",
        [{"name": "id"}],
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "sqli-blind")
    assert hit.confidence == "heuristic"
    assert hit.severity == "critical"


def test_sqli_clean_response_is_not_a_finding():
    findings = probe_sqli(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q"}],
        "",
        client=FakeClient(lambda *a, **k: FakeResp(200, "hello world")),
        pacer=Pacer(0),
    )
    assert findings == []


def test_sqli_network_error_returns_empty():
    class Boom:
        def request(self, *a, **k):
            raise ConnectionError("down")

        def close(self):
            pass

    findings = probe_sqli(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q"}],
        "",
        client=Boom(),
        pacer=Pacer(0),
    )
    assert findings == []


def test_sqli_hsql_exception_is_confirmed():
    def handler(method, url, kw):
        if any("'" in v for v in _values(kw)):
            return FakeResp(200, "org.hsqldb.HsqlException: unexpected token: OR")
        return FakeResp(200, "ok")

    findings = probe_sqli(
        "http://127.0.0.1/SqlInjection/attack2",
        "POST",
        [{"name": "query"}],
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "sqli")
    assert hit.confidence == "confirmed"
    assert hit.severity == "critical"


def test_sqli_webgoat_lesson_output_is_confirmed():
    import json

    payload = json.dumps(
        {
            "lessonCompleted": False,
            "feedback": "You are close",
            "output": "USERID | NAME\n1 | admin",
        }
    )

    def handler(method, url, kw):
        if any("'" in v for v in _values(kw)):
            return FakeResp(200, payload)
        return FakeResp(200, json.dumps({"lessonCompleted": False, "output": ""}))

    findings = probe_sqli(
        "http://127.0.0.1/SqlInjection/attack2",
        "POST",
        [{"name": "query"}],
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "sqli")
    assert hit.confidence == "confirmed"


def test_sqli_webgoat_empty_output_is_not_a_finding():
    import json

    body = json.dumps(
        {"lessonCompleted": False, "feedback": "try again", "output": ""}
    )
    findings = probe_sqli(
        "http://127.0.0.1/SqlInjection/attack2",
        "POST",
        [{"name": "query"}],
        "",
        client=FakeClient(lambda *a, **k: FakeResp(200, body)),
        pacer=Pacer(0),
    )
    assert findings == []


def _is_4s_payload(values: list[str]) -> bool:
    return any(
        "SLEEP(4)" in v
        or "pg_sleep(4)" in v
        or "WAITFOR DELAY '0:0:4'" in v
        or "RANDOMBLOB" in v
        for v in values
    )


def test_sqli_time_based_confirmed_on_sleep_payload():
    def handler(method, url, kw):
        if _is_4s_payload(_values(kw)):
            return FakeResp(200, "ok", elapsed=4.2)
        return FakeResp(200, "ok", elapsed=0.2)

    findings = probe_sqli(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q", "value": "test"}],
        "session=owner",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "sqli-time-based")
    assert hit.confidence == "confirmed"
    assert hit.severity == "high"
    assert hit.category == "payload"
    assert "elapsed=" in (hit.evidence or "")
    assert "SLEEP(4)" in (hit.evidence or "") or "WAITFOR" in (hit.evidence or "")
    assert not any(f.id == "sqli-blind" for f in findings)
    assert not any(f.id == "sqli-boolean-blind" for f in findings)


def test_sqli_time_based_skips_slow_baseline():
    def handler(method, url, kw):
        return FakeResp(200, "ok", elapsed=2.5)

    findings = probe_sqli(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert not any(f.id in {"sqli-time-based", "sqli-blind"} for f in findings)


def test_sqli_boolean_blind_heuristic_on_length():
    def handler(method, url, kw):
        values = _values(kw)
        if any("'1'='1" in v for v in values):
            return FakeResp(200, "x" * 200)
        if any("'1'='2" in v for v in values):
            return FakeResp(200, "x" * 10)
        return FakeResp(200, "ok", elapsed=0.05)

    findings = probe_sqli(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "sqli-boolean-blind")
    assert hit.confidence == "heuristic"
    assert hit.severity == "high"
    assert hit.category == "payload"


def test_sqli_boolean_blind_heuristic_on_status():
    def handler(method, url, kw):
        values = _values(kw)
        if any("'1'='1" in v for v in values):
            return FakeResp(200, "ok")
        if any("'1'='2" in v for v in values):
            return FakeResp(500, "ok")
        return FakeResp(200, "ok", elapsed=0.05)

    findings = probe_sqli(
        "http://127.0.0.1/search",
        "POST",
        [{"name": "id"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    hit = next(f for f in findings if f.id == "sqli-boolean-blind")
    assert hit.confidence == "heuristic"
    assert hit.severity == "high"


def test_sqli_error_based_skips_time_and_boolean():
    calls = []

    def handler(method, url, kw):
        calls.append(_values(kw))
        if any("'" in v for v in _values(kw)):
            return FakeResp(200, "You have an error in your SQL syntax")
        return FakeResp(200, "ok")

    findings = probe_sqli(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q", "value": "test"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert [f.id for f in findings] == ["sqli"]
    blobs = " ".join(v for row in calls for v in row)
    assert "SLEEP(4)" not in blobs
    assert "'1'='2" not in blobs


def test_sqli_time_based_skips_boolean():
    def handler(method, url, kw):
        if _is_4s_payload(_values(kw)):
            return FakeResp(200, "ok", elapsed=5.0)
        return FakeResp(200, "ok", elapsed=0.1)

    findings = probe_sqli(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q"}],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    ids = [f.id for f in findings]
    assert "sqli-time-based" in ids
    assert "sqli-boolean-blind" not in ids


def test_sqli_boolean_same_response_is_not_a_finding():
    findings = probe_sqli(
        "http://127.0.0.1/search",
        "GET",
        [{"name": "q"}],
        "",
        client=FakeClient(lambda *a, **k: FakeResp(200, "hello world", elapsed=0.05)),
        pacer=Pacer(0),
    )
    assert findings == []


def test_sqli_time_based_skips_path_params():
    calls: list[tuple[str, dict]] = []

    def handler(method, url, kw):
        calls.append((url, kw))
        return FakeResp(200, "ok", elapsed=0.05)

    findings = probe_sqli(
        "http://127.0.0.1/guilds/1/events/1",
        "GET",
        [
            {"name": "id", "value": "1", "in": "path", "type": "integer"},
            {"name": "id2", "value": "1", "in": "path", "type": "integer"},
        ],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    blob = " ".join(url for url, _ in calls)
    blob += " " + " ".join(v for _, kw in calls for v in _values(kw))
    assert "SLEEP" not in blob
    assert "WAITFOR" not in blob
    assert "pg_sleep" not in blob
    assert not any(f.id in {"sqli-time-based", "sqli-blind"} for f in findings)


def test_sqli_time_based_runs_on_query_when_path_ids_present():
    def handler(method, url, kw):
        if _is_4s_payload(_values(kw)):
            return FakeResp(200, "ok", elapsed=4.2)
        return FakeResp(200, "ok", elapsed=0.1)

    findings = probe_sqli(
        "http://127.0.0.1/guilds/1/search",
        "GET",
        [
            {"name": "id", "value": "1", "in": "path", "type": "integer"},
            {"name": "q", "value": "test", "in": "query"},
        ],
        "",
        client=FakeClient(handler),
        pacer=Pacer(0),
    )
    assert any(f.id == "sqli-time-based" for f in findings)
