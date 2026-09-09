from __future__ import annotations

from shroodler.attack_chain import (
    AttackChain,
    ChainStep,
    interpolate,
    run_chain,
)


class _Resp:
    def __init__(self, status_code: int, text: str = "{}"):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8")


def test_interpolation():
    ctx = {
        "prev": {"id": "99", "token": "abc"},
        "create": {"id": "42"},
        "step_1": {"token": "tok"},
    }
    assert interpolate("http://x/{prev.id}", ctx) == "http://x/99"
    assert interpolate("/obj/{create.id}", ctx) == "/obj/42"
    assert interpolate("Bearer {step_1.token}", ctx) == "Bearer tok"


def test_random_template():
    once = interpolate("id={random}", {})
    assert once.startswith("id=")
    hexpart = once[3:]
    assert len(hexpart) == 12
    assert all(c in "0123456789abcdef" for c in hexpart)
    two = interpolate("{random}-{random}", {})
    left, right = two.split("-")
    assert left != right
    assert len(left) == 12 and len(right) == 12


def test_step_failure_stops_chain(monkeypatch):
    statuses = iter([200, 403])

    def fake_request(*args, **kwargs):
        return _Resp(next(statuses), '{"ok": true}')

    monkeypatch.setattr("shroodler.attack_chain.request", fake_request)
    chain = AttackChain(
        name="stop-on-fail",
        description="should stop",
        finding_id="chain-stop",
        steps=[
            ChainStep(id="one", url="http://127.0.0.1/a", expect_status=200),
            ChainStep(id="two", url="http://127.0.0.1/b", expect_status=200),
        ],
        success_condition="last.status == 200",
    )
    out = run_chain(chain)
    assert out["findings"] == []
    assert out["stopped_at"] == "two"
    assert out["urls_tested"] == 2


def test_success_condition_fires_finding(monkeypatch):
    monkeypatch.setattr(
        "shroodler.attack_chain.request",
        lambda *a, **k: _Resp(200, '{"id": "7"}'),
    )
    chain = AttackChain(
        name="idor",
        description="peer can read owner object",
        finding_id="chain-idor-peer-access",
        severity="high",
        steps=[
            ChainStep(
                id="owner_read",
                url="http://127.0.0.1/users/1",
                extract={"obj": "$.id"},
                expect_status=200,
                cookie_account="owner",
            ),
            ChainStep(
                id="peer_read",
                url="http://127.0.0.1/users/{owner_read.obj}",
                expect_status=200,
                cookie_account="peer",
            ),
        ],
        success_condition="last.status == 200",
    )
    out = run_chain(chain, cookies={"owner": "a=1", "peer": "b=2"})
    assert len(out["findings"]) == 1
    assert out["findings"][0].id == "chain-idor-peer-access"
    assert out["findings"][0].confidence == "confirmed"
    assert out["stopped_at"] is None
