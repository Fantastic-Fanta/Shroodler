from __future__ import annotations

from types import SimpleNamespace

from shroodler.business_logic import (
    AppDomainModel,
    financial_probes_for,
    infer_app_domain,
    run_business_probe,
)


class _Resp:
    def __init__(self, status_code: int, text: str):
        self.status_code = status_code
        self.text = text
        self.content = text.encode("utf-8")


def test_infer_app_domain_parses(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

    class FakeMessages:
        def create(self, **kwargs):
            assert kwargs["model"]
            assert kwargs["max_tokens"] == 2000
            return SimpleNamespace(
                content=[
                    SimpleNamespace(
                        text=(
                            "```json\n"
                            '{"domain": "brokerage", "financial": true, '
                            '"workflows": ["trade"], "amount_params": ["qty"], '
                            '"currency_params": ["ccy"]}\n'
                            "```"
                        )
                    )
                ]
            )

    class FakeAnthropic:
        def __init__(self):
            self.messages = FakeMessages()

    import anthropic

    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)
    model = infer_app_domain(
        [{"url": "http://x/app.js", "text": "placeOrder()"}],
        {"http://x/api/balance": '{"balance": 1}'},
    )
    assert isinstance(model, AppDomainModel)
    assert model.financial is True
    assert model.domain == "brokerage"
    assert "trade" in model.workflows


def test_infer_app_domain_no_key_skips_network(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    def boom(*args, **kwargs):
        raise AssertionError("must not call Claude without an API key")

    monkeypatch.setattr("anthropic.Anthropic", boom, raising=False)
    model = infer_app_domain([], {})
    assert model.domain == "unknown"
    assert model.financial is False


def test_negative_amount_probe_fires(monkeypatch):
    monkeypatch.setattr(
        "shroodler.business_logic.request",
        lambda *a, **k: _Resp(200, '{"balance": 1000}'),
    )
    probes = financial_probes_for("http://127.0.0.1/trade")
    probe = next(p for p in probes if p.id == "negative-amount")
    findings = run_business_probe(probe)
    assert findings
    assert findings[0].id == "business-negative-amount"
    assert findings[0].confidence == "confirmed"


def test_zero_price_probe_fires(monkeypatch):
    monkeypatch.setattr(
        "shroodler.business_logic.request",
        lambda *a, **k: _Resp(200, '{"confirmation": "ok", "orderId": "1"}'),
    )
    probes = financial_probes_for("http://127.0.0.1/checkout")
    probe = next(p for p in probes if p.id == "zero-price")
    findings = run_business_probe(probe)
    assert findings
    assert findings[0].id == "business-zero-price"


def test_skip_step_probe_no_finding_on_403(monkeypatch):
    monkeypatch.setattr(
        "shroodler.business_logic.request",
        lambda *a, **k: _Resp(403, '{"balance": 1000}'),
    )
    probes = financial_probes_for("http://127.0.0.1/confirm")
    probe = next(p for p in probes if p.id == "skip-step")
    assert run_business_probe(probe) == []
