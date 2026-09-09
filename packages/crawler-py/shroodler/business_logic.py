"""LLM-assisted business-logic probing, plus built-in financial templates."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any

from shroodler.llm_triage import _parse_json_object
from shroodler.models import Finding
from shroodler.probes.common import body_text, request

# Spec asked for claude-sonnet-5. llm_triage uses claude-haiku-4-5-20251001.
BUSINESS_LOGIC_MODEL = "claude-sonnet-5"
BUSINESS_LOGIC_MAX_TOKENS = 2000

_SUCCESS_KEYWORDS = (
    "balance",
    "confirmation",
    "transaction",
    "txn",
    "orderid",
    "tradeid",
)

SYSTEM_PROMPT = (
    "You infer the business domain of a web application from JavaScript "
    "bundles and API response samples. Return JSON only: "
    '{"domain": "string", "financial": bool, "workflows": ["..."], '
    '"amount_params": ["..."], "currency_params": ["..."]}. '
    "Set financial=true for trading, payments, banking, checkout, or wallets. "
    "If unsure, financial=false and domain=unknown."
)


@dataclass
class AppDomainModel:
    domain: str = "unknown"
    financial: bool = False
    workflows: list[str] = field(default_factory=list)
    amount_params: list[str] = field(default_factory=list)
    currency_params: list[str] = field(default_factory=list)


@dataclass
class ProbeStep:
    method: str = "POST"
    url: str = ""
    params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    json_body: dict[str, Any] | None = None


@dataclass
class BusinessProbe:
    id: str
    description: str
    steps: list[ProbeStep] = field(default_factory=list)


def _log_error(exc: BaseException) -> None:
    print(
        json_dumps({"error": f"business_logic: {type(exc).__name__}: {exc}"}),
        file=sys.stderr,
        flush=True,
    )


def json_dumps(payload: dict[str, Any]) -> str:
    import json

    return json.dumps(payload, default=str)


def _bundle_texts(js_bundles: Any) -> list[str]:
    out: list[str] = []
    for item in js_bundles or []:
        if isinstance(item, str) and item.strip():
            out.append(item[:8000])
        elif isinstance(item, dict):
            text = str(item.get("text") or item.get("body") or "")
            url = str(item.get("url") or "")
            if text.strip():
                out.append((f"{url}\n{text}" if url else text)[:8000])
    return out[:3]


def infer_app_domain(js_bundles: Any, api_samples: Any, pages: Any = None) -> AppDomainModel:
    """Call Claude when ANTHROPIC_API_KEY is set; otherwise return unknown."""
    empty = AppDomainModel()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return empty
    try:
        import json

        import anthropic

        samples = api_samples if isinstance(api_samples, dict) else {}
        payload = {
            "js_bundles": _bundle_texts(js_bundles),
            "api_samples": {str(k): str(v)[:200] for k, v in list(samples.items())[:40]},
            "page_count": len(pages or []),
        }
        client = anthropic.Anthropic()
        message = client.messages.create(
            model=BUSINESS_LOGIC_MODEL,
            max_tokens=BUSINESS_LOGIC_MAX_TOKENS,
            temperature=0,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(payload, default=str)}],
        )
        text = ""
        content = getattr(message, "content", None) or []
        if content:
            text = getattr(content[0], "text", "") or ""
        data = _parse_json_object(text)
        if data is None:
            return empty
        workflows = data.get("workflows") or []
        amount_params = data.get("amount_params") or []
        currency_params = data.get("currency_params") or []
        return AppDomainModel(
            domain=str(data.get("domain") or "unknown") or "unknown",
            financial=bool(data.get("financial")),
            workflows=[str(x) for x in workflows if str(x)],
            amount_params=[str(x) for x in amount_params if str(x)],
            currency_params=[str(x) for x in currency_params if str(x)],
        )
    except Exception as exc:  # noqa: BLE001 - fail closed, never crash the agent
        _log_error(exc)
        return empty


def _looks_like_accepted(status: int, body: str) -> bool:
    if status != 200:
        return False
    lowered = (body or "").lower()
    return any(keyword in lowered for keyword in _SUCCESS_KEYWORDS)


def financial_probes_for(url: str) -> list[BusinessProbe]:
    """Built-in financial templates. No LLM required for generation."""
    target = str(url or "")
    return [
        BusinessProbe(
            id="negative-amount",
            description="Submit a negative amount/price and look for an accepted transaction",
            steps=[
                ProbeStep(
                    method="POST",
                    url=target,
                    params={"amount": "-1", "price": "-1"},
                    json_body={"amount": -1, "price": -1},
                )
            ],
        ),
        BusinessProbe(
            id="zero-price",
            description="Submit a zero price and look for an accepted transaction",
            steps=[
                ProbeStep(
                    method="POST",
                    url=target,
                    params={"amount": "1", "price": "0"},
                    json_body={"amount": 1, "price": 0},
                )
            ],
        ),
        BusinessProbe(
            id="integer-overflow",
            description="Submit an overflowing amount",
            steps=[
                ProbeStep(
                    method="POST",
                    url=target,
                    params={"amount": "999999999999999999"},
                    json_body={"amount": 999999999999999999},
                )
            ],
        ),
        BusinessProbe(
            id="skip-step",
            description="Skip an earlier workflow step and hit the confirm/complete URL directly",
            steps=[
                ProbeStep(
                    method="POST",
                    url=target,
                    params={"step": "confirm", "skip": "1"},
                    json_body={"step": "confirm", "skip": True},
                )
            ],
        ),
        BusinessProbe(
            id="replay-step",
            description="Replay a completed step with the same parameters",
            steps=[
                ProbeStep(
                    method="POST",
                    url=target,
                    params={"amount": "10", "replay": "1"},
                    json_body={"amount": 10, "replay": True},
                ),
                ProbeStep(
                    method="POST",
                    url=target,
                    params={"amount": "10", "replay": "1"},
                    json_body={"amount": 10, "replay": True},
                ),
            ],
        ),
        BusinessProbe(
            id="param-pollution",
            description="Send duplicate amount parameters (HTTP parameter pollution)",
            steps=[
                ProbeStep(
                    method="POST",
                    url=target,
                    params={"amount": "1"},
                    json_body={"amount": [1, 0]},
                )
            ],
        ),
        BusinessProbe(
            id="currency-mismatch",
            description="Submit a currency that does not match the account/order currency",
            steps=[
                ProbeStep(
                    method="POST",
                    url=target,
                    params={"amount": "10", "currency": "XXX", "price": "10"},
                    json_body={"amount": 10, "currency": "XXX", "price": 10},
                )
            ],
        ),
    ]


def run_business_probe(
    probe: BusinessProbe,
    *,
    cookie_header: str = "",
    pacer: Any = None,
    client: Any = None,
) -> list[Finding]:
    """Execute probe steps via probes.common.request. Fail closed on transport errors."""
    last_status = 0
    last_body = ""
    for step in probe.steps:
        kwargs: dict[str, Any] = {}
        if step.json_body is not None:
            kwargs["json"] = step.json_body
        elif step.params:
            method = (step.method or "POST").upper()
            if method == "GET":
                kwargs["params"] = dict(step.params)
            else:
                kwargs["data"] = dict(step.params)
        resp = request(
            step.method or "POST",
            step.url,
            cookie_header=cookie_header,
            extra_headers=dict(step.headers or {}),
            client=client,
            pacer=pacer,
            **kwargs,
        )
        if resp is None:
            return []
        last_status = int(getattr(resp, "status_code", 0) or 0)
        last_body = body_text(resp)
    if not _looks_like_accepted(last_status, last_body):
        return []
    return [
        Finding(
            id=f"business-{probe.id}",
            severity="high",
            category="payload",
            url=probe.steps[-1].url if probe.steps else "",
            description=(
                f"Business-logic probe {probe.id!r} was accepted (HTTP {last_status}) "
                f"with a transaction-like response. {probe.description}"
            ),
            evidence=last_body[:500],
            confidence="confirmed",
        )
    ]
