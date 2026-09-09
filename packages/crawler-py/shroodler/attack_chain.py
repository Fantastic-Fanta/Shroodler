"""Multi-step attack-chain executor.

Kept separate from shroodler.chains (compound-finding correlator) so existing
chain_findings() behaviour is unchanged.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from shroodler.models import Finding
from shroodler.probes.common import body_text, request

_TEMPLATE_RE = re.compile(r"\{([^{}]+)\}")
_COMPARE_RE = re.compile(
    r"^(?P<left>.+?)\s*(?P<op>==|!=)\s*(?P<right>.+)$"
)


@dataclass
class ChainStep:
    id: str
    url: str
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    extract: dict[str, str] = field(default_factory=dict)
    expect_status: int | list[int] = 200
    cookie_account: str = "owner"


@dataclass
class AttackChain:
    name: str
    description: str
    finding_id: str
    severity: str = "high"
    steps: list[ChainStep] = field(default_factory=list)
    success_condition: str = "last.status == 200"


def jsonpath_lite(data: Any, path: str) -> Any:
    """Tiny ``$.a.b`` walker. No extra dependency."""
    text = (path or "").strip()
    if text.startswith("$."):
        text = text[2:]
    elif text.startswith("$"):
        text = text[1:].lstrip(".")
    if not text:
        return data
    cur = data
    for part in text.split("."):
        if not part:
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
            continue
        if isinstance(cur, list) and part.isdigit():
            idx = int(part)
            if 0 <= idx < len(cur):
                cur = cur[idx]
                continue
        return None
    return cur


def _nested_get(obj: Any, path: str) -> Any:
    cur = obj
    for part in (path or "").split("."):
        if not part:
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
            continue
        return None
    return cur


def interpolate(text: str, ctx: dict[str, Any], *, random_factory=None) -> str:
    """Replace ``{prev.field}``, ``{<step_id>.x}``, ``{step_N.x}``, ``{random}``."""

    def repl(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        if key == "random":
            factory = random_factory or secrets.token_hex
            return str(factory(6))
        if "." in key:
            head, _, tail = key.partition(".")
            obj = ctx.get(head)
            if isinstance(obj, dict):
                value = _nested_get(obj, tail)
                return "" if value is None else str(value)
            return ""
        value = ctx.get(key)
        return "" if value is None else str(value)

    return _TEMPLATE_RE.sub(repl, text or "")


def _status_ok(actual: int, expected: int | list[int]) -> bool:
    if isinstance(expected, list):
        allowed = {int(x) for x in expected}
        return actual in allowed
    return actual == int(expected)


def _parse_json_body(text: str) -> Any:
    raw = (text or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def _resolve_token(token: str, ctx: dict[str, Any]) -> str:
    text = (token or "").strip().strip("'\"")
    if not text:
        return ""
    if "{" in text:
        return interpolate(text, ctx)
    if "." in text:
        head, _, tail = text.partition(".")
        obj = ctx.get(head)
        if isinstance(obj, dict):
            value = _nested_get(obj, tail)
            return "" if value is None else str(value)
    if text in ctx:
        value = ctx[text]
        if isinstance(value, dict) and "status" in value:
            return str(value.get("status"))
        return "" if value is None else str(value)
    return text


def eval_success_condition(condition: str, ctx: dict[str, Any]) -> bool:
    raw = (condition or "").strip()
    if not raw:
        last = ctx.get("last") or {}
        return int(last.get("status") or 0) == 200
    text = interpolate(raw, ctx) if "{" in raw else raw
    lowered = text.lower()
    if lowered in {"true", "1", "yes"}:
        return True
    if lowered in {"false", "0", "no"}:
        return False
    matched = _COMPARE_RE.match(text)
    if not matched:
        last = ctx.get("last") or {}
        return bool(text) and int(last.get("status") or 0) == 200
    left = _resolve_token(matched.group("left"), ctx)
    right = _resolve_token(matched.group("right"), ctx)
    op = matched.group("op")
    if op == "==":
        return left == right
    return left != right


def _cookie_for_account(config: Any, account: str) -> str:
    role = (account or "owner").strip().lower()
    if role == "anon":
        return ""
    if role == "peer":
        return str(getattr(config, "peer_cookie", None) or "")
    owner = getattr(config, "owner_cookie", None) or getattr(config, "higher_priv_jar", None)
    return str(owner or "")


def _step_from_dict(raw: dict[str, Any], index: int) -> ChainStep:
    expect = raw.get("expect_status", 200)
    if isinstance(expect, list):
        expect_status: int | list[int] = [int(x) for x in expect]
    else:
        expect_status = int(expect or 200)
    params = raw.get("params") or {}
    headers = raw.get("headers") or {}
    extract = raw.get("extract") or {}
    return ChainStep(
        id=str(raw.get("id") or f"step_{index + 1}"),
        url=str(raw.get("url") or ""),
        method=str(raw.get("method") or "GET").upper() or "GET",
        params={str(k): str(v) for k, v in dict(params).items()},
        headers={str(k): str(v) for k, v in dict(headers).items()},
        extract={str(k): str(v) for k, v in dict(extract).items()},
        expect_status=expect_status,
        cookie_account=str(raw.get("cookie_account") or "owner"),
    )


def chain_from_dict(raw: dict[str, Any]) -> AttackChain:
    steps_raw = raw.get("steps") or []
    steps = [
        _step_from_dict(item, i)
        for i, item in enumerate(steps_raw)
        if isinstance(item, dict)
    ]
    return AttackChain(
        name=str(raw.get("name") or "unnamed"),
        description=str(raw.get("description") or ""),
        finding_id=str(raw.get("finding_id") or raw.get("id") or "attack-chain"),
        severity=str(raw.get("severity") or "high"),
        steps=steps,
        success_condition=str(raw.get("success_condition") or "last.status == 200"),
    )


def load_chain_spec(path: str | Path) -> AttackChain:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"chain spec {path} must be a JSON object")
    return chain_from_dict(data)


def run_chain(
    chain: AttackChain,
    *,
    config: Any = None,
    pacer: Any = None,
    client: Any = None,
    cookies: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run steps in order. Stop on unexpected status. Emit a finding if success_condition holds."""
    ctx: dict[str, Any] = {}
    findings: list[Finding] = []
    urls_tested = 0
    last: dict[str, Any] = {}
    for index, step in enumerate(chain.steps):
        url = interpolate(step.url, ctx)
        method = interpolate(step.method, ctx)
        params = {k: interpolate(str(v), ctx) for k, v in (step.params or {}).items()}
        headers = {k: interpolate(str(v), ctx) for k, v in (step.headers or {}).items()}
        account = interpolate(step.cookie_account, ctx) or "owner"
        cookie_header = ""
        if cookies and account in cookies:
            cookie_header = cookies[account]
        elif config is not None:
            cookie_header = _cookie_for_account(config, account)
        kwargs: dict[str, Any] = {}
        method_u = (method or "GET").upper()
        if method_u == "GET":
            if params:
                kwargs["params"] = params
        elif params:
            kwargs["data"] = params
        resp = request(
            method_u,
            url,
            cookie_header=cookie_header,
            extra_headers=headers or None,
            client=client,
            pacer=pacer,
            **kwargs,
        )
        urls_tested += 1
        if resp is None:
            return {
                "findings": [],
                "urls_tested": urls_tested,
                "stopped_at": step.id,
                "reason": "transport error",
            }
        status = int(getattr(resp, "status_code", 0) or 0)
        if not _status_ok(status, step.expect_status):
            return {
                "findings": [],
                "urls_tested": urls_tested,
                "stopped_at": step.id,
                "reason": f"expected {step.expect_status} got {status}",
            }
        body = body_text(resp)
        parsed = _parse_json_body(body)
        extracted: dict[str, Any] = {"status": status, "body": body[:500]}
        if isinstance(parsed, dict):
            extracted.update(parsed)
        for name, path in (step.extract or {}).items():
            extracted[name] = jsonpath_lite(parsed, path) if parsed is not None else None
        ctx[step.id] = extracted
        ctx[f"step_{index + 1}"] = extracted
        ctx["prev"] = extracted
        ctx["last"] = extracted
        last = extracted
    ctx["last"] = last
    ctx["prev"] = last
    if eval_success_condition(chain.success_condition, ctx):
        allowed = {"info", "low", "medium", "high", "critical"}
        severity = chain.severity if chain.severity in allowed else "high"
        fallback_url = chain.steps[-1].url if chain.steps else ""
        raw_url = last.get("url") if isinstance(last.get("url"), str) else None
        url = str(raw_url or fallback_url)
        findings.append(
            Finding(
                id=chain.finding_id,
                severity=severity,  # type: ignore[arg-type]
                category="auth",
                url=interpolate(url, ctx),
                description=chain.description or f"Attack chain {chain.name!r} succeeded",
                evidence=f"chain={chain.name} last_status={last.get('status')}",
                confidence="confirmed",
            )
        )
    return {
        "findings": findings,
        "urls_tested": urls_tested,
        "stopped_at": None,
        "reason": "",
    }


def _in_origin(url: str, target: str) -> bool:
    if not url or not target:
        return False
    try:
        a, b = urlparse(url), urlparse(target)
        return bool(a.scheme and a.netloc and a.scheme == b.scheme and a.netloc == b.netloc)
    except ValueError:
        return False


def bind_builtin_chains(state: Any, config: Any) -> list[AttackChain]:
    """Parameterize built-in chains from program state. Skip when URLs cannot bind."""
    target = str(getattr(config, "target", "") or "")
    owner = str(getattr(config, "owner_cookie", None) or "")
    peer = str(getattr(config, "peer_cookie", None) or "")
    endpoints = getattr(state, "endpoints", None) or {}
    object_ids = getattr(state, "object_ids", None) or {}
    chains: list[AttackChain] = []

    idor_url = ""
    for url, meta in endpoints.items():
        if not _in_origin(url, target):
            continue
        method = str((meta or {}).get("method") or "GET").upper()
        if method not in {"GET", "HEAD"}:
            continue
        path = urlparse(url).path.lower()
        if any(token in path for token in ("/users/", "/account", "/profile", "/order", "/id")):
            idor_url = url
            break
        if "{id}" in url:
            idor_url = url
            break
    if not idor_url:
        for pattern, ids in object_ids.items():
            if not ids:
                continue
            for url in endpoints:
                if not _in_origin(url, target):
                    continue
                if pattern.rstrip("/") in urlparse(url).path:
                    idor_url = url
                    break
            if idor_url:
                break
    if idor_url and owner and peer:
        chains.append(
            AttackChain(
                name="idor-peer-access",
                description=(
                    "Owner can read an object URL; the peer session also received 200. "
                    "Broken access control across accounts."
                ),
                finding_id="chain-idor-peer-access",
                severity="high",
                success_condition="last.status == 200",
                steps=[
                    ChainStep(
                        id="owner_read",
                        url=idor_url,
                        method="GET",
                        expect_status=200,
                        cookie_account="owner",
                    ),
                    ChainStep(
                        id="peer_read",
                        url=idor_url,
                        method="GET",
                        expect_status=200,
                        cookie_account="peer",
                    ),
                ],
            )
        )

    write_url = ""
    for url, meta in endpoints.items():
        if not _in_origin(url, target):
            continue
        method = str((meta or {}).get("method") or "GET").upper()
        path = urlparse(url).path.lower()
        if method in {"POST", "PUT", "PATCH"} and any(
            token in path for token in ("/transfer", "/payment", "/order", "/trade", "/checkout")
        ):
            write_url = url
            break
    if write_url and owner:
        chains.append(
            AttackChain(
                name="unauth-write-after-owner",
                description=(
                    "Owner write succeeded, then the same mutation as anonymous also "
                    "returned 200 — authentication is not enforced on the write."
                ),
                finding_id="chain-unauth-write",
                severity="critical",
                success_condition="last.status == 200",
                steps=[
                    ChainStep(
                        id="owner_write",
                        url=write_url,
                        method="POST",
                        expect_status=[200, 201, 204],
                        cookie_account="owner",
                    ),
                    ChainStep(
                        id="anon_write",
                        url=write_url,
                        method="POST",
                        expect_status=200,
                        cookie_account="anon",
                    ),
                ],
            )
        )
    return chains
