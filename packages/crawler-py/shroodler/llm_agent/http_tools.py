"""Deeper HTTP tools for the LLM agent loop.

These give the planner primitives to reach past the fixed probe list:

- ``send_request``     — craft and send an arbitrary HTTP request, then get
                         a structured observation back (status, timing,
                         reflection context, body snippet).
- ``compare_responses`` — send two requests and diff them.
- ``replay_as_user``    — send the same request as owner / peer / anon and
                         compare, for broken-access-control reasoning.
- ``decode_token``      — inspect a JWT or base64 token, no network.

Adaptive payloads (``craft_payloads`` in payloads.py) build on
``send_request``: the model writes the payload, this layer fires it and
reports exactly what came back so the model can reason further.

Scope is enforced by the guardrail layer before dispatch; these functions
assume the URL(s) are already in scope.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from shroodler.llm_agent.executor import ToolResult, _auth, _params_of
from shroodler.llm_agent.planner import PlannerDecision
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, request, response_elapsed

_BODY_CAP = 2000
_DIFF_CAP = 600


def _with_query(url: str, extra: dict[str, Any]) -> str:
    parsed = urlparse(url)
    added = urlencode({str(k): str(v) for k, v in extra.items()}, doseq=True)
    query = "&".join(p for p in (parsed.query, added) if p)
    return urlunparse(parsed._replace(query=query))


def reflection_context(body: str, needle: str) -> str:
    """Where does `needle` land in `body`? Drives XSS/SSTI reasoning.

    Returns one of: none, script, attribute, tag, comment, json, text.
    """
    if not needle or not body:
        return "none"
    idx = body.find(needle)
    if idx < 0:
        return "none"
    before = body[max(0, idx - 200) : idx].lower()
    # Nearest unclosed context wins.
    last_script = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script > last_script_close:
        return "script"
    last_comment = before.rfind("<!--")
    last_comment_close = before.rfind("-->")
    if last_comment > last_comment_close:
        return "comment"
    lt = before.rfind("<")
    gt = before.rfind(">")
    if lt > gt:
        # Inside a tag; attribute if a quote is open.
        seg = before[lt:]
        if seg.count('"') % 2 == 1 or seg.count("'") % 2 == 1:
            return "attribute"
        return "tag"
    stripped = body.lstrip()
    if stripped[:1] in {"{", "["}:
        return "json"
    return "text"


def _observe(resp: httpx.Response | None, needles: list[str]) -> dict[str, Any]:
    if resp is None:
        return {"error": "transport", "status_code": 0}
    body = body_text(resp)
    snippet = body[:_BODY_CAP]
    reflected: dict[str, str] = {}
    for needle in needles:
        n = str(needle or "")
        if len(n) < 3:
            continue
        ctx = reflection_context(body, n)
        if ctx != "none":
            reflected[n] = ctx
    ctype = ""
    location = ""
    try:
        ctype = str(resp.headers.get("content-type") or "")
        location = str(resp.headers.get("location") or "")
    except Exception:  # noqa: BLE001
        ctype = ""
    status = int(getattr(resp, "status_code", 0) or 0)
    out = {
        "status_code": status,
        "elapsed_s": round(response_elapsed(resp), 3),
        "bytes": len(body),
        "content_type": ctype,
        "reflected": reflected,
        "body": snippet,
    }
    # On a redirect, surface where it points so the planner can follow it
    # instead of stalling on a bare 3xx.
    if 300 <= status < 400 and location:
        out["redirect_to"] = location
    return out


def _send(
    method: str,
    url: str,
    *,
    headers: dict[str, Any] | None,
    body: Any,
    params: Any,
    cookie_header: str,
    client: httpx.Client | None,
    pacer: Pacer | None,
) -> tuple[httpx.Response | None, str, list[str]]:
    method_u = (str(method or "GET").upper()) or "GET"
    target = url
    kwargs: dict[str, Any] = {}
    needles: list[str] = []
    if isinstance(params, dict) and params:
        needles.extend(str(v) for v in params.values())
        if method_u in {"GET", "HEAD"}:
            target = _with_query(url, params)
        else:
            kwargs["data"] = {str(k): str(v) for k, v in params.items()}
    if body not in (None, ""):
        if isinstance(body, (dict, list)):
            kwargs["json"] = body
            needles.append(json.dumps(body))
        else:
            kwargs["content"] = str(body)
            needles.append(str(body))
    extra_headers = {str(k): str(v) for k, v in (headers or {}).items()}
    resp = request(
        method_u,
        target,
        cookie_header=cookie_header,
        extra_headers=extra_headers or None,
        client=client,
        pacer=pacer,
        **kwargs,
    )
    return resp, target, needles


def send_request(
    decision: PlannerDecision,
    config: Any,
    pacer: Pacer,
    client: httpx.Client | None,
) -> ToolResult:
    params = _params_of(decision)
    url = str(params.get("url") or "").strip()
    if not url:
        return ToolResult(summary="send_request missing url", raw_output={"error": "missing url"})
    method = str(params.get("method") or "GET")
    include_auth = params.get("include_auth", True)
    cookie_header = ""
    if include_auth in (True, "true", "True", 1):
        cookie_header, _peer = _auth(config)
    resp, target, needles = _send(
        method,
        url,
        headers=params.get("headers") if isinstance(params.get("headers"), dict) else None,
        body=params.get("body"),
        params=params.get("params") if isinstance(params.get("params"), dict) else None,
        cookie_header=cookie_header,
        client=client,
        pacer=pacer,
    )
    obs = _observe(resp, needles)
    obs.update({"url": target, "method": str(method).upper()})
    if obs.get("error") == "transport":
        return ToolResult(summary=f"send_request {url} transport error", raw_output=obs)
    refl = ", ".join(f"{k[:16]}→{v}" for k, v in (obs.get("reflected") or {}).items())
    summary = (
        f"send_request {obs['method']} {url} status={obs['status_code']} "
        f"bytes={obs['bytes']} t={obs['elapsed_s']}s"
    )
    if refl:
        summary += f" reflected[{refl}]"
    return ToolResult(findings_added=0, summary=summary, raw_output=obs)


def _diff_summary(a: str, b: str) -> str:
    if a == b:
        return "identical bodies"
    # Cheap line-level diff summary.
    a_lines = a.splitlines()
    b_lines = b.splitlines()
    only_b = [ln for ln in b_lines if ln not in set(a_lines)]
    text = "\n".join(only_b[:20])
    return (text or "bodies differ (no unique lines)")[:_DIFF_CAP]


def compare_responses(
    decision: PlannerDecision,
    config: Any,
    pacer: Pacer,
    client: httpx.Client | None,
) -> ToolResult:
    params = _params_of(decision)
    spec_a = params.get("a") if isinstance(params.get("a"), dict) else None
    spec_b = params.get("b") if isinstance(params.get("b"), dict) else None
    if not spec_a or not spec_b:
        return ToolResult(
            summary="compare_responses needs a and b request specs",
            raw_output={"error": "missing a/b"},
        )
    cookie_header, _peer = _auth(config)

    def run(spec: dict[str, Any]) -> dict[str, Any]:
        auth = spec.get("include_auth", True)
        ch = cookie_header if auth in (True, "true", "True", 1) else ""
        resp, target, needles = _send(
            str(spec.get("method") or "GET"),
            str(spec.get("url") or ""),
            headers=spec.get("headers") if isinstance(spec.get("headers"), dict) else None,
            body=spec.get("body"),
            params=spec.get("params") if isinstance(spec.get("params"), dict) else None,
            cookie_header=ch,
            client=client,
            pacer=pacer,
        )
        obs = _observe(resp, needles)
        obs["url"] = target
        return obs

    obs_a = run(spec_a)
    obs_b = run(spec_b)
    diff = _diff_summary(str(obs_a.get("body") or ""), str(obs_b.get("body") or ""))
    identical = diff == "identical bodies"
    summary = (
        f"compare a[status={obs_a.get('status_code')} bytes={obs_a.get('bytes')}] "
        f"b[status={obs_b.get('status_code')} bytes={obs_b.get('bytes')}] "
        f"{'identical' if identical else 'differ'}"
    )
    return ToolResult(
        findings_added=0,
        summary=summary,
        raw_output={"a": obs_a, "b": obs_b, "identical": identical, "diff": diff},
    )


def replay_as_user(
    decision: PlannerDecision,
    config: Any,
    pacer: Pacer,
    client: httpx.Client | None,
) -> ToolResult:
    """Send one request as owner, peer, and anonymous; report each outcome.

    Lets the model reason about broken access control: if peer/anon get the
    same 200 body as owner, that's a lead to confirm.
    """
    params = _params_of(decision)
    url = str(params.get("url") or "").strip()
    if not url:
        return ToolResult(summary="replay_as_user missing url", raw_output={"error": "missing url"})
    method = str(params.get("method") or "GET")
    owner, peer = _auth(config)
    identities = {"owner": owner, "peer": peer, "anon": ""}
    out: dict[str, Any] = {}
    for label, ch in identities.items():
        resp, target, needles = _send(
            method,
            url,
            headers=params.get("headers") if isinstance(params.get("headers"), dict) else None,
            body=params.get("body"),
            params=params.get("params") if isinstance(params.get("params"), dict) else None,
            cookie_header=ch,
            client=client,
            pacer=pacer,
        )
        obs = _observe(resp, needles)
        out[label] = {
            "status_code": obs.get("status_code"),
            "bytes": obs.get("bytes"),
            "body": str(obs.get("body") or "")[:_DIFF_CAP],
        }
    owner_body = out.get("owner", {}).get("body") or ""
    leak = [
        who
        for who in ("peer", "anon")
        if int(out.get(who, {}).get("status_code") or 0) == 200
        and out.get(who, {}).get("body") == owner_body
        and owner_body
    ]
    summary = (
        "replay_as_user "
        + " ".join(f"{k}={v.get('status_code')}" for k, v in out.items())
    )
    if leak:
        summary += f" — same-as-owner for: {', '.join(leak)} (possible broken access control)"
    out["access_control_lead"] = leak
    out["url"] = url
    return ToolResult(findings_added=0, summary=summary, raw_output=out)


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def decode_token(decision: PlannerDecision) -> ToolResult:
    """Decode a JWT (header + payload, no verification) or a base64 blob."""
    params = _params_of(decision)
    token = str(params.get("token") or "").strip()
    if not token:
        return ToolResult(
            summary="decode_token missing token",
            raw_output={"error": "missing token"},
        )
    parts = token.split(".")
    if len(parts) == 3:
        try:
            header = json.loads(_b64url_decode(parts[0]))
            payload = json.loads(_b64url_decode(parts[1]))
        except (ValueError, binascii.Error, json.JSONDecodeError) as exc:
            return ToolResult(
                summary=f"decode_token not a valid JWT: {exc}",
                raw_output={"error": str(exc)},
            )
        alg = str((header or {}).get("alg") or "")
        weak = []
        if alg.lower() in {"none", ""}:
            weak.append("alg:none")
        if alg.upper().startswith("HS"):
            weak.append("HMAC alg (test for weak/known secret & RS->HS confusion)")
        summary = f"decode_token JWT alg={alg or '?'} claims={sorted((payload or {}).keys())}"
        if weak:
            summary += f" — weak signals: {'; '.join(weak)}"
        return ToolResult(
            findings_added=0,
            summary=summary,
            raw_output={
                "kind": "jwt",
                "header": header,
                "payload": payload,
                "alg": alg,
                "weak_signals": weak,
                "signature_present": bool(parts[2]),
            },
        )
    # Fall back to a base64 decode.
    try:
        decoded = _b64url_decode(token).decode("utf-8", "replace")
    except (binascii.Error, ValueError) as exc:
        return ToolResult(
            summary=f"decode_token not base64/JWT: {exc}",
            raw_output={"error": str(exc)},
        )
    return ToolResult(
        findings_added=0,
        summary=f"decode_token base64 → {decoded[:120]}",
        raw_output={"kind": "base64", "decoded": decoded[:_BODY_CAP]},
    )
