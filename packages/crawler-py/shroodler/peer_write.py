"""Known-object peer-write replay.

authz-diff replays GETs from a privileged crawl. `--check-idor` walks n±1
on the same session. Neither is the hunt that actually lands: capture a
write the owner just issued against a *known* object, replay that same
POST/PUT/PATCH/DELETE as a peer, and compare it to the same body aimed at
a nonsense id. A 200 that matches the nonsense control is a dummy
success, not a finding. `{"success": false}` is a denial dressed as JSON.
A peer 2xx that differs from the nonsense control is an IDOR lead; an
owner re-read that actually changed is confirmation.

This is not an enumerator. It never invents adjacent ids.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx

from shroodler.cookie_source import load_captured_sessions
from shroodler.extractors.challenge import detect_challenge
from shroodler.models import Finding
from shroodler.pacer import Pacer, compose_user_agent
from shroodler.sessions import _body_text
from shroodler.urls import is_loopback_or_local

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MAX_WRITES = 50
DEFAULT_NONSENSE_ID = "1"
DEFAULT_RATE = 1.0

_SKIP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "cookie",
    "transfer-encoding",
    "keep-alive",
    "proxy-connection",
}
_NUMERIC_ID = re.compile(r"^\d{3,}$")
_LOGIN_REDIRECT_HINTS = ("login", "signin", "sign-in", "log-in", "auth", "session/new")


def swap_object_id(url: str, object_id: str, replacement: str) -> str:
    if not object_id:
        return url
    parsed = urlparse(url)
    parts = [replacement if part == object_id else part for part in parsed.path.split("/")]
    qs = [
        (k, replacement if v == object_id else v)
        for k, v in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunparse(parsed._replace(path="/".join(parts), query=urlencode(qs)))


def _swap_in_json(value: Any, object_id: str, replacement: str) -> Any:
    if isinstance(value, dict):
        return {k: _swap_in_json(v, object_id, replacement) for k, v in value.items()}
    if isinstance(value, list):
        return [_swap_in_json(v, object_id, replacement) for v in value]
    if isinstance(value, str) and value == object_id:
        return replacement
    if isinstance(value, int) and str(value) == object_id:
        try:
            return int(replacement)
        except ValueError:
            return replacement
    return value


def swap_id_in_body(body: str, object_id: str, replacement: str) -> str:
    if not body or not object_id:
        return body
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return body
    return json.dumps(_swap_in_json(data, object_id, replacement), separators=(",", ":"))


def infer_id_value(url: str, body: str = "") -> str | None:
    path = urlparse(url).path
    numeric = [seg for seg in path.split("/") if _NUMERIC_ID.match(seg)]
    if numeric:
        return numeric[-1]
    if body:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, dict):
            for key in ("id", "pk", "object_id", "photo_id", "collection_id"):
                val = data.get(key)
                if isinstance(val, int) and val >= 100:
                    return str(val)
                if isinstance(val, str) and _NUMERIC_ID.match(val):
                    return val
    return None


def json_write_rejected(body: str) -> bool:
    try:
        data = json.loads(body or "")
    except json.JSONDecodeError:
        return False
    if not isinstance(data, dict):
        return False
    if data.get("success") is False or data.get("ok") is False:
        return True
    err = data.get("error") or data.get("error_msg")
    return bool(err)


def _normalize_body(text: str) -> Any:
    text = (text or "").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _bodies_equivalent(a: str, b: str) -> bool:
    return _normalize_body(a) == _normalize_body(b)


def _is_success(status: int) -> bool:
    return 200 <= status < 300


def _is_denied(status: int, location: str = "") -> bool:
    if status in (401, 403, 404, 405):
        return True
    if status in (301, 302, 303, 307, 308):
        loc = location.lower()
        return any(hint in loc for hint in _LOGIN_REDIRECT_HINTS)
    return False


def _abs_url(target: str, url: str) -> str:
    if not url:
        return ""
    if "://" in url:
        return url
    return urljoin(target if target.endswith("/") else target + "/", url.lstrip("/"))


def _clean_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in (headers or {}).items():
        if str(key).lower() in _SKIP_HEADERS:
            continue
        out[str(key)] = str(value)
    return out


def writes_from_sessions(
    sessions: list[dict[str, Any]],
    *,
    target: str = "",
    only_id: str | None = None,
    max_writes: int = MAX_WRITES,
) -> list[dict[str, Any]]:
    """Pull POST/PUT/PATCH/DELETE requests that already name an object id."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for sess in sessions:
        req = sess.get("request") or {}
        method = str(req.get("method") or "GET").upper()
        if method not in WRITE_METHODS:
            continue
        url = str(req.get("url") or "")
        if not url:
            continue
        if target and "://" in url and "://" in target:
            from shroodler.urls import same_origin

            if not same_origin(url, target):
                continue
        body = _body_text(req.get("body"))
        object_id = infer_id_value(url, body)
        if not object_id:
            continue
        if only_id and object_id != only_id and only_id not in url:
            continue
        key = (method, url, body)
        if key in seen:
            continue
        seen.add(key)
        headers = {str(k): str(v) for k, v in (req.get("headers") or {}).items()}
        out.append(
            {
                "method": method,
                "url": url,
                "headers": _clean_headers(headers),
                "body": body,
                "id_value": object_id,
            }
        )
        if len(out) >= max_writes:
            break
    return out


def load_playbook(
    playbook: dict[str, Any] | None = None,
    *,
    sessions_path: str | None = None,
    target: str = "",
    only_id: str | None = None,
    max_writes: int = MAX_WRITES,
) -> dict[str, Any]:
    doc = dict(playbook or {})
    writes = list(doc.get("writes") or [])
    inferred_target = str(doc.get("target") or target or "")
    if sessions_path:
        sessions = load_captured_sessions(sessions_path)
        if not inferred_target:
            for sess in sessions:
                url = str((sess.get("request") or {}).get("url") or "")
                if "://" in url:
                    p = urlparse(url)
                    inferred_target = f"{p.scheme}://{p.netloc}/"
                    break
        writes.extend(
            writes_from_sessions(
                sessions,
                target=inferred_target,
                only_id=only_id,
                max_writes=max_writes,
            )
        )
    if only_id:
        writes = [
            w
            for w in writes
            if str(w.get("id_value") or "") == only_id or only_id in str(w.get("url") or "")
        ]
    truncated = len(writes) > max_writes
    return {
        "target": inferred_target,
        "writes": writes[:max_writes],
        "truncated": truncated,
    }


def _session_headers(
    cookie: str,
    extra: dict[str, str] | None,
    write_headers: dict[str, str] | None,
    user_agent: str,
) -> dict[str, str]:
    headers = _clean_headers(write_headers)
    for key, value in (extra or {}).items():
        headers[key] = value
    if cookie:
        headers["Cookie"] = cookie
    if user_agent:
        headers.setdefault("User-Agent", user_agent)
    return headers


def _looks_like_challenge(resp: httpx.Response) -> bool:
    headers = {k: v for k, v in resp.headers.items()}
    set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    if not set_cookies:
        raw = resp.headers.get("set-cookie")
        set_cookies = [raw] if raw else []
    return detect_challenge(headers, resp.text, resp.status_code, set_cookies) is not None


def _send(
    http: httpx.Client,
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None,
    enforcer,
    pacer: Pacer,
) -> httpx.Response | None:
    pacer.wait()
    if enforcer is not None:
        ok, _reason = enforcer.check(url)
        if not ok:
            return None
    kwargs: dict[str, Any] = {"headers": headers}
    if method.upper() in {"POST", "PUT", "PATCH"} and body is not None:
        kwargs["content"] = body.encode("utf-8") if isinstance(body, str) else body
    try:
        return http.request(method.upper(), url, **kwargs)
    except httpx.HTTPError:
        return None


def _checked(
    write: dict[str, Any],
    *,
    verdict: str,
    peer_status: int | None = None,
    nonsense_status: int | None = None,
    owner_changed: bool | None = None,
    note: str = "",
) -> dict[str, Any]:
    row = {
        "method": str(write.get("method") or "POST").upper(),
        "url": write.get("url") or "",
        "id_value": write.get("id_value") or "",
        "verdict": verdict,
        "peer_status": peer_status,
        "nonsense_status": nonsense_status,
        "owner_changed": owner_changed,
    }
    if note:
        row["note"] = note
    return row


def run(
    playbook: dict[str, Any],
    *,
    owner_cookie: str = "",
    peer_cookie: str = "",
    extra_headers: dict[str, str] | None = None,
    allow_external: bool = False,
    client: httpx.Client | None = None,
    enforcer=None,
    pacer: Pacer | None = None,
    rate: float = DEFAULT_RATE,
    user_agent: str = "",
    user_agent_suffix: str = "",
    nonsense_id: str = DEFAULT_NONSENSE_ID,
    only_id: str | None = None,
    max_writes: int = MAX_WRITES,
) -> dict[str, Any]:
    """Replay known writes as the peer. Returns `{target, findings, checked}`."""
    loaded = load_playbook(
        playbook,
        target=str(playbook.get("target") or ""),
        only_id=only_id,
        max_writes=max_writes,
    )
    target = str(loaded.get("target") or "")
    if not target:
        raise ValueError("peer-write needs a target (playbook.target or --target)")
    if not allow_external and not is_loopback_or_local(target):
        raise ValueError(
            "peer-write refuses non-local targets without --allow-external "
            "(only scan hosts you are authorized to test)"
        )

    ua = compose_user_agent(user_agent or None, user_agent_suffix or None)
    clock = pacer or Pacer(rate)
    http = client or httpx.Client(timeout=8.0, follow_redirects=False)
    own = client is None
    findings: list[dict[str, Any]] = []
    checked: list[dict[str, Any]] = []

    try:
        for write in loaded["writes"]:
            method = str(write.get("method") or "POST").upper()
            url = _abs_url(target, str(write.get("url") or ""))
            if not url:
                checked.append(_checked(write, verdict="skipped", note="missing url"))
                continue
            if not allow_external and not is_loopback_or_local(url):
                checked.append(_checked(write, verdict="skipped", note="off-origin"))
                continue
            body = write.get("body")
            body = "" if body is None else str(body)
            object_id = str(write.get("id_value") or infer_id_value(url, body) or "")
            write = {**write, "url": url, "id_value": object_id, "method": method}
            if not object_id:
                checked.append(_checked(write, verdict="skipped", note="no object id"))
                continue

            verify = write.get("verify") if isinstance(write.get("verify"), dict) else None
            verify_url = _abs_url(target, str((verify or {}).get("url") or ""))
            verify_method = str((verify or {}).get("method") or "GET").upper()

            peer_headers = _session_headers(peer_cookie, extra_headers, write.get("headers"), ua)
            owner_headers = _session_headers(owner_cookie, extra_headers, None, ua)

            owner_before = ""
            if verify_url and owner_cookie:
                before = _send(
                    http,
                    method=verify_method,
                    url=verify_url,
                    headers=owner_headers,
                    body=None,
                    enforcer=enforcer,
                    pacer=clock,
                )
                if before is not None:
                    owner_before = before.text

            nonsense_url = swap_object_id(url, object_id, nonsense_id)
            nonsense_body = swap_id_in_body(body, object_id, nonsense_id)
            nonsense_resp = _send(
                http,
                method=method,
                url=nonsense_url,
                headers=peer_headers,
                body=nonsense_body,
                enforcer=enforcer,
                pacer=clock,
            )
            if nonsense_resp is None:
                checked.append(
                    _checked(write, verdict="skipped", note="nonsense request blocked or failed")
                )
                continue
            if _looks_like_challenge(nonsense_resp):
                checked.append(
                    _checked(
                        write,
                        verdict="challenge",
                        nonsense_status=nonsense_resp.status_code,
                        note="WAF/captcha on nonsense-id control; not solved",
                    )
                )
                continue

            real_resp = _send(
                http,
                method=method,
                url=url,
                headers=peer_headers,
                body=body,
                enforcer=enforcer,
                pacer=clock,
            )
            if real_resp is None:
                checked.append(
                    _checked(
                        write,
                        verdict="skipped",
                        nonsense_status=nonsense_resp.status_code,
                        note="real-id request blocked or failed",
                    )
                )
                continue
            if _looks_like_challenge(real_resp):
                checked.append(
                    _checked(
                        write,
                        verdict="challenge",
                        peer_status=real_resp.status_code,
                        nonsense_status=nonsense_resp.status_code,
                        note="WAF/captcha on real-id write; not solved",
                    )
                )
                continue

            owner_after = ""
            owner_changed = None
            if verify_url and owner_cookie:
                after = _send(
                    http,
                    method=verify_method,
                    url=verify_url,
                    headers=owner_headers,
                    body=None,
                    enforcer=enforcer,
                    pacer=clock,
                )
                if after is not None:
                    owner_after = after.text
                    owner_changed = not _bodies_equivalent(owner_before, owner_after)

            location = real_resp.headers.get("location", "")
            if _is_denied(real_resp.status_code, location):
                checked.append(
                    _checked(
                        write,
                        verdict="denied",
                        peer_status=real_resp.status_code,
                        nonsense_status=nonsense_resp.status_code,
                        owner_changed=owner_changed,
                    )
                )
                continue
            if not _is_success(real_resp.status_code):
                checked.append(
                    _checked(
                        write,
                        verdict="error",
                        peer_status=real_resp.status_code,
                        nonsense_status=nonsense_resp.status_code,
                        owner_changed=owner_changed,
                    )
                )
                continue
            if json_write_rejected(real_resp.text):
                checked.append(
                    _checked(
                        write,
                        verdict="write-failure",
                        peer_status=real_resp.status_code,
                        nonsense_status=nonsense_resp.status_code,
                        owner_changed=owner_changed,
                    )
                )
                continue
            if _is_success(nonsense_resp.status_code) and _bodies_equivalent(
                real_resp.text, nonsense_resp.text
            ):
                checked.append(
                    _checked(
                        write,
                        verdict="dummy-success",
                        peer_status=real_resp.status_code,
                        nonsense_status=nonsense_resp.status_code,
                        owner_changed=owner_changed,
                    )
                )
                continue

            confidence = "confirmed" if owner_changed else "probable"
            finding = Finding(
                id="peer-write-idor",
                severity="high",
                category="auth",
                url=url,
                description=(
                    f"Peer session {method} to known object {object_id} returned "
                    f"{real_resp.status_code} and differed from the nonsense-id "
                    f"control ({nonsense_id} → {nonsense_resp.status_code}). "
                    + (
                        "Owner re-read confirmed the object changed."
                        if owner_changed
                        else "Re-read as the owner to confirm the write persisted."
                    )
                ),
                evidence=(
                    f"peer={real_resp.status_code} nonsense={nonsense_resp.status_code} "
                    f"id={object_id} owner_changed={owner_changed}"
                ),
                confidence=confidence,
            ).model_dump(exclude_none=True)
            findings.append(finding)
            checked.append(
                _checked(
                    write,
                    verdict="idor",
                    peer_status=real_resp.status_code,
                    nonsense_status=nonsense_resp.status_code,
                    owner_changed=owner_changed,
                )
            )
    finally:
        if own:
            http.close()

    out: dict[str, Any] = {"target": target, "findings": findings, "checked": checked}
    if loaded.get("truncated"):
        out["truncated"] = True
    return out
