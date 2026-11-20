"""Resend one stored HTTP exchange.

The record is a proxy JSONL line (a session the recording proxy already
wrote) or a finding proof (method, URL, and the saved request excerpt).
Scope matches every other live request: loopback is allowed, anything else
needs ``--allow-external`` and a scope host.

Apache-2.0. Shroodler's own replay command. It does not copy another
project's proxy or evidence code.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from shroodler.toolchain import _is_loopback_host, host_in_scope


def _body_text(body: Any) -> str:
    if isinstance(body, str):
        return body
    if isinstance(body, dict):
        content = body.get("content")
        if isinstance(content, str):
            return content
    return ""


def _split_excerpt(excerpt: str) -> tuple[dict[str, str], str]:
    """Headers and body from a saved request excerpt. The request line is skipped."""
    text = excerpt or ""
    if "\r\n\r\n" in text:
        head, body = text.split("\r\n\r\n", 1)
    elif "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, ""
    headers: dict[str, str] = {}
    lines = head.splitlines()
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        if name and name.lower() not in {"host", "content-length"}:
            headers[name] = value.strip()
    return headers, body


def exchange_from_obj(obj: dict[str, Any]) -> dict[str, Any] | None:
    """A proxy session or a finding proof, normalized to method/url/headers/body."""
    request = obj.get("request")
    if isinstance(request, dict) and (request.get("url") or request.get("method")):
        headers = request.get("headers") if isinstance(request.get("headers"), dict) else {}
        return {
            "method": str(request.get("method") or "GET").upper(),
            "url": str(request.get("url") or ""),
            "headers": {str(k): str(v) for k, v in headers.items()},
            "body": _body_text(request.get("body")),
            "session_id": str(obj.get("id") or ""),
        }
    url = str(obj.get("url") or "")
    method = str(obj.get("method") or "")
    if url and method:
        headers, body = _split_excerpt(str(obj.get("request_excerpt") or ""))
        return {
            "method": method.upper(),
            "url": url,
            "headers": headers,
            "body": body,
            "session_id": str(obj.get("session_id") or ""),
        }
    return None


def _load_jsonl(path: Path, selector: str) -> dict[str, Any] | None:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    if not rows:
        return None
    if not selector:
        return rows[0]
    if selector.isdigit():
        index = int(selector) - 1
        if index < 0 or index >= len(rows):
            return None
        return rows[index]
    for obj in rows:
        if str(obj.get("id") or "") == selector:
            return obj
    return None


def load_exchange(record: str, *, finding: dict[str, Any] | None = None) -> dict[str, Any]:
    """Load one exchange from a record path or an already-loaded finding."""
    if finding is not None:
        proof = finding.get("proof") if isinstance(finding.get("proof"), dict) else finding
        if isinstance(proof, dict):
            parsed = exchange_from_obj(proof)
            if parsed and parsed.get("url"):
                return parsed
        raise ValueError(f"finding {record!r} has no replayable proof")

    text = str(record or "").strip()
    selector = ""
    path_text = text
    if "#" in text:
        path_text, selector = text.split("#", 1)
    path = Path(path_text)
    if not path.is_file():
        raise ValueError(f"replay record not found: {record}")
    raw = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl" or "\n" in raw.strip():
        obj = _load_jsonl(path, selector)
    else:
        obj = json.loads(raw)
        if not isinstance(obj, dict):
            obj = None
    if not isinstance(obj, dict):
        raise ValueError(f"replay record {record!r} has no exchange")
    parsed = exchange_from_obj(obj)
    if not parsed or not parsed.get("url"):
        raise ValueError(f"replay record {record!r} has no request url")
    return parsed


def scope_error(url: str, *, allow_external: bool, scope_hosts: list[str] | None) -> str:
    """Empty when this URL may be resent. Otherwise the refusal reason."""
    host = ""
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        host = ""
    if not host:
        return "replay url has no host"
    if not host_in_scope(host, scope_hosts):
        return f"out of scope: {host}"
    if not allow_external and not _is_loopback_host(host):
        return f"{host} requires --allow-external"
    return ""


def replay_exchange(
    record: str,
    *,
    allow_external: bool = False,
    scope_hosts: list[str] | None = None,
    finding: dict[str, Any] | None = None,
    sender: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Resend one exchange. A scope refusal does not call ``sender``."""
    try:
        exchange = load_exchange(record, finding=finding)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": str(exc), "verified": False}
    url = str(exchange.get("url") or "")
    refused = scope_error(url, allow_external=allow_external, scope_hosts=scope_hosts)
    if refused:
        return {
            "ok": False,
            "error": refused,
            "verified": False,
            "method": exchange.get("method") or "",
            "url": url,
        }
    method = str(exchange.get("method") or "GET")
    headers = dict(exchange.get("headers") or {})
    body = str(exchange.get("body") or "")
    if sender is None:
        sender = _default_send
    try:
        sent = sender(method=method, url=url, headers=headers, body=body)
    except Exception as exc:  # noqa: BLE001 - the command reports the failure
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "verified": False, "url": url}
    status = 0
    text = ""
    if isinstance(sent, dict):
        status = int(sent.get("status_code") or 0)
        text = str(sent.get("text") or "")
    else:
        status = int(getattr(sent, "status_code", 0) or 0)
        text = str(getattr(sent, "text", "") or "")[:2000]
    return {
        "ok": True,
        "verified": False,
        "method": method,
        "url": url,
        "status_code": status,
        "body_excerpt": text[:2000],
        "session_id": exchange.get("session_id") or "",
    }


def _default_send(*, method: str, url: str, headers: dict[str, str], body: str) -> Any:
    import httpx

    return httpx.request(
        method,
        url,
        headers=headers,
        content=body.encode("utf-8") if body else None,
        timeout=30.0,
        follow_redirects=False,
    )
