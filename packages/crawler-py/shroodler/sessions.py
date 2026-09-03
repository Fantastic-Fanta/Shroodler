from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from shroodler import __version__
from shroodler.crawler import page_from_fetch
from shroodler.extractors.secrets import scan_text
from shroodler.models import CrawlerInfo, CrawlResult, CrawlStats
from shroodler.modes.static import FetchResult, _decode_body
from shroodler.urls import canonical_key, is_loopback_or_local, origin, same_origin

_SKIP_METHODS = {"CONNECT", "OPTIONS"}
_SET_COOKIE_SPLIT = re.compile(r", (?=[^ ;,]+=)")


def header_get(headers: dict[str, Any] | None, name: str) -> str:
    if not headers:
        return ""
    want = name.lower()
    for k, v in headers.items():
        if str(k).lower() == want:
            return v if isinstance(v, str) else str(v)
    return ""


def split_set_cookie(raw: str) -> list[str]:
    raw = (raw or "").strip()
    if not raw:
        return []
    return [p.strip() for p in _SET_COOKIE_SPLIT.split(raw) if p.strip()]


def cookie_pairs_from_header(raw: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for part in (raw or "").split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        skip = {"secure", "httponly", "samesite", "path", "domain", "expires", "max-age"}
        if not name or name.lower() in skip:
            continue
        out.append((name, value.strip()))
    return out


def cookie_pairs_from_set_cookie(raw: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for cookie in split_set_cookie(raw):
        first = cookie.split(";", 1)[0]
        if "=" not in first:
            continue
        name, value = first.split("=", 1)
        name = name.strip()
        if name:
            out.append((name, value.strip()))
    return out


def load_sessions(path: str | Path) -> list[dict[str, Any]]:
    text = Path(path).read_text(encoding="utf-8")
    sessions: list[dict[str, Any]] = []
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid session JSONL at line {i}: {exc}") from exc
        if isinstance(obj, dict):
            sessions.append(obj)
    return sessions


def _request_url(sess: dict[str, Any]) -> str:
    req = sess.get("request") or {}
    return str(req.get("url") or "")


def _usable(sess: dict[str, Any]) -> bool:
    method = str((sess.get("request") or {}).get("method") or "GET").upper()
    if method in _SKIP_METHODS:
        return False
    url = _request_url(sess)
    return bool(url) and "://" in url


def seed_urls(sessions: list[dict[str, Any]], origin_url: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for sess in sessions:
        if not _usable(sess):
            continue
        url = _request_url(sess)
        if origin_url and not same_origin(url, origin_url):
            continue
        key = canonical_key(url)
        if key in seen:
            continue
        seen.add(key)
        out.append(url)
    return out


def cookie_header(sessions: list[dict[str, Any]], origin_url: str) -> str:
    jar: dict[str, str] = {}
    for sess in sessions:
        if not _usable(sess):
            continue
        url = _request_url(sess)
        if origin_url and not same_origin(url, origin_url):
            continue
        req = sess.get("request") or {}
        for name, value in cookie_pairs_from_header(header_get(req.get("headers"), "Cookie")):
            jar[name] = value
        resp = sess.get("response") or {}
        if not isinstance(resp, dict):
            continue
        sc = header_get(resp.get("headers"), "Set-Cookie")
        for name, value in cookie_pairs_from_set_cookie(sc):
            jar[name] = value
    return "; ".join(f"{k}={v}" for k, v in jar.items())


def _body_text(body: dict[str, Any] | None) -> str:
    if not body:
        return ""
    encoding = str(body.get("encoding") or "utf8")
    content = str(body.get("content") or "")
    if encoding == "base64":
        import base64

        try:
            raw = base64.b64decode(content)
        except Exception:
            return content
        return _decode_body(raw, header_get({}, "content-type") or "text/plain")
    return content


def fetch_result_from_session(sess: dict[str, Any]) -> FetchResult:
    req = sess.get("request") or {}
    resp = sess.get("response") if isinstance(sess.get("response"), dict) else {}
    url = str(req.get("url") or "")
    headers = {str(k): str(v) for k, v in (resp.get("headers") or {}).items()}
    text = _body_text(resp.get("body"))
    set_cookies = split_set_cookie(header_get(headers, "Set-Cookie"))
    status = int(resp.get("status_code") or 0)
    return FetchResult(
        url=url,
        status_code=status,
        headers=headers,
        body=text.encode("utf-8", errors="replace"),
        text=text,
        redirect_to=None,
        set_cookies=set_cookies,
    )


def ingest_sessions(
    path: str | Path,
    *,
    target: str | None = None,
    allow_external: bool = False,
) -> CrawlResult:
    from datetime import datetime, timezone
    from time import monotonic

    sessions = load_sessions(path)
    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = monotonic()
    inferred = target
    if not inferred:
        for sess in sessions:
            if _usable(sess):
                inferred = origin(_request_url(sess))
                break
    if not inferred:
        raise ValueError(
            "no sessions to ingest; pass --target or capture at least one HTTP session"
        )
    if "://" not in inferred:
        inferred = "http://" + inferred
    if not allow_external and not is_loopback_or_local(inferred):
        raise ValueError(
            "refusing to ingest non-local host; pass --allow-external to scan a remote target"
        )

    extra_findings = []
    last_by_key: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for sess in sessions:
        if not _usable(sess):
            continue
        url = _request_url(sess)
        if not same_origin(url, inferred):
            continue
        req = sess.get("request") or {}
        blob = _body_text(req.get("body"))
        hdrs = req.get("headers") or {}
        if isinstance(hdrs, dict):
            blob = blob + "\n" + "\n".join(f"{k}: {v}" for k, v in hdrs.items())
        if blob.strip():
            extra_findings.extend(scan_text(blob, url))
        resp = sess.get("response")
        if not isinstance(resp, dict):
            continue
        key = canonical_key(url)
        if key not in last_by_key:
            order.append(key)
        last_by_key[key] = sess

    pages = []
    findings = list(extra_findings)
    endpoints = []
    for key in order:
        page, page_findings, page_eps = page_from_fetch(fetch_result_from_session(last_by_key[key]))
        pages.append(page)
        findings.extend(page_findings)
        endpoints.extend(page_eps)

    from shroodler.crawler import _dedupe_endpoints, _dedupe_findings

    finished = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return CrawlResult(
        target=inferred,
        scan_started_at=started,
        scan_finished_at=finished,
        crawler=CrawlerInfo(name="shroodler-py", version=__version__, mode="ingest"),
        pages=pages,
        findings=_dedupe_findings(findings),
        js_endpoints=_dedupe_endpoints(endpoints),
        stats=CrawlStats(
            pages_crawled=len(pages),
            requests=len(order),
            elapsed_ms=int((monotonic() - t0) * 1000),
        ),
    )
