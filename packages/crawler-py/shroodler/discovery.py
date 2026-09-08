"""Discover live subdomains and JS API endpoints for a program.

Never raises on a crt.sh timeout or parse failure: log the error and
return whatever was found so far.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from shroodler import program
from shroodler.extractors.js_api_surface import extract_endpoints
from shroodler.modes.static import StaticFetcher
from shroodler.program import ProgramState
from shroodler.robots import DEFAULT_UA
from shroodler.urls import same_origin


@dataclass
class DiscoveryResult:
    subdomains_found: list[str]
    subdomains_added_to_state: int
    endpoints_found: list[str]
    elapsed_ms: int


@dataclass
class DiscoveryConfig:
    target: str
    max_subdomains: int = 300
    probe_timeout: float = 5.0
    probe_workers: int = 20
    skip_crtsh: bool = False
    skip_js_surface: bool = False
    dry_run: bool = False
    enforcer: Any = None


def _log_error(message: str) -> None:
    print(json.dumps({"error": message}, default=str), file=sys.stderr, flush=True)


def apex_domain(target: str) -> str:
    """https://api.example.com -> example.com (last two labels)."""
    raw = (target or "").strip()
    host = urlparse(raw).hostname if "://" in raw else raw
    host = (host or raw).lower().rstrip(".")
    if host.startswith("[") and "]" in host:
        return host
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def parse_crtsh_names(payload: Any, apex: str) -> list[str]:
    """Extract unique in-scope FQDNs from a crt.sh JSON array.

    Drops wildcards, values with embedded newlines, and off-apex names.
    The apex itself is kept even though it does not end with `.{apex}`.
    Never raises.
    """
    try:
        if isinstance(payload, (bytes, bytearray)):
            payload = payload.decode("utf-8", errors="replace")
        if isinstance(payload, str):
            payload = json.loads(payload)
        if not isinstance(payload, list):
            return []
    except (json.JSONDecodeError, TypeError, ValueError, UnicodeError) as exc:
        _log_error(f"crt.sh parse: {type(exc).__name__}: {exc}")
        return []

    apex_norm = (apex or "").lower().rstrip(".")
    suffix = f".{apex_norm}" if apex_norm else ""
    names: list[str] = []
    seen: set[str] = set()
    for row in payload:
        try:
            if isinstance(row, dict):
                raw = str(row.get("name_value") or "")
            else:
                raw = str(row or "")
            if "\n" in raw or "\r" in raw:
                continue
            name = raw.strip().lower().rstrip(".")
            if not name or "*" in name:
                continue
            if name != apex_norm and (not suffix or not name.endswith(suffix)):
                continue
            if name in seen:
                continue
            seen.add(name)
            names.append(name)
        except Exception as exc:  # noqa: BLE001 - never raise on a bad row
            _log_error(f"crt.sh row: {type(exc).__name__}: {exc}")
            continue
    return names


def fetch_crtsh_candidates(apex: str, timeout: float = 5.0) -> list[str]:
    """GET crt.sh CT logs. Returns [] on timeout/parse/HTTP failure."""
    apex_norm = (apex or "").lower().rstrip(".")
    if not apex_norm:
        return []
    url = f"https://crt.sh/?q=%25.{apex_norm}&output=json"
    try:
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            trust_env=False,
            headers={"User-Agent": DEFAULT_UA},
        ) as client:
            resp = client.get(url)
            resp.raise_for_status()
            payload = resp.json()
    except Exception as exc:  # noqa: BLE001 - never raise on crt.sh failure
        _log_error(f"crt.sh: {type(exc).__name__}: {exc}")
        return []
    try:
        return parse_crtsh_names(payload, apex_norm)
    except Exception as exc:  # noqa: BLE001
        _log_error(f"crt.sh parse: {type(exc).__name__}: {exc}")
        return []


def _is_live_result(result: Any) -> bool:
    status = int(getattr(result, "status_code", 0) or 0)
    return status > 0


def probe_subdomains(
    candidates: list[str],
    *,
    timeout: float = 5.0,
    workers: int = 20,
    enforcer: Any = None,
) -> list[str]:
    """Probe https://{fqdn}/. Any HTTP status is live; connection errors are dead."""
    if not candidates:
        return []
    fetcher = StaticFetcher(timeout=timeout)
    lock = threading.Lock()
    live: list[str | None] = [None] * len(candidates)

    def probe(index_and_fqdn: tuple[int, str]) -> None:
        idx, fqdn = index_and_fqdn
        url = f"https://{fqdn}/"
        try:
            if enforcer is not None:
                with lock:
                    allowed, _reason = enforcer.check(url)
                if not allowed:
                    return
            result = fetcher.fetch(url)
            if _is_live_result(result):
                live[idx] = fqdn
        except Exception:  # noqa: BLE001 - connection errors are dead
            return

    try:
        max_workers = max(1, int(workers or 1))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            list(pool.map(probe, enumerate(candidates)))
    finally:
        fetcher.close()
    return [fqdn for fqdn in live if fqdn]


def _js_urls_from_pages(pages: list[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for page in pages:
        if not isinstance(page, dict):
            continue
        raw_lists: list[Any] = []
        for key in ("js_files", "script_srcs", "scripts", "js_urls"):
            val = page.get(key)
            if isinstance(val, list):
                raw_lists.extend(val)
            elif isinstance(val, str) and val:
                raw_lists.append(val)
        base = str(page.get("url") or "")
        for raw in raw_lists:
            if not isinstance(raw, str) or not raw.strip():
                continue
            url = urljoin(base, raw.strip()) if base else raw.strip()
            if url not in seen:
                seen.add(url)
                out.append(url)
    return out


def expand_js_surface(
    state: ProgramState,
    target: str,
    *,
    timeout: float = 5.0,
    enforcer: Any = None,
) -> list[str]:
    """Fetch JS from the latest scan's pages and extract same-origin endpoints."""
    if not state.scans:
        return []
    pages = state.scans[-1].get("pages") if isinstance(state.scans[-1], dict) else None
    if not isinstance(pages, list) or not pages:
        return []
    js_urls = _js_urls_from_pages(pages)
    if not js_urls:
        return []

    origin_base = target if target.endswith("/") else target + "/"
    found: list[str] = []
    seen: set[str] = set()
    fetcher = StaticFetcher(timeout=timeout)
    try:
        for js_url in js_urls:
            try:
                if enforcer is not None:
                    allowed, _reason = enforcer.check(js_url)
                    if not allowed:
                        continue
                result = fetcher.fetch(js_url)
            except Exception as exc:  # noqa: BLE001
                _log_error(f"js fetch {js_url}: {type(exc).__name__}: {exc}")
                continue
            if not _is_live_result(result):
                continue
            body = getattr(result, "text", "") or ""
            try:
                endpoints = extract_endpoints(body)
            except Exception as exc:  # noqa: BLE001
                _log_error(f"js extract {js_url}: {type(exc).__name__}: {exc}")
                continue
            for raw in endpoints or []:
                if not isinstance(raw, str) or not raw.strip():
                    continue
                resolved = urljoin(origin_base, raw.strip())
                try:
                    if not same_origin(resolved, target):
                        continue
                except ValueError:
                    continue
                if resolved in state.endpoints or resolved in seen:
                    continue
                seen.add(resolved)
                found.append(resolved)
    finally:
        fetcher.close()
    return found


def discover(state: ProgramState, target: str, config: DiscoveryConfig) -> DiscoveryResult:
    started = time.monotonic()
    target = target or config.target
    subdomains: list[str] = []
    endpoints: list[str] = []

    if not config.skip_crtsh:
        try:
            apex = apex_domain(target)
            candidates = fetch_crtsh_candidates(apex, timeout=config.probe_timeout)
            cap = max(0, int(config.max_subdomains))
            candidates = candidates[:cap]
            subdomains = probe_subdomains(
                candidates,
                timeout=config.probe_timeout,
                workers=config.probe_workers,
                enforcer=config.enforcer,
            )
        except Exception as exc:  # noqa: BLE001 - never raise on crt.sh/probe failure
            _log_error(f"discovery crt.sh: {type(exc).__name__}: {exc}")

    if not config.skip_js_surface:
        try:
            endpoints = expand_js_surface(
                state,
                target,
                timeout=config.probe_timeout,
                enforcer=config.enforcer,
            )
        except Exception as exc:  # noqa: BLE001
            _log_error(f"discovery js: {type(exc).__name__}: {exc}")

    added = 0
    for fqdn in subdomains:
        scoped = f"https://{fqdn}/"
        if scoped not in state.scope_urls:
            added += 1
            if not config.dry_run:
                state.scope_urls.append(scoped)
        if not config.dry_run and scoped not in state.endpoints:
            state.endpoints[scoped] = program._endpoint_meta(scoped, program._now())

    new_endpoints: list[str] = []
    for url in endpoints:
        if url in state.endpoints:
            continue
        new_endpoints.append(url)
        if not config.dry_run:
            state.endpoints[url] = program._endpoint_meta(url, program._now())

    if not config.dry_run:
        program.save(state)

    elapsed_ms = int((time.monotonic() - started) * 1000)
    return DiscoveryResult(
        subdomains_found=list(subdomains),
        subdomains_added_to_state=added,
        endpoints_found=new_endpoints,
        elapsed_ms=elapsed_ms,
    )
