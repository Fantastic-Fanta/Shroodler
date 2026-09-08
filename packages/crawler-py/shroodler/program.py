"""Per-program engagement memory under ~/.shroodler/programs/<slug>/state.json.

Tracks endpoints, object IDs, findings, and sessions across crawls so an
agent (or a human) can pick up where the last session left off.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from shroodler.models import Finding

_SLUG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_INT_ID_RE = re.compile(r"^[0-9]{1,18}$")
_ID_KEY_RE = re.compile(r"^(id|.+_id|.+Id)$")
_STALE_AFTER = timedelta(hours=24)


def programs_root() -> Path:
    return Path.home() / ".shroodler" / "programs"


def validate_slug(slug: str) -> str:
    if not slug or not _SLUG_RE.fullmatch(slug):
        raise ValueError(
            f"invalid program slug {slug!r}: use 1-64 chars of letters, "
            "digits, '.', '_' or '-' (must start with alphanumeric)"
        )
    return slug


def program_dir(slug: str) -> Path:
    return programs_root() / validate_slug(slug)


def state_path(slug: str) -> Path:
    return program_dir(slug) / "state.json"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ts(raw: str | None) -> datetime | None:
    if not raw:
        return None
    text = str(raw).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass
class ProgramState:
    slug: str
    scope_urls: list[str] = field(default_factory=list)
    scope_out: list[str] = field(default_factory=list)
    endpoints: dict[str, dict[str, Any]] = field(default_factory=dict)
    object_ids: dict[str, list[str]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    sessions: list[dict[str, Any]] = field(default_factory=list)
    scans: list[dict[str, Any]] = field(default_factory=list)


def _finding_to_dict(finding: Finding | dict) -> dict[str, Any]:
    if isinstance(finding, Finding):
        return finding.model_dump(exclude_none=True)
    return dict(finding)


def _finding_from_dict(raw: dict) -> Finding | None:
    try:
        return Finding(
            id=str(raw.get("id") or ""),
            severity=raw.get("severity") or "info",
            category=raw.get("category") or "scan-note",
            url=str(raw.get("url") or ""),
            description=str(raw.get("description") or ""),
            evidence=raw.get("evidence"),
            confidence=raw.get("confidence"),
        )
    except Exception:
        return None


def load(slug: str) -> ProgramState:
    """Read ~/.shroodler/programs/<slug>/state.json, creating an empty
    state file if the program does not exist yet.
    """
    validate_slug(slug)
    path = state_path(slug)
    if not path.is_file():
        state = ProgramState(slug=slug)
        save(state)
        return state
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    findings: list[Finding] = []
    for item in data.get("findings") or []:
        if isinstance(item, dict):
            parsed = _finding_from_dict(item)
            if parsed is not None:
                findings.append(parsed)
    endpoints = data.get("endpoints") or {}
    if not isinstance(endpoints, dict):
        endpoints = {}
    object_ids = data.get("object_ids") or {}
    if not isinstance(object_ids, dict):
        object_ids = {}
    cleaned_ids: dict[str, list[str]] = {}
    for key, vals in object_ids.items():
        if isinstance(vals, list):
            cleaned_ids[str(key)] = [str(v) for v in vals if str(v)]
    return ProgramState(
        slug=str(data.get("slug") or slug),
        scope_urls=[str(u) for u in (data.get("scope_urls") or []) if str(u)],
        scope_out=[str(u) for u in (data.get("scope_out") or []) if str(u)],
        endpoints={str(k): dict(v) if isinstance(v, dict) else {} for k, v in endpoints.items()},
        object_ids=cleaned_ids,
        findings=findings,
        sessions=[dict(s) for s in (data.get("sessions") or []) if isinstance(s, dict)],
        scans=[dict(s) for s in (data.get("scans") or []) if isinstance(s, dict)],
    )


def save(state: ProgramState) -> Path:
    """Atomic write: dump to state.json.tmp then rename over state.json."""
    path = state_path(state.slug)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "slug": state.slug,
        "scope_urls": list(state.scope_urls),
        "scope_out": list(state.scope_out),
        "endpoints": dict(state.endpoints),
        "object_ids": dict(state.object_ids),
        "findings": [_finding_to_dict(f) for f in state.findings],
        "sessions": list(state.sessions),
        "scans": list(state.scans),
    }
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def _endpoint_meta(url: str, last_seen: str) -> dict[str, Any]:
    return {
        "tested_authz": False,
        "tested_peer_write": False,
        "tested_payload": False,
        "last_seen": last_seen,
    }


def url_to_pattern(url: str) -> str:
    """Replace UUID / integer path segments with {id} so object IDs group."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    parts: list[str] = []
    for seg in path.split("/"):
        if not seg:
            continue
        if _UUID_RE.fullmatch(seg) or _INT_ID_RE.fullmatch(seg):
            parts.append("{id}")
        else:
            parts.append(seg)
    prefix = "/" + "/".join(parts) if parts else "/"
    if path.endswith("/") and prefix != "/":
        prefix += "/"
    return prefix


def _walk_object_ids(value: Any, out: list[str]) -> None:
    if isinstance(value, dict):
        for key, val in value.items():
            key_s = str(key)
            if _ID_KEY_RE.match(key_s):
                if isinstance(val, bool):
                    pass
                elif isinstance(val, int) and not isinstance(val, bool):
                    out.append(str(val))
                elif isinstance(val, str) and (
                    _UUID_RE.fullmatch(val) or _INT_ID_RE.fullmatch(val)
                ):
                    out.append(val)
            _walk_object_ids(val, out)
    elif isinstance(value, list):
        for item in value:
            _walk_object_ids(item, out)
    elif isinstance(value, str) and _UUID_RE.fullmatch(value):
        out.append(value)


def extract_object_ids(body: str) -> list[str]:
    text = (body or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    found: list[str] = []
    _walk_object_ids(data, found)
    seen: set[str] = set()
    out: list[str] = []
    for item in found:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _page_bodies(page: dict) -> list[str]:
    bodies: list[str] = []
    for key in ("body", "text", "response_body"):
        val = page.get(key)
        if isinstance(val, str) and val.strip():
            bodies.append(val)
    return bodies


def merge_crawl_doc(state: ProgramState, doc: dict) -> dict[str, int]:
    """Ingest an in-memory crawl document. Returns a delta of counts."""
    last_seen = str(doc.get("scan_finished_at") or doc.get("scan_started_at") or _now())
    new_endpoints = 0
    updated_endpoints = 0
    urls: list[str] = []
    for page in doc.get("pages") or []:
        if not isinstance(page, dict):
            continue
        url = str(page.get("url") or "")
        if not url:
            continue
        urls.append(url)
        meta = state.endpoints.get(url)
        if meta is None:
            state.endpoints[url] = _endpoint_meta(url, last_seen)
            new_endpoints += 1
        else:
            meta["last_seen"] = last_seen
            updated_endpoints += 1
        pattern = url_to_pattern(url)
        for body in _page_bodies(page):
            ids = extract_object_ids(body)
            if not ids:
                continue
            bucket = state.object_ids.setdefault(pattern, [])
            for oid in ids:
                if oid not in bucket:
                    bucket.append(oid)
    for ep in doc.get("js_endpoints") or []:
        if not isinstance(ep, dict):
            continue
        endpoint = str(ep.get("endpoint") or "")
        source = str(ep.get("source") or "")
        url = endpoint if endpoint.startswith("http") else source
        if url and url not in state.endpoints:
            state.endpoints[url] = _endpoint_meta(url, last_seen)
            new_endpoints += 1
            urls.append(url)

    new_findings = 0
    seen = {(f.id, f.url) for f in state.findings}
    for raw in doc.get("findings") or []:
        if not isinstance(raw, dict):
            continue
        parsed = _finding_from_dict(raw)
        if parsed is None:
            continue
        key = (parsed.id, parsed.url)
        if key in seen:
            continue
        seen.add(key)
        state.findings.append(parsed)
        new_findings += 1

    new_object_ids = sum(len(v) for v in state.object_ids.values())
    pages_snapshot: list[dict[str, Any]] = []
    for page in doc.get("pages") or []:
        if not isinstance(page, dict):
            continue
        page_url = str(page.get("url") or "")
        if not page_url:
            continue
        js_files = page.get("js_files") or []
        if not isinstance(js_files, list):
            js_files = []
        pages_snapshot.append(
            {
                "url": page_url,
                "js_files": [str(u) for u in js_files if u],
            }
        )
    state.scans.append(
        {
            "timestamp": last_seen,
            "type": "crawl",
            "finding_count": len(doc.get("findings") or []),
            "pages": pages_snapshot,
        }
    )
    return {
        "new_endpoints": new_endpoints,
        "updated_endpoints": updated_endpoints,
        "new_findings": new_findings,
        "object_id_values": new_object_ids,
        "pages": len(urls),
    }


def merge_crawl(state: ProgramState, crawl_json_path: str | Path) -> dict[str, int]:
    doc = json.loads(Path(crawl_json_path).read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("crawl JSON must be an object")
    return merge_crawl_doc(state, doc)


def coverage_gaps(state: ProgramState) -> list[dict[str, Any]]:
    """Endpoints not yet tested for authz or peer-write, last_seen desc."""
    gaps: list[dict[str, Any]] = []
    for url, meta in state.endpoints.items():
        tested_authz = bool(meta.get("tested_authz"))
        tested_peer = bool(meta.get("tested_peer_write"))
        if tested_authz and tested_peer:
            continue
        gaps.append(
            {
                "url": url,
                "tested_authz": tested_authz,
                "tested_peer_write": tested_peer,
                "tested_payload": bool(meta.get("tested_payload")),
                "last_seen": str(meta.get("last_seen") or ""),
            }
        )
    gaps.sort(key=lambda g: g.get("last_seen") or "", reverse=True)
    return gaps


def mark_tested(state: ProgramState, urls: list[str], field: str) -> int:
    """Set tested_authz / tested_peer_write / tested_payload on matching URLs."""
    if field not in {"tested_authz", "tested_peer_write", "tested_payload"}:
        raise ValueError(f"unknown tested field {field!r}")
    n = 0
    now = _now()
    for url in urls:
        if not url:
            continue
        meta = state.endpoints.get(url)
        if meta is None:
            meta = _endpoint_meta(url, now)
            state.endpoints[url] = meta
        if not meta.get(field):
            n += 1
        meta[field] = True
        meta["last_seen"] = meta.get("last_seen") or now
    return n


def add_session(
    state: ProgramState,
    path: str,
    label: str,
    expires: str | None = None,
) -> dict[str, Any]:
    record = {
        "label": label,
        "path": str(path),
        "captured_at": _now(),
        "expires_hint": expires,
    }
    state.sessions.append(record)
    return record


def stale_sessions(state: ProgramState, now: datetime | None = None) -> list[dict[str, Any]]:
    now = now or datetime.now(timezone.utc)
    out: list[dict[str, Any]] = []
    for sess in state.sessions:
        captured = _parse_ts(sess.get("captured_at"))
        expires = _parse_ts(sess.get("expires_hint"))
        stale = False
        if expires is not None and expires <= now:
            stale = True
        elif captured is not None and (now - captured) > _STALE_AFTER:
            stale = True
        if stale:
            out.append(dict(sess))
    return out


def unconfirmed_leads(state: ProgramState) -> list[Finding]:
    out: list[Finding] = []
    for finding in state.findings:
        conf = finding.confidence
        if conf == "confirmed":
            continue
        if finding.category == "scan-note" and finding.severity in {"info", "low"}:
            continue
        out.append(finding)
    return out


def object_ids_flat(state: ProgramState, only_id: str | None = None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for ids in state.object_ids.values():
        for oid in ids:
            if only_id and oid != only_id:
                continue
            if oid not in seen:
                seen.add(oid)
                out.append(oid)
    return out


def apply_program_ids(
    playbook: dict[str, Any],
    state: ProgramState,
    *,
    only_id: str | None = None,
) -> dict[str, Any]:
    """Expand playbook writes across stored object IDs for matching URL patterns."""
    from shroodler.peer_write import swap_id_in_body, swap_object_id

    doc = dict(playbook)
    writes = list(doc.get("writes") or [])
    if not writes:
        doc["program_object_ids"] = object_ids_flat(state, only_id)
        return doc
    expanded: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for write in writes:
        url = str(write.get("url") or "")
        current = str(write.get("id_value") or "")
        pattern = url_to_pattern(url)
        candidates = list(state.object_ids.get(pattern) or [])
        if current and current not in candidates:
            candidates = [current, *candidates]
        if not candidates:
            expanded.append(write)
            continue
        for oid in candidates:
            if only_id and oid != only_id:
                continue
            new_url = swap_object_id(url, current, oid) if current else url
            body = str(write.get("body") or "")
            new_body = swap_id_in_body(body, current, oid) if current and body else body
            key = (str(write.get("method") or ""), new_url, oid)
            if key in seen:
                continue
            seen.add(key)
            expanded.append({**write, "url": new_url, "body": new_body, "id_value": oid})
    doc["writes"] = expanded
    return doc


def load_scope_file(path: str | Path) -> tuple[list[str], list[str]]:
    """One URL/glob per line. Lines starting with '!' / '-' go to scope_out."""
    ins: list[str] = []
    out: list[str] = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!") or line.startswith("- "):
            out.append(line[1:].strip() if line.startswith("!") else line[2:].strip())
        elif line.startswith("-"):
            out.append(line[1:].strip())
        else:
            ins.append(line)
    return ins, out


def as_briefing(state: ProgramState) -> dict[str, Any]:
    gaps = coverage_gaps(state)
    stale = stale_sessions(state)
    leads = unconfirmed_leads(state)
    warning = None
    if stale:
        labels = ", ".join(str(s.get("label") or s.get("path") or "?") for s in stale[:3])
        warning = (
            f"{len(stale)} session(s) captured more than 24h ago or past "
            f"expires_hint ({labels}). Refresh via session-export before authz-diff."
        )
    return {
        "slug": state.slug,
        "scope": {"in": list(state.scope_urls), "out": list(state.scope_out)},
        "endpoint_count": len(state.endpoints),
        "finding_count": len(state.findings),
        "coverage_gaps": gaps[:10],
        "coverage_gap_count": len(gaps),
        "unconfirmed_leads": len(leads),
        "stale_sessions": stale,
        "stale_session_warning": warning,
        "object_id_patterns": len(state.object_ids),
    }
