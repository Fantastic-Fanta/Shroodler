"""Convert Nuclei HTTP YAML templates into Shroodler payload-pack shape.

This is a loader, not a CVE library: it does not fetch or vendor Nuclei
templates. Operators pass local YAML they already have. Templates with
no injectable payload (or only matchers we cannot express) are skipped.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_SEVERITY = {"info", "low", "medium", "high", "critical"}


def is_nuclei_template(obj: object) -> bool:
    if not isinstance(obj, dict):
        return False
    if not isinstance(obj.get("info"), dict):
        return False
    return "http" in obj or "requests" in obj


def to_packs(obj: dict) -> list[dict]:
    tid = str(obj.get("id") or "nuclei").strip() or "nuclei"
    info = obj.get("info") or {}
    severity = str(info.get("severity") or "medium").lower()
    if severity not in _SEVERITY:
        severity = "medium"
    desc = str(info.get("description") or info.get("name") or tid)
    blocks = obj.get("http") if obj.get("http") is not None else obj.get("requests")
    if isinstance(blocks, dict):
        blocks = [blocks]
    if not isinstance(blocks, list):
        return []
    packs: list[dict] = []
    for i, block in enumerate(blocks):
        if not isinstance(block, dict):
            continue
        payloads = _payload_values(block)
        match = _match_from_matchers(block)
        if not payloads:
            continue
        if not match:
            match = {"any": [{"reflected": True}]}
        multi = len(payloads) > 1 or len(blocks) > 1
        for j, payload in enumerate(payloads):
            pid = f"{tid}-{i}-{j}" if multi else tid
            packs.append(
                {
                    "id": pid,
                    "finding_id": f"nuclei-{tid}",
                    "payload": payload,
                    "severity": severity,
                    "description": desc,
                    "match": match,
                }
            )
    return packs


def convert_files(paths: list[Path]) -> tuple[list[dict], list[str]]:
    packs: list[dict] = []
    skipped: list[str] = []
    for path in paths:
        loaded = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if not is_nuclei_template(loaded):
            skipped.append(f"{path}: not a Nuclei HTTP template")
            continue
        converted = to_packs(loaded)
        if not converted:
            skipped.append(f"{path}: no convertible payloads")
            continue
        packs.extend(converted)
    return packs, skipped


def dumps_pack(packs: list[dict]) -> str:
    return yaml.safe_dump(packs, sort_keys=False, allow_unicode=True)


def _payload_values(block: dict) -> list[str]:
    raw = block.get("payloads")
    out: list[str] = []
    if isinstance(raw, dict):
        for values in raw.values():
            if isinstance(values, list):
                out.extend(str(v) for v in values if v is not None and str(v))
            elif values is not None and str(values):
                out.append(str(values))
    body = block.get("body")
    if isinstance(body, str) and body.strip() and "{{" not in body:
        out.append(body.strip())
    # De-dupe, preserve order.
    seen: set[str] = set()
    uniq: list[str] = []
    for item in out:
        if item not in seen:
            seen.add(item)
            uniq.append(item)
    return uniq


def _match_from_matchers(block: dict) -> dict | None:
    matchers = block.get("matchers") or []
    if not isinstance(matchers, list):
        return None
    condition = str(block.get("matchers-condition") or "or").lower()
    clauses: list[dict] = []
    for matcher in matchers:
        if not isinstance(matcher, dict):
            continue
        clauses.extend(_clauses_from_matcher(matcher))
    if not clauses:
        return None
    key = "all" if condition == "and" else "any"
    return {key: clauses}


def _clauses_from_matcher(matcher: dict) -> list[dict]:
    kind = str(matcher.get("type") or "").lower()
    part = str(matcher.get("part") or "body").lower()
    if kind == "word":
        words = matcher.get("words") or []
        if not isinstance(words, list):
            words = [words]
        clauses = []
        for word in words:
            if word is None or str(word) == "":
                continue
            clauses.append(_word_clause(str(word), part))
        return clauses
    if kind == "status":
        statuses = matcher.get("status") or []
        if not isinstance(statuses, list):
            statuses = [statuses]
        nums = [int(s) for s in statuses if str(s).isdigit() or isinstance(s, int)]
        if not nums:
            return []
        return [{"status_gte": min(nums)}]
    return []


def _word_clause(word: str, part: str) -> dict:
    if part in {"header", "headers"}:
        return {"header_contains": word}
    if part in {"location", "header_location"}:
        return {"redirected_to_contains": word}
    return {"body_contains": word}
