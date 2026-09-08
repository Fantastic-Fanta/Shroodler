"""Translate Slither JSON into Shroodler's finding schema.

A loader, not an EVM analyzer: operators run Slither themselves and hand
Shroodler the JSON. Mirrors `nuclei-ingest` — never shells out to Slither
or vendors its detectors.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any

from shroodler import __version__
from shroodler.models import CrawlerInfo, CrawlResult, CrawlStats, Finding

_IMPACT_TO_SEVERITY = {
    "informational": "info",
    "info": "info",
    "optimization": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

_SLITHER_CONFIDENCE = {
    "high": "confirmed",
    "medium": "probable",
    "low": "heuristic",
}


def is_slither_report(obj: object) -> bool:
    if not isinstance(obj, dict):
        return False
    results = obj.get("results")
    if isinstance(results, dict) and isinstance(results.get("detectors"), list):
        return True
    return isinstance(obj.get("detectors"), list)


def detectors_of(obj: dict[str, Any]) -> list[dict[str, Any]]:
    results = obj.get("results")
    if isinstance(results, dict) and isinstance(results.get("detectors"), list):
        raw = results["detectors"]
    else:
        raw = obj.get("detectors") or []
    return [item for item in raw if isinstance(item, dict)]


def _severity(detector: dict[str, Any]) -> str:
    impact = str(detector.get("impact") or "medium").lower()
    return _IMPACT_TO_SEVERITY.get(impact, "medium")


def _confidence(detector: dict[str, Any]) -> str:
    conf = str(detector.get("confidence") or "").lower()
    return _SLITHER_CONFIDENCE.get(conf, "probable")


def _source_url(detector: dict[str, Any]) -> str:
    marker = str(detector.get("first_markdown_element") or "").strip()
    if marker:
        return marker
    for element in detector.get("elements") or []:
        if not isinstance(element, dict):
            continue
        mapping = element.get("source_mapping")
        if not isinstance(mapping, dict):
            continue
        path = (
            mapping.get("filename_relative")
            or mapping.get("filename_short")
            or mapping.get("filename_absolute")
            or ""
        )
        path = str(path).strip()
        if not path:
            continue
        lines = mapping.get("lines")
        if isinstance(lines, list) and lines:
            return f"{path}#L{lines[0]}"
        return path
    check = str(detector.get("check") or "detector").strip() or "detector"
    return check


def to_findings(obj: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for detector in detectors_of(obj):
        check = str(detector.get("check") or "detector").strip() or "detector"
        desc = str(detector.get("description") or detector.get("markdown") or check).strip()
        evidence = str(detector.get("first_markdown_element") or check)
        out.append(
            Finding(
                id=f"slither-{check}",
                severity=_severity(detector),  # type: ignore[arg-type]
                category="smart-contract",
                url=_source_url(detector),
                description=desc,
                evidence=evidence,
                confidence=_confidence(detector),  # type: ignore[arg-type]
            )
        )
    return out


def convert_file(path: str | Path, *, target: str | None = None) -> CrawlResult:
    from shroodler.crawler import _dedupe_findings

    started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    t0 = monotonic()
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not is_slither_report(raw):
        raise ValueError(f"{path}: not a Slither JSON report (missing results.detectors)")
    findings = to_findings(raw)
    inferred = (target or "").strip()
    if not inferred:
        inferred = findings[0].url.split("#", 1)[0] if findings else str(path)
    finished = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return CrawlResult(
        target=inferred,
        scan_started_at=started,
        scan_finished_at=finished,
        crawler=CrawlerInfo(name="shroodler-py", version=__version__, mode="ingest"),
        pages=[],
        findings=_dedupe_findings(findings),
        js_endpoints=[],
        stats=CrawlStats(
            pages_crawled=0,
            requests=0,
            elapsed_ms=int((monotonic() - t0) * 1000),
        ),
    )
