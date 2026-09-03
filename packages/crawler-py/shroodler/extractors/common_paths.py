from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from urllib.parse import urljoin

from shroodler.extractors.secrets import scan_text
from shroodler.models import Finding, Page
from shroodler.modes.static import FetchResult, StaticFetcher
from shroodler.urls import canonical_key, query_param_names


def wordlists_dir() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "packages" / "secret-patterns" / "wordlists"
        if candidate.is_dir():
            return candidate
        alt = parent / "secret-patterns" / "wordlists"
        if alt.is_dir():
            return alt
    raise FileNotFoundError("secret-patterns/wordlists not found")


def _parse_wordlist(text: str) -> list[str]:
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("/"):
            line = "/" + line
        lines.append(line)
    return lines


@lru_cache(maxsize=1)
def load_paths() -> list[str]:
    seen: set[str] = set()
    lines: list[str] = []
    for path in sorted(wordlists_dir().glob("*.txt")):
        for line in _parse_wordlist(path.read_text(encoding="utf-8")):
            if line in seen:
                continue
            seen.add(line)
            lines.append(line)
    return lines


def probe_paths(
    origin: str,
    fetcher: StaticFetcher,
    already: set[str],
) -> tuple[list[Page], list[Finding]]:
    pages: list[Page] = []
    findings: list[Finding] = []
    for path in load_paths():
        url = urljoin(origin.rstrip("/") + "/", path.lstrip("/"))
        # urljoin("http://h:1/", ".git/config") can drop the dot path incorrectly.
        url = origin.rstrip("/") + path
        key = canonical_key(url)
        if key in already:
            continue
        result: FetchResult = fetcher.fetch(url)
        if result.status_code != 200:
            continue
        already.add(key)
        pages.append(
            Page(
                url=url,
                status_code=200,
                params=query_param_names(url),
            )
        )
        findings.append(
            Finding(
                id="exposed-file",
                severity="high",
                category="exposed-file",
                url=url,
                description=f"Common path {path} is reachable",
                evidence=path,
            )
        )
        findings.extend(scan_text(result.text, url))
    return pages, findings
