from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from time import monotonic
from urllib.parse import urlparse

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


PATH_WORDLISTS = ("common-paths.txt", "source-control.txt", "well-known.txt")


def _parse_lines(text: str, *, as_paths: bool) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if as_paths and not line.startswith("/"):
            line = "/" + line
        lines.append(line)
    return lines


@lru_cache(maxsize=1)
def load_paths() -> list[str]:
    seen: set[str] = set()
    lines: list[str] = []
    wordlists = wordlists_dir()
    for name in PATH_WORDLISTS:
        path = wordlists / name
        if not path.is_file():
            continue
        for line in _parse_lines(path.read_text(encoding="utf-8"), as_paths=True):
            if line in seen:
                continue
            seen.add(line)
            lines.append(line)
    return lines


@lru_cache(maxsize=1)
def load_backup_suffixes() -> list[str]:
    return _parse_lines(
        (wordlists_dir() / "backup-suffixes.txt").read_text(encoding="utf-8"),
        as_paths=False,
    )


@lru_cache(maxsize=1)
def load_backup_interesting() -> frozenset[str]:
    names = _parse_lines(
        (wordlists_dir() / "backup-interesting.txt").read_text(encoding="utf-8"),
        as_paths=False,
    )
    return frozenset(n.lower().lstrip("/") for n in names)


def _path_of(url_or_path: str) -> str:
    if "://" in url_or_path:
        path = urlparse(url_or_path).path or "/"
    else:
        path = url_or_path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return path


def _segment(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1].lower()


def is_mutation_base(path: str, *, wordlist: set[str] | None = None) -> bool:
    path = _path_of(path)
    if path == "/":
        return False
    wl = wordlist if wordlist is not None else set(load_paths())
    if path in wl:
        return True
    name = _segment(path)
    if not name:
        return False
    interesting = load_backup_interesting()
    stem = name.split(".")[0]
    return name in interesting or stem in interesting


def mutation_paths(discovered: list[str]) -> list[str]:
    """Append backup suffixes to a small set of discovered interesting paths."""
    suffixes = load_backup_suffixes()
    wordlist = set(load_paths())
    bases: list[str] = []
    seen_bases: set[str] = set()
    for raw in discovered:
        path = _path_of(raw)
        if path in seen_bases or not is_mutation_base(path, wordlist=wordlist):
            continue
        seen_bases.add(path)
        bases.append(path)
    out: list[str] = []
    seen_out: set[str] = set()
    for base in bases:
        for suffix in suffixes:
            mutated = base + suffix
            if mutated == base or mutated in seen_out or mutated in seen_bases:
                continue
            seen_out.add(mutated)
            out.append(mutated)
    return out


def _record_hit(
    url: str,
    path: str,
    already: set[str],
    pages: list[Page],
    findings: list[Finding],
    *,
    description: str,
) -> None:
    already.add(canonical_key(url))
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
            description=description,
            evidence=path,
        )
    )


def probe_paths(
    origin: str,
    fetcher: StaticFetcher,
    already: set[str],
    remaining: int | None = None,
    deadline: float | None = None,
) -> tuple[list[Page], list[Finding]]:
    pages: list[Page] = []
    findings: list[Finding] = []
    for path in load_paths():
        if remaining is not None and len(pages) >= remaining:
            break
        if deadline is not None and monotonic() >= deadline:
            break
        url = origin.rstrip("/") + path
        key = canonical_key(url)
        if key in already:
            continue
        result: FetchResult = fetcher.fetch(url)
        if result.status_code != 200:
            continue
        _record_hit(
            url,
            path,
            already,
            pages,
            findings,
            description=f"Common path {path} is reachable",
        )
        findings.extend(scan_text(result.text, url))
    return pages, findings


def probe_mutations(
    origin: str,
    fetcher: StaticFetcher,
    already: set[str],
    discovered: list[str],
) -> tuple[list[Page], list[Finding]]:
    pages: list[Page] = []
    findings: list[Finding] = []
    for path in mutation_paths(discovered):
        url = origin.rstrip("/") + path
        key = canonical_key(url)
        if key in already:
            continue
        result: FetchResult = fetcher.fetch(url)
        if result.status_code != 200:
            continue
        _record_hit(
            url,
            path,
            already,
            pages,
            findings,
            description=f"Backup-name mutation {path} is reachable",
        )
        findings.extend(scan_text(result.text, url))
    return pages, findings
