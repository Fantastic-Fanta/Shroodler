"""Code-attributed findings: map a crawled URL to the source file/line
that most plausibly defines that route, and the commit that most
recently touched it -- "this SQLi was introduced by the change to
routes/export.py:44" instead of a flat finding list bridging only as far
as a URL.

This is heuristic, not a real router/AST analysis: it greps source files
for a route-registration line that mentions the URL's path, using
patterns common to Flask/FastAPI/Bottle, Express-style JS/TS, and
Django. Multi-framework, best-effort, and openly so -- most DAST tools
stop at the URL specifically because bridging URL to source is
framework-specific; this doesn't try to be exhaustive, it tries to be
useful often enough to be worth the (cheap) attempt, and says plainly
when it can't attribute something rather than guessing.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

_SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".java"}
_SKIP_DIR_NAMES = {
    "node_modules",
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
}
# Bound the one-time file walk: a `--gate` run on a large monorepo with
# many new findings would otherwise re-walk and re-read the entire tree
# once PER FINDING with no cap at all -- a routine CI security gate has
# no business taking minutes because of this best-effort heuristic. Files
# above the size cap are skipped (a generated/vendored file that huge is
# unlikely to be a hand-written route registration anyway); the file
# count cap stops the walk itself early on a pathologically large tree.
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_FILES_SCANNED = 20_000
# Aggregate cap across every file a SourceIndex holds in memory at once --
# the per-file and file-count caps above don't bound the total, and many
# files each just under the per-file cap could otherwise add up to
# multiple GB resident for a "best-effort" CI heuristic.
_MAX_TOTAL_INDEX_BYTES = 200 * 1024 * 1024

# A route-registration line generally has BOTH an HTTP-verb-ish call name
# (route/get/post/put/patch/delete/path/url) AND the path string itself
# on the same line -- checking for that combination (rather than just
# "does this line contain the path substring") cuts down on matching an
# unrelated string literal that happens to contain the same characters.
_ROUTE_KEYWORD_RE = re.compile(r"\b(route|get|post|put|patch|delete|path|url)\b", re.IGNORECASE)


@dataclass(frozen=True)
class SourceLocation:
    file: str  # relative to source_root
    line: int
    snippet: str


@dataclass(frozen=True)
class BlameInfo:
    commit: str
    author: str
    date: str


def _iter_source_files(source_root: Path):
    scanned = 0
    for path in source_root.rglob("*"):
        if scanned >= _MAX_FILES_SCANNED:
            return
        if not path.is_file():
            continue
        if path.suffix not in _SOURCE_EXTENSIONS:
            continue
        if any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        scanned += 1
        yield path


class SourceIndex:
    """A one-time read of every candidate source file under `source_root`,
    built once and reused across every finding attributed in a single run
    -- `attribute_finding`/`find_route_source` used to re-walk and
    re-read the entire tree from scratch for every finding independently,
    which is quadratic-ish work with no shared cache on a `--gate` run
    with many new findings against a large repo.
    """

    def __init__(self, source_root: Path) -> None:
        self.source_root = source_root
        self._files: list[tuple[Path, list[str]]] | None = None

    def _load(self) -> list[tuple[Path, list[str]]]:
        if self._files is None:
            loaded = []
            total_bytes = 0
            for path in _iter_source_files(self.source_root):
                if total_bytes >= _MAX_TOTAL_INDEX_BYTES:
                    # The per-file (_MAX_FILE_BYTES) and file-count
                    # (_MAX_FILES_SCANNED) caps don't bound the AGGREGATE
                    # memory this index holds -- many files each just
                    # under the per-file cap can still add up to a
                    # multi-GB resident index for what's supposed to be
                    # a cheap best-effort heuristic. Stop reading further
                    # files once the aggregate budget is spent; whatever
                    # was already indexed is still searched.
                    break
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                total_bytes += len(text.encode("utf-8", errors="ignore"))
                loaded.append((path, text.splitlines()))
            self._files = loaded
        return self._files

    def find(self, url_path: str) -> SourceLocation | None:
        candidates = _path_candidates(url_path)
        for path, lines in self._load():
            for lineno, line in enumerate(lines, start=1):
                if not _ROUTE_KEYWORD_RE.search(line):
                    continue
                for candidate in candidates:
                    if candidate and candidate in line:
                        return SourceLocation(
                            file=str(path.relative_to(self.source_root)),
                            line=lineno,
                            snippet=line.strip()[:200],
                        )
        return None


def find_route_source(source_root: Path, url_path: str) -> SourceLocation | None:
    """Best-effort search for the source line that registers `url_path`
    as a route. Returns the first match found (files walked in OS
    directory order, which isn't guaranteed stable across filesystems --
    fine for a best-effort heuristic, not a deterministic ranking).
    A path with a numeric-looking segment also tries the same search
    with that segment replaced by a route-parameter placeholder pattern,
    since `/users/42` in a crawl almost always maps to `/users/<id>` (or
    `:id`, `{id}`, `[id]`) in source, not the literal digits.

    Convenience wrapper around a throwaway `SourceIndex` for a single
    lookup -- attributing many findings in one run should build one
    `SourceIndex` and call `.find()` repeatedly instead (see
    `attribute_findings`).
    """
    return SourceIndex(source_root).find(url_path)


def _path_candidates(url_path: str) -> list[str]:
    segments = [s for s in url_path.split("/") if s]
    out = [url_path]
    if not segments:
        return out
    # Replace each numeric segment, one at a time, with the common
    # parameter-placeholder spellings across frameworks; a URL usually
    # only has one dynamic segment so this covers the common case
    # without exploding into every combination for multi-parameter URLs.
    for i, seg in enumerate(segments):
        if not seg.isdigit():
            continue
        for placeholder in ("<id>", ":id", "{id}", "[id]", "<int:id>"):
            replaced = list(segments)
            replaced[i] = placeholder
            out.append("/" + "/".join(replaced))
    return out


def blame(source_root: Path, location: SourceLocation) -> BlameInfo | None:
    """Which commit most recently touched this line -- `git log -1` on
    the line range, not a full `git blame` parse, since we only want the
    LATEST change, not the line's full history."""
    try:
        result = subprocess.run(
            [
                "git",
                "log",
                "-1",
                "--format=%H%x1f%an%x1f%ad",
                "--date=short",
                "-L",
                f"{location.line},{location.line}:{location.file}",
            ],
            cwd=source_root,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    # `git log -L` prints the commit header line(s) first, then a diff;
    # the first line we emitted via --format is what we want.
    first_line = result.stdout.strip().splitlines()[0]
    parts = first_line.split("\x1f")
    if len(parts) != 3:
        return None
    commit, author, date = parts
    return BlameInfo(commit=commit[:12], author=author, date=date)


def _attribute_from_location(source_root: Path, location: SourceLocation | None) -> dict | None:
    if location is None:
        return None
    result = {"file": location.file, "line": location.line, "snippet": location.snippet}
    info = blame(source_root, location)
    if info is not None:
        result["commit"] = info.commit
        result["author"] = info.author
        result["date"] = info.date
    return result


def attribute_finding(source_root: Path, url: str) -> dict | None:
    """High-level entry point for a SINGLE lookup: resolve a finding's
    URL to a source location and (if this is a git repo) the commit that
    last touched it. Returns None if no plausible route source was
    found -- callers should treat that as "couldn't attribute this one",
    not an error. Attributing several findings in one run should use
    `attribute_findings` instead, which builds one `SourceIndex` shared
    across all of them rather than re-walking the tree per finding.
    """
    url_path = urlparse(url).path or "/"
    location = find_route_source(source_root, url_path)
    return _attribute_from_location(source_root, location)


def attribute_findings(source_root: Path, urls: list[str]) -> dict[str, dict]:
    """Batch form of `attribute_finding`: builds one `SourceIndex` and
    reuses it for every URL, instead of re-walking (and re-reading every
    file in) `source_root` once per URL. Returns a dict keyed by the
    URLs that were successfully attributed; a URL with no plausible
    route source is simply absent from the result, same convention as
    `attribute_finding` returning None.
    """
    index = SourceIndex(source_root)
    out: dict[str, dict] = {}
    for url in urls:
        url_path = urlparse(url).path or "/"
        attribution = _attribute_from_location(source_root, index.find(url_path))
        if attribution is not None:
            out[url] = attribution
    return out
