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
    for path in source_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in _SOURCE_EXTENSIONS:
            continue
        if any(part in _SKIP_DIR_NAMES for part in path.parts):
            continue
        yield path


def find_route_source(source_root: Path, url_path: str) -> SourceLocation | None:
    """Best-effort search for the source line that registers `url_path`
    as a route. Returns the first match found (files walked in OS
    directory order, which isn't guaranteed stable across filesystems --
    fine for a best-effort heuristic, not a deterministic ranking).
    A path with a numeric-looking segment also tries the same search
    with that segment replaced by a route-parameter placeholder pattern,
    since `/users/42` in a crawl almost always maps to `/users/<id>` (or
    `:id`, `{id}`, `[id]`) in source, not the literal digits.
    """
    candidates = _path_candidates(url_path)
    for path in _iter_source_files(source_root):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, start=1):
            if not _ROUTE_KEYWORD_RE.search(line):
                continue
            for candidate in candidates:
                if candidate and candidate in line:
                    return SourceLocation(
                        file=str(path.relative_to(source_root)),
                        line=lineno,
                        snippet=line.strip()[:200],
                    )
    return None


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


def attribute_finding(source_root: Path, url: str) -> dict | None:
    """High-level entry point: resolve a finding's URL to a source
    location and (if this is a git repo) the commit that last touched
    it. Returns None if no plausible route source was found -- callers
    should treat that as "couldn't attribute this one", not an error."""
    url_path = urlparse(url).path or "/"
    location = find_route_source(source_root, url_path)
    if location is None:
        return None
    result = {"file": location.file, "line": location.line, "snippet": location.snippet}
    info = blame(source_root, location)
    if info is not None:
        result["commit"] = info.commit
        result["author"] = info.author
        result["date"] = info.date
    return result
