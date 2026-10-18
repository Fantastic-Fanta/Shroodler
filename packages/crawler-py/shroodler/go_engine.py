"""Subprocess client for the Go network engine (``shroodler-go``).

A thin seam between the Python agent and the Go crawl/network engine, which
is the sole crawler. The Go ``crawl`` subcommand emits the JSON document shape
(``crawler``, ``pages``, ``edges``, ``findings``, ``js_endpoints``, ``stats``,
``target``, ``scan_started_at``, ``scan_finished_at``) that the rest of the
Python pipeline consumes directly.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_DEFAULT_BINARY = _REPO_ROOT / "packages" / "crawler-go" / "shroodler-go"
_DEFAULT_TIMEOUT = 300.0


class GoEngineError(RuntimeError):
    """The Go engine binary is missing, failed, or returned unparseable output."""


def find_go_binary() -> Path:
    """Locate the ``shroodler-go`` binary.

    Honors ``SHROODLER_GO_BIN`` (an explicit path), else the in-repo build.
    Raises ``GoEngineError`` if neither exists.
    """
    override = os.environ.get("SHROODLER_GO_BIN")
    candidate = Path(override) if override else _DEFAULT_BINARY
    if not candidate.is_file():
        raise GoEngineError(
            f"shroodler-go binary not found at {candidate}. "
            "Build it (go build ./cmd/shroodler) or set SHROODLER_GO_BIN."
        )
    return candidate


def available() -> bool:
    """True if the Go engine binary can be located (never raises)."""
    try:
        find_go_binary()
    except GoEngineError:
        return False
    return True


def _crawl_args(
    target: str,
    *,
    mode: str | None,
    max_pages: int | None,
    depth: int | None,
    max_time: float | None,
    ignore_robots: bool,
    no_sitemap: bool,
    allow_external: bool,
    check_rate_limit: bool,
    headers: list[str] | None,
    user_agent: str | None,
    cookies: list[str] | None,
    cookie_jar: str | None,
    storage_state: str | None,
    login_recipe: str | None,
    proxy: str | None,
    seeds: list[str] | None,
    output: str,
) -> list[str]:
    """Build the ``shroodler-go crawl`` argument vector (pure, for testing).

    ``headers`` are raw ``"Name: value"`` lines and ``cookies`` raw
    ``"name=value"`` pairs -- the same shapes the CLI accepts and the Go
    binary's repeatable ``--header`` / ``--cookie`` flags expect.
    """
    args = ["crawl", target, "--output", output]
    if mode:
        args += ["--mode", mode]
    if max_pages is not None:
        args += ["--max-pages", str(max_pages)]
    if depth is not None:
        args += ["--depth", str(depth)]
    if max_time is not None:
        args += ["--max-time", str(max_time)]
    if ignore_robots:
        args.append("--ignore-robots")
    if no_sitemap:
        args.append("--no-sitemap")
    if allow_external:
        args.append("--allow-external")
    if check_rate_limit:
        args.append("--check-rate-limit")
    for line in headers or []:
        args += ["--header", line]
    if user_agent:
        args += ["--user-agent", user_agent]
    for cookie in cookies or []:
        args += ["--cookie", cookie]
    if cookie_jar:
        args += ["--cookie-jar", cookie_jar]
    if storage_state:
        args += ["--storage-state", storage_state]
    if login_recipe:
        args += ["--login-recipe", login_recipe]
    if proxy:
        args += ["--proxy", proxy]
    for seed in seeds or []:
        args += ["--seed", seed]
    return args


def crawl(
    target: str,
    *,
    mode: str | None = None,
    max_pages: int | None = None,
    depth: int | None = None,
    max_time: float | None = None,
    ignore_robots: bool = False,
    no_sitemap: bool = False,
    allow_external: bool = False,
    check_rate_limit: bool = False,
    headers: list[str] | None = None,
    user_agent: str | None = None,
    cookies: list[str] | None = None,
    cookie_jar: str | None = None,
    storage_state: str | None = None,
    login_recipe: str | None = None,
    proxy: str | None = None,
    seeds: list[str] | None = None,
    timeout: float | None = None,
    binary: Path | None = None,
) -> dict:
    """Crawl ``target`` with the Go engine and return the result document.

    The returned dict is the Go engine's JSON report, which shares its schema
    with the Python crawler's output. Raises ``GoEngineError`` on any failure.
    """
    bin_path = binary or find_go_binary()
    with tempfile.TemporaryDirectory(prefix="shroodler-go-") as tmp:
        out_path = os.path.join(tmp, "crawl.json")
        args = _crawl_args(
            target,
            mode=mode,
            max_pages=max_pages,
            depth=depth,
            max_time=max_time,
            ignore_robots=ignore_robots,
            no_sitemap=no_sitemap,
            allow_external=allow_external,
            check_rate_limit=check_rate_limit,
            headers=headers,
            user_agent=user_agent,
            cookies=cookies,
            cookie_jar=cookie_jar,
            storage_state=storage_state,
            login_recipe=login_recipe,
            proxy=proxy,
            seeds=seeds,
            output=out_path,
        )
        try:
            proc = subprocess.run(
                [str(bin_path), *args],
                capture_output=True,
                text=True,
                timeout=timeout if timeout is not None else _DEFAULT_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise GoEngineError(f"shroodler-go crawl timed out after {exc.timeout}s") from exc
        except OSError as exc:
            raise GoEngineError(f"could not run shroodler-go: {exc}") from exc
        if proc.returncode != 0:
            raise GoEngineError(
                f"shroodler-go crawl exited {proc.returncode}: "
                f"{(proc.stderr or '').strip()[:500]}"
            )
        try:
            doc = json.loads(Path(out_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise GoEngineError(f"shroodler-go produced no valid JSON report: {exc}") from exc
        return _normalize_doc(doc)


# List-typed top-level fields the crawl schema expects as arrays. Go marshals a
# nil slice to JSON ``null`` rather than ``[]`` (e.g. js_endpoints when a crawl
# finds none), which fails schema validation for callers that validate the raw
# doc (reverify, cmd_crawl, scan_route). Coerce them so every Python consumer
# gets a schema-valid document from the seam.
_DOC_LIST_FIELDS = ("pages", "findings", "js_endpoints", "edges", "xhr_endpoints")


def _normalize_doc(doc: dict) -> dict:
    if isinstance(doc, dict):
        for key in _DOC_LIST_FIELDS:
            if doc.get(key) is None and key in doc:
                doc[key] = []
    return doc
