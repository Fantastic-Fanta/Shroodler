"""Program scope: include/exclude host patterns for crawl and probe queues."""

from __future__ import annotations

import json
from fnmatch import fnmatch
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from shroodler.program import program_dir


def scope_path(slug: str) -> Path:
    return program_dir(slug) / "scope.json"


def load_scope(slug: str, path: str | Path | None = None) -> dict[str, Any]:
    target = Path(path) if path else scope_path(slug)
    if not target.is_file():
        return {}
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    include = [str(item) for item in (data.get("include") or []) if str(item)]
    exclude = [str(item) for item in (data.get("exclude") or []) if str(item)]
    allow = data.get("allow_subdomains")
    return {
        "include": include,
        "exclude": exclude,
        "allow_subdomains": True if allow is None else bool(allow),
    }


def save_scope(slug: str, scope: dict[str, Any]) -> Path:
    path = scope_path(slug)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "include": list(scope.get("include") or []),
        "exclude": list(scope.get("exclude") or []),
        "allow_subdomains": bool(scope.get("allow_subdomains", True)),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def _hostname(url: str) -> str:
    try:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
    except Exception:  # noqa: BLE001
        return ""
    return host


def _host_matches(host: str, pattern: str, *, allow_subdomains: bool) -> bool:
    host = (host or "").lower().rstrip(".")
    pat = (pattern or "").lower().rstrip(".")
    if not host or not pat:
        return False
    if "*" in pat:
        if pat.startswith("*."):
            suffix = pat[1:]  # .example.com
            apex = pat[2:]
            return host == apex or host.endswith(suffix) or fnmatch(host, pat)
        return fnmatch(host, pat)
    if host == pat:
        return True
    if allow_subdomains and host.endswith("." + pat):
        return True
    return False


def in_scope(url: str, scope: dict | None) -> bool:
    """Return True when `url` is allowed. Missing/empty scope means everything."""
    if not scope:
        return True
    include = [str(p) for p in (scope.get("include") or []) if str(p)]
    exclude = [str(p) for p in (scope.get("exclude") or []) if str(p)]
    allow = bool(scope.get("allow_subdomains", True))
    host = _hostname(url)
    if not host:
        return True
    if any(_host_matches(host, pat, allow_subdomains=allow) for pat in exclude):
        return False
    if not include:
        return True
    return any(_host_matches(host, pat, allow_subdomains=allow) for pat in include)
