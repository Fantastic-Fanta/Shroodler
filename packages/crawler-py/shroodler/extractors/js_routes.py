"""Mine parameterized URL templates out of bundled JS.

`extract_js_endpoints` already catches literal `fetch("/api/x")` strings.
SPA bundles more often keep the *shape* of a write (`/collections/{id}/edit`,
`/users/${userId}`, Express `/:pk`) and fill the id at runtime. Those
templates are the map for a known-object peer-write replay — not a list
of ids to enumerate.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

# Path-looking quoted strings that already contain a `{name}` placeholder.
_BRACE = re.compile(
    r"""(?P<q>['"])(?P<path>(?:https?:)?/[^'"]*\{[A-Za-z_][A-Za-z0-9_]*\}[^'"]*)(?P=q)"""
)
# Template literals: `/collections/${collectionId}/edit`
_DOLLAR = re.compile(
    r"""`(?P<path>(?:https?:)?/[^`]*\$\{[A-Za-z_][A-Za-z0-9_]*\}[^`]*)`"""
)
# Express-style `'/users/:userId/settings'`
_COLON = re.compile(
    r"""(?P<q>['"`])(?P<path>(?:https?:)?/[^'"`]*:[A-Za-z_][A-Za-z0-9_]*[^'"`]*)(?P=q)"""
)
# Django-style `"/items/<int:pk>/"`
_ANGLE = re.compile(
    r"""(?P<q>['"`])(?P<path>(?:https?:)?/[^'"`]*<(?:int:|str:|uuid:)?[A-Za-z_][A-Za-z0-9_]*>[^'"`]*)(?P=q)"""
)

_PARAM_BRACE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_PARAM_DOLLAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_PARAM_COLON = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")
_PARAM_ANGLE = re.compile(r"<(?:int:|str:|uuid:)?([A-Za-z_][A-Za-z0-9_]*)>")

# `:hover` / `http://` / `data:image` are not route params.
_COLON_NOISE = {
    "http",
    "https",
    "ws",
    "wss",
    "mailto",
    "data",
    "javascript",
    "hover",
    "focus",
    "active",
    "visited",
    "nth",
}


def _normalize_template(raw: str) -> str:
    raw = raw.strip()
    raw = _PARAM_DOLLAR.sub(r"{\1}", raw)
    raw = _PARAM_ANGLE.sub(r"{\1}", raw)

    def _colon_to_brace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name.lower() in _COLON_NOISE:
            return match.group(0)
        return "{" + name + "}"

    return _PARAM_COLON.sub(_colon_to_brace, raw)


def _params_of(template: str) -> list[str]:
    seen: list[str] = []
    for name in _PARAM_BRACE.findall(template):
        if name not in seen:
            seen.append(name)
    return seen


def _keep(template: str, params: list[str]) -> bool:
    if not params or not template.startswith(("/", "http://", "https://")):
        return False
    if len(params) > 6:
        return False
    if len(template) > 400:
        return False
    return True


def extract_js_routes(source: str, js_text: str) -> list[dict[str, Any]]:
    """Return unique `{template, params, source}` dicts from JS text."""
    if not js_text:
        return []
    found: list[str] = []
    for pat in (_BRACE, _DOLLAR, _COLON, _ANGLE):
        for match in pat.finditer(js_text):
            found.append(match.group("path"))

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in found:
        template = _normalize_template(raw)
        params = _params_of(template)
        if not _keep(template, params):
            continue
        if template in seen:
            continue
        seen.add(template)
        out.append({"template": template, "params": params, "source": source})
    return out


def extract_js_routes_file(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    routes = extract_js_routes(str(p), p.read_text(encoding="utf-8", errors="replace"))
    return {"source": str(p), "routes": routes}
