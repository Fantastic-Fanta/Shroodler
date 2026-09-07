"""Plugin/extension loader for extra payload packs, secret rules, and
optional Python page checks.

A plugin is a directory, either with a `plugin.yaml` manifest:

    name: extra
    payloads: [packs/]          # files or dirs of YAML payload packs
    secrets: [rules/secrets.yaml]
    checks: [checks/custom.py]  # trusted Python; must define check(...)

or, without a manifest, a directory of YAML files classified by shape
(a list of `{id, pattern}` is secret rules; anything with a `payloads`
key — or a list of objects that have one — is a payload pack).

Discovery: `--plugin PATH` (repeatable) plus `SHROODLER_PLUGIN_PATH`
(colon-separated). Plugins are trusted local code/config the operator
chose to load, not remote content.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, get_args

import yaml

from shroodler.models import Category, Finding

CheckFn = Callable[..., list[Finding]]

_SECRET_KEYS = {"pattern"}
_PACK_KEYS = {"payloads", "payload"}


@dataclass
class Plugin:
    name: str
    root: Path
    payload_paths: list[Path] = field(default_factory=list)
    secret_rules: list[dict] = field(default_factory=list)
    checks: list[CheckFn] = field(default_factory=list)


def plugin_paths_from_env(extra: Sequence[str] | None = None) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()

    def add(raw: str) -> None:
        p = Path(raw).expanduser().resolve()
        if p in seen:
            return
        seen.add(p)
        paths.append(p)

    for item in extra or []:
        add(item)
    env = os.environ.get("SHROODLER_PLUGIN_PATH") or ""
    for part in env.split(os.pathsep):
        part = part.strip()
        if part:
            add(part)
    return paths


def load_plugins(paths: Sequence[Path]) -> list[Plugin]:
    plugins: list[Plugin] = []
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(f"plugin path does not exist: {path}")
        if path.is_file():
            plugins.append(_load_single_file(path))
            continue
        manifest = path / "plugin.yaml"
        if manifest.is_file():
            plugins.append(_load_manifest(path, manifest))
        else:
            plugins.append(_load_autodiscover(path))
    return plugins


def merge_secret_rules(plugins: Sequence[Plugin]) -> list[dict]:
    rules: list[dict] = []
    for plugin in plugins:
        rules.extend(plugin.secret_rules)
    return rules


def merge_payload_paths(plugins: Sequence[Plugin]) -> list[Path]:
    paths: list[Path] = []
    for plugin in plugins:
        paths.extend(plugin.payload_paths)
    return paths


def merge_checks(plugins: Sequence[Plugin]) -> list[CheckFn]:
    fns: list[CheckFn] = []
    for plugin in plugins:
        fns.extend(plugin.checks)
    return fns


def run_checks(
    checks: Sequence[CheckFn],
    *,
    url: str,
    body: str,
    headers: dict[str, str],
    status_code: int,
) -> list[Finding]:
    findings: list[Finding] = []
    for fn in checks:
        raw = fn(url=url, body=body, headers=headers, status_code=status_code)
        if not raw:
            continue
        for item in raw:
            findings.append(_as_finding(item, url))
    return findings


def _load_manifest(root: Path, manifest: Path) -> Plugin:
    data = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{manifest} must be a mapping")
    name = str(data.get("name") or root.name)
    plugin = Plugin(name=name, root=root)
    for rel in _as_list(data.get("payloads")):
        plugin.payload_paths.extend(_expand_yaml(root / rel))
    for rel in _as_list(data.get("secrets")):
        plugin.secret_rules.extend(_load_secret_file(root / rel))
    for rel in _as_list(data.get("checks")):
        plugin.checks.append(_load_check_module(root / rel))
    return plugin


def _load_autodiscover(root: Path) -> Plugin:
    plugin = Plugin(name=root.name, root=root)
    for path in sorted(root.rglob("*.yaml")):
        if path.name == "plugin.yaml":
            continue
        kind = _classify_yaml(path)
        if kind == "secrets":
            plugin.secret_rules.extend(_load_secret_file(path))
        elif kind == "payloads":
            plugin.payload_paths.append(path)
    for path in sorted(root.rglob("*.py")):
        if path.name.startswith("_"):
            continue
        plugin.checks.append(_load_check_module(path))
    return plugin


def _load_single_file(path: Path) -> Plugin:
    plugin = Plugin(name=path.stem, root=path.parent)
    if path.suffix == ".py":
        plugin.checks.append(_load_check_module(path))
        return plugin
    kind = _classify_yaml(path)
    if kind == "secrets":
        plugin.secret_rules.extend(_load_secret_file(path))
    else:
        plugin.payload_paths.append(path)
    return plugin


def _classify_yaml(path: Path) -> str:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    samples: list[dict] = []
    if isinstance(loaded, list):
        samples = [x for x in loaded if isinstance(x, dict)]
    elif isinstance(loaded, dict):
        samples = [loaded]
    if samples and all(set(s) & _SECRET_KEYS and not (set(s) & _PACK_KEYS) for s in samples):
        return "secrets"
    return "payloads"


def _load_secret_file(path: Path) -> list[dict]:
    if path.is_dir():
        rules: list[dict] = []
        for child in sorted(path.glob("*.yaml")):
            rules.extend(_load_secret_file(child))
        return rules
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if isinstance(loaded, dict):
        loaded = [loaded]
    if not isinstance(loaded, list):
        raise ValueError(f"{path} is not a secret-rule list")
    return [r for r in loaded if isinstance(r, dict) and r.get("id") and r.get("pattern")]


def _expand_yaml(path: Path) -> list[Path]:
    if path.is_dir():
        return sorted(path.glob("*.yaml"))
    return [path]


def _load_check_module(path: Path) -> CheckFn:
    if not path.is_file():
        raise FileNotFoundError(f"plugin check module not found: {path}")
    mod_name = f"shroodler_plugin_{path.stem}_{abs(hash(path))}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot import plugin check {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    spec.loader.exec_module(module)
    fn = getattr(module, "check", None)
    if not callable(fn):
        raise ValueError(f"{path} must define a callable check(...)")
    return fn


def _as_finding(item: Any, fallback_url: str) -> Finding:
    if isinstance(item, Finding):
        return item
    if not isinstance(item, dict):
        raise ValueError("plugin check() must return Finding objects or dicts")
    severity = str(item.get("severity") or "info")
    if severity not in {"info", "low", "medium", "high", "critical"}:
        severity = "info"
    category = str(item.get("category") or "scan-note")
    # Unknown categories fall back rather than crashing crawl validation.
    if category not in get_args(Category):
        category = "scan-note"
    return Finding(
        id=str(item.get("id") or "plugin-check"),
        severity=severity,  # type: ignore[arg-type]
        category=category,  # type: ignore[arg-type]
        url=str(item.get("url") or fallback_url),
        description=str(item.get("description") or item.get("id") or "plugin check"),
        evidence=item.get("evidence"),
    )


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return []
