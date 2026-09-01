from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from shroodler.suppress import filter_findings
from shroodler.suppress import path_of as _path


@dataclass
class DiffOutcome:
    errors: list[str] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)

    def failing(self) -> list[str]:
        return self.errors


def finding_key(item: dict) -> tuple[str, str]:
    return (item.get("id", ""), _path(item.get("url", "")))


def diff_outcome(
    actual: dict,
    expected: dict,
    *,
    pages_only: bool = False,
    gate: bool = False,
    suppressions: list[dict] | None = None,
) -> DiffOutcome:
    out = DiffOutcome()
    actual_paths = {_path(p["url"]) for p in actual.get("pages", [])}

    if not gate:
        for path in expected.get("expected_pages", []):
            if path not in actual_paths:
                out.errors.append(f"missing page {path}")

    if pages_only:
        return out

    rules = suppressions or []
    visible = filter_findings(actual.get("findings", []), rules)
    actual_findings = {finding_key(f) for f in visible}
    expected_keys = {finding_key(exp) for exp in expected.get("expected_findings", [])}

    if not gate:
        for exp in expected.get("expected_findings", []):
            key = finding_key(exp)
            if key not in actual_findings:
                out.errors.append(f"missing finding {key[0]} at {key[1]}")
    else:
        for exp in expected.get("expected_findings", []):
            key = finding_key(exp)
            if key not in actual_findings:
                out.resolved.append(f"resolved {key[0]} at {key[1]}")

    for nf in expected.get("expected_not_found", []):
        key = finding_key(nf)
        if key in actual_findings:
            out.errors.append(f"unexpected finding {key[0]} at {key[1]}")

    if gate:
        for f in visible:
            key = finding_key(f)
            if key not in expected_keys:
                out.errors.append(f"new finding {key[0]} at {key[1]}")
        return out

    expected_forms = expected.get("expected_forms", {})
    pages_by_path = {}
    for page in actual.get("pages", []):
        pages_by_path[_path(page["url"])] = page
    for path, field_names in expected_forms.items():
        page = pages_by_path.get(path)
        if page is None:
            out.errors.append(f"missing page for forms {path}")
            continue
        actual_fields: set[str] = set()
        for form in page.get("forms", []):
            for fld in form.get("fields", []):
                actual_fields.add(fld.get("name", ""))
        for name in field_names:
            if name not in actual_fields:
                out.errors.append(f"missing form field {name} on {path}")

    return out


def diff_documents(
    actual: dict,
    expected: dict,
    *,
    pages_only: bool = False,
    gate: bool = False,
    suppressions: list[dict] | None = None,
) -> list[str]:
    return diff_outcome(
        actual,
        expected,
        pages_only=pages_only,
        gate=gate,
        suppressions=suppressions,
    ).errors


def load_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
