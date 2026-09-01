from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse


def _path(url: str) -> str:
    p = urlparse(url)
    path = p.path or "/"
    return path


def diff_documents(actual: dict, expected: dict, *, pages_only: bool = False) -> list[str]:
    errors: list[str] = []
    actual_paths = {_path(p["url"]) for p in actual.get("pages", [])}

    for path in expected.get("expected_pages", []):
        if path not in actual_paths:
            errors.append(f"missing page {path}")

    if pages_only:
        return errors

    def finding_key(item: dict) -> tuple[str, str]:
        return (item.get("id", ""), _path(item.get("url", "")))

    actual_findings = {finding_key(f) for f in actual.get("findings", [])}

    for exp in expected.get("expected_findings", []):
        key = (exp.get("id", ""), _path(exp.get("url", "")))
        if key not in actual_findings:
            errors.append(f"missing finding {key[0]} at {key[1]}")

    for nf in expected.get("expected_not_found", []):
        key = (nf.get("id", ""), _path(nf.get("url", "")))
        if key in actual_findings:
            errors.append(f"unexpected finding {key[0]} at {key[1]}")

    expected_forms = expected.get("expected_forms", {})
    pages_by_path = {}
    for page in actual.get("pages", []):
        pages_by_path[_path(page["url"])] = page
    for path, field_names in expected_forms.items():
        page = pages_by_path.get(path)
        if page is None:
            errors.append(f"missing page for forms {path}")
            continue
        actual_fields: set[str] = set()
        for form in page.get("forms", []):
            for field in form.get("fields", []):
                actual_fields.add(field.get("name", ""))
        for name in field_names:
            if name not in actual_fields:
                errors.append(f"missing form field {name} on {path}")

    return errors


def load_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
