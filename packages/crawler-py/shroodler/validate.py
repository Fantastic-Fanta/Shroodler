from __future__ import annotations

import json
from pathlib import Path

import jsonschema


def schema_path() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "schema" / "finding.schema.json"
        if candidate.exists():
            return candidate
    raise FileNotFoundError("schema/finding.schema.json not found")


def schema() -> dict:
    return json.loads(schema_path().read_text(encoding="utf-8"))


def validate_crawl(doc: dict) -> None:
    jsonschema.validate(instance=doc, schema=schema())
