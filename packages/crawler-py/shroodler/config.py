from __future__ import annotations

from pathlib import Path

import yaml


def load_rc() -> dict:
    for candidate in (Path.cwd() / ".shroodlerrc", Path.home() / ".shroodlerrc"):
        if candidate.is_file():
            data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
            if isinstance(data, dict):
                return data
    return {}
