"""Persistent (endpoint, probe) memory for the opt-in LLM agent loop.

Remembers which parameter/probe combinations have already been tried so
later runs can skip fruitless pairs and bias toward productive probe types.
"""

from __future__ import annotations

import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}$"
)
_NUMERIC_SEG_RE = re.compile(r"^\d{3,}$")
_BASE62_SEG_RE = re.compile(r"^[A-Za-z0-9]{16,}$")
_LETTER_RE = re.compile(r"[A-Za-z]")
_DIGIT_RE = re.compile(r"\d")
_MEMORY_PATH = ":memory:"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _param_key(param_name: str | None) -> str:
    """SQLite UNIQUE treats NULLs as distinct; store None as empty string."""
    if param_name is None:
        return ""
    return str(param_name)


def _normalise_segment(seg: str) -> str:
    if _UUID_RE.fullmatch(seg):
        return "{uuid}"
    if _NUMERIC_SEG_RE.fullmatch(seg):
        return "{id}"
    if (
        _BASE62_SEG_RE.fullmatch(seg)
        and _LETTER_RE.search(seg)
        and _DIGIT_RE.search(seg)
    ):
        return "{token}"
    return seg


def normalise_url(url: str) -> str:
    """Replace IDs, UUIDs, tokens, and query values with placeholders."""
    if not url:
        return url
    try:
        parsed = urlparse(url)
    except ValueError:
        return url
    raw_path = parsed.path or ""
    parts = [
        _normalise_segment(seg) if seg else seg for seg in raw_path.split("/")
    ]
    new_path = "/".join(parts)
    new_query = ""
    if parsed.query:
        bits: list[str] = []
        for part in parsed.query.split("&"):
            if not part:
                continue
            if "=" in part:
                key, _, _val = part.partition("=")
                bits.append(f"{key}={{val}}")
            else:
                bits.append(part)
        new_query = "&".join(bits)
    return urlunparse(
        parsed._replace(path=new_path, query=new_query, fragment="")
    )


@dataclass
class ProbeRecord:
    endpoint_pattern: str
    probe_type: str
    param_name: str | None
    result: str
    tried_at: str
    finding_id: str | None = None


class ProbeMemory:
    """SQLite-backed store of tried (endpoint, probe, param) triples."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        if str(db_path) != _MEMORY_PATH:
            parent = Path(db_path).parent
            if str(parent) not in {"", "."}:
                parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            db_path,
            check_same_thread=False,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS probe_records (
                endpoint_pattern TEXT NOT NULL,
                probe_type TEXT NOT NULL,
                param_name TEXT NOT NULL DEFAULT '',
                result TEXT NOT NULL,
                tried_at TEXT NOT NULL,
                finding_id TEXT,
                UNIQUE (endpoint_pattern, probe_type, param_name)
            )
            """
        )
        self._conn.commit()

    def record(self, rec: ProbeRecord) -> None:
        """Insert a record. Duplicates of the unique triple are ignored."""
        tried_at = rec.tried_at or _now()
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO probe_records (
                    endpoint_pattern, probe_type, param_name,
                    result, tried_at, finding_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    rec.endpoint_pattern,
                    rec.probe_type,
                    _param_key(rec.param_name),
                    rec.result,
                    tried_at,
                    rec.finding_id,
                ),
            )
            self._conn.commit()

    def already_tried(
        self,
        endpoint_pattern: str,
        probe_type: str,
        param_name: str | None = None,
    ) -> bool:
        """True when this triple finished with finding or no-finding."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT 1 FROM probe_records
                WHERE endpoint_pattern = ?
                  AND probe_type = ?
                  AND param_name = ?
                  AND result IN ('finding', 'no-finding')
                LIMIT 1
                """,
                (endpoint_pattern, probe_type, _param_key(param_name)),
            ).fetchone()
        return row is not None

    def get_productive_probes(self) -> list[str]:
        """Probe types with at least one finding, most frequent first."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT probe_type, COUNT(*) AS n
                FROM probe_records
                WHERE result = 'finding'
                GROUP BY probe_type
                ORDER BY n DESC, probe_type ASC
                """
            ).fetchall()
        return [str(row[0]) for row in rows]

    def endpoint_patterns(self) -> list[str]:
        """Distinct normalised endpoint patterns seen so far."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT endpoint_pattern FROM probe_records"
            ).fetchall()
        return [str(row[0]) for row in rows]

    def get_barren_probes(self) -> list[str]:
        """Probe types tried on >= 5 distinct endpoints with zero findings."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT probe_type
                FROM probe_records
                GROUP BY probe_type
                HAVING COUNT(DISTINCT endpoint_pattern) >= 5
                   AND SUM(CASE WHEN result = 'finding' THEN 1 ELSE 0 END) = 0
                ORDER BY probe_type ASC
                """
            ).fetchall()
        return [str(row[0]) for row in rows]

    def summary(self) -> str:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) FROM (
                    SELECT 1 FROM probe_records
                    GROUP BY endpoint_pattern, probe_type
                )
                """
            ).fetchone()
        n = int(row[0] if row else 0)
        productive = self.get_productive_probes()
        barren = self.get_barren_probes()
        return (
            f"tried {n} (endpoint, probe) pairs; "
            f"productive: {productive}; barren: {barren}"
        )

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None
