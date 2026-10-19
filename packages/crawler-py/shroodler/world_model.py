"""A first inferred model of the target application.

A scanner sees a flat list of endpoints. A human pentester sees an application:
objects of some kind, addressed by ids, that *ought* to belong to someone -- and
most real bugs are violations of those "ought"s (an order you can read that is
not yours, a record you can edit that you do not own). This module takes the
first step toward that understanding by reading what the crawl already recorded
on :class:`~shroodler.program.ProgramState` -- endpoint patterns, the object ids
seen in responses, the HTTP methods observed -- and inferring:

* **Entities**: object-addressed resources (``/api/orders/{id}`` -> ``orders``),
  with the id scheme in use and whether the surface is mutable.
* **Ownership invariants**: the properties that, if false, are bugs -- "an
  ``orders`` object addressed by id should be restricted to its owner" -- each
  with a concrete test hint (authz-diff / IDOR on the pattern).

It is deliberately conservative and purely derived: it issues no requests and
invents nothing the state does not already support. The inferred model is
surfaced to the planner as an ``APP MODEL`` context block so the agent reasons
about invariant violations, not just raw endpoints. It is a scaffold for the
larger world-model goal, not the finished thing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from shroodler.program import ProgramState, url_to_pattern

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_INT_RE = re.compile(r"^[0-9]{1,18}$")
_ID_SEG = "{id}"
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_MAX_ENTITIES = 40


@dataclass
class Entity:
    """An object-addressed resource inferred from the crawl surface."""

    name: str
    pattern: str
    id_scheme: str  # sequential-integer | uuid | mixed | unknown
    known_ids: int
    methods: list[str] = field(default_factory=list)

    @property
    def mutable(self) -> bool:
        return any(m.upper() not in _READ_METHODS for m in self.methods)


@dataclass
class Invariant:
    """A property whose violation is a bug, with how to test it."""

    kind: str  # "ownership"
    entity: str
    statement: str
    test_hint: str


@dataclass
class WorldModel:
    entities: list[Entity] = field(default_factory=list)
    invariants: list[Invariant] = field(default_factory=list)


def _entity_name(pattern: str) -> str:
    """The resource word for a pattern: the last non-id path segment."""
    segments = [s for s in pattern.split("/") if s and s != _ID_SEG]
    if not segments:
        return "resource"
    name = segments[-1]
    # Strip a file extension if the last segment is a document, not a collection.
    return name.split(".", 1)[0] or "resource"


def _id_scheme(ids: list[str]) -> str:
    if not ids:
        return "unknown"
    uuid = sum(1 for v in ids if _UUID_RE.fullmatch(str(v)))
    integer = sum(1 for v in ids if _INT_RE.fullmatch(str(v)))
    if uuid and not integer:
        return "uuid"
    if integer and not uuid:
        return "sequential-integer"
    if uuid and integer:
        return "mixed"
    return "unknown"


def _methods_for(state: ProgramState, pattern: str) -> list[str]:
    seen: list[str] = []
    for url, meta in (state.endpoints or {}).items():
        if url_to_pattern(str(url)) != pattern:
            continue
        method = str((meta or {}).get("method") or "GET").upper() or "GET"
        if method not in seen:
            seen.append(method)
    return seen or ["GET"]


def build_model(state: ProgramState) -> WorldModel:
    """Infer entities and ownership invariants from program state. Never raises."""
    model = WorldModel()
    try:
        patterns: dict[str, int] = {}
        # Object-id buckets are keyed by url_to_pattern already.
        for pattern, ids in (state.object_ids or {}).items():
            if _ID_SEG in str(pattern):
                patterns[str(pattern)] = len(ids or [])
        # Also pick up id-addressed endpoints that returned no ids in-body.
        for url in (state.endpoints or {}):
            pat = url_to_pattern(str(url))
            if _ID_SEG in pat and pat not in patterns:
                patterns[pat] = 0

        for pattern in sorted(patterns):
            ids = [str(v) for v in (state.object_ids or {}).get(pattern, [])]
            entity = Entity(
                name=_entity_name(pattern),
                pattern=pattern,
                id_scheme=_id_scheme(ids),
                known_ids=patterns[pattern],
                methods=_methods_for(state, pattern),
            )
            model.entities.append(entity)

        for entity in model.entities[:_MAX_ENTITIES]:
            verb = "read or modify" if entity.mutable else "read"
            model.invariants.append(
                Invariant(
                    kind="ownership",
                    entity=entity.name,
                    statement=(
                        f"a {entity.name} object addressed by id should be "
                        f"restricted to its owner (a peer identity must not {verb} "
                        "another user's)"
                    ),
                    test_hint=f"authz-diff / idor on {entity.pattern}",
                )
            )
    except Exception:  # noqa: BLE001 - inference must never break the loop
        return WorldModel()
    return model


_MAX_LINES = 12


def summarize_model(state: ProgramState) -> str:
    """Render an APP MODEL block for the planner context, or '' if too thin."""
    try:
        model = build_model(state)
        if not model.entities:
            return ""
        lines = [
            "APP MODEL (inferred from crawl surface; verify, do not assume):",
            "entities (object-addressed resources):",
        ]
        for entity in model.entities[:_MAX_LINES]:
            mut = "mutable" if entity.mutable else "read-only"
            methods = ",".join(entity.methods)
            lines.append(
                f"- {entity.name} [{entity.pattern}] ids={entity.id_scheme}"
                f" known={entity.known_ids} {mut} ({methods})"
            )
        if model.invariants:
            lines.append("invariants to check (a violation is a finding):")
            for inv in model.invariants[:_MAX_LINES]:
                lines.append(f"- {inv.statement} -> {inv.test_hint}")
        return "\n".join(lines)
    except Exception:  # noqa: BLE001
        return ""
