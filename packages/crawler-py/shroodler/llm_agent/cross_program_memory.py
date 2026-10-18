"""Cross-target pattern learning for the LLM agent.

Where ``engagement_memory`` carries facts forward within one program (the same
target, run after run), this module learns *across* programs: it records, per
engagement, the target's abstracted shape (framework, id scheme, auth style,
JWT alg, WAF vendor, GraphQL presence) alongside the bug classes that were
*confirmed*, then surfaces the correlation to a new, unrelated target that
shares some of that shape -- "targets with id_scheme=sequential-integer had
idor confirmed in 6/8 prior engagements". It is the agent getting better across
engagements the way a senior human does, not re-deriving each target from zero.

Scope isolation is the hard property here, because one client's data must never
leak into another client's run. The design is fail-closed:

* Feature VALUES are accepted only if they are a member of a fixed per-key
  vocabulary (see ``_FEATURE_VOCAB``). A fact value that embeds a URL, hostname,
  IP, parameter, token or any other target-identifying string is not in the
  vocabulary, so it is dropped rather than stored. Unknown-but-harmless values
  (a framework we have not listed) are also dropped; we would rather under-learn
  than ever carry target data across engagements.
* Bug classes come from confirmed-finding ids -- tool-internal labels, never
  target-controlled -- slugified and gate-validated to a short token.
* The only per-engagement key on disk is a one-way ``sha256(slug)[:16]`` digest,
  used solely to deduplicate repeat runs of the same program. It is never
  surfaced in any hint shown to another engagement.

Every public function is wrapped so the learning layer can never break the
agent loop. The store lives at ``~/.shroodler/cross_program/patterns.json`` and
can be redirected with ``config.cross_program_dir`` or
``$SHROODLER_CROSS_PROGRAM_DIR`` (tests and eval runs point it at a temp dir).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from shroodler.util import now_iso

# Fixed, fail-closed vocabulary per feature key. A value that is not listed is
# dropped, never stored -- this is what guarantees no target-identifying string
# (hostname, URL, IP, param, token) can ride across engagements. Expand these
# lists deliberately; do not replace with an open regex.
_FEATURE_VOCAB: dict[str, frozenset[str]] = {
    "framework": frozenset(
        {
            "flask", "django", "fastapi", "tornado", "express", "nextjs", "nuxt",
            "react", "angular", "vue", "svelte", "rails", "sinatra", "laravel",
            "symfony", "spring", "aspnet", "gin", "fiber", "echo", "phoenix",
            "wordpress", "drupal", "joomla", "nodejs", "php", "go", "dotnet",
        }
    ),
    "id_scheme": frozenset({"sequential-integer", "uuid", "opaque-token"}),
    "auth_style": frozenset(
        {"cookie", "session", "jwt", "oauth", "basic", "bearer", "apikey", "sso"}
    ),
    "jwt_alg": frozenset(
        {
            "none", "hs256", "hs384", "hs512", "rs256", "rs384", "rs512",
            "es256", "es384", "es512", "ps256", "ps384", "ps512", "eddsa",
        }
    ),
    "waf_vendor": frozenset(
        {
            "cloudflare", "akamai", "imperva", "incapsula", "awswaf", "aws",
            "modsecurity", "f5", "fortinet", "sucuri", "wordfence", "barracuda",
            "fastly", "present-vendor-unknown",
        }
    ),
    "graphql": frozenset({"endpoint-present", "present"}),
}
_FEATURE_KEYS = tuple(_FEATURE_VOCAB)

# Bug-class labels are our own probe ids (not target-controlled); still gated to
# a short letter-led token so nothing unexpected reaches disk.
_LABEL_RE = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
_SLUG_SUB_RE = re.compile(r"[^a-z0-9]+")

# Variant suffixes collapsed so "xss-reflected"/"xss-stored" group as "xss".
_VARIANT_SUFFIXES = (
    "-reflected",
    "-stored",
    "-blind",
    "-boolean",
    "-time",
    "-error",
    "-based",
    "-oob",
)

_STORE_VERSION = 1
_MAX_ENGAGEMENTS = 500
_MAX_FEATURES_PER_ENGAGEMENT = 12
_MAX_CLASSES_PER_ENGAGEMENT = 40

# Thresholds for surfacing a correlation to a new target.
_MIN_TOTAL_ENGAGEMENTS = 3
_MIN_FEATURE_SUPPORT = 3  # engagements that shared the feature
_MIN_CLASS_HITS = 2  # of those, how many confirmed the class
_MIN_CONFIRM_FRACTION = 0.5
_MAX_HINT_LINES = 8


def _slug(value: Any) -> str:
    """Lowercase, collapse any non-alphanumeric run to a single hyphen, trim."""
    text = str(value or "").strip().lower()
    if not text:
        return ""
    return _SLUG_SUB_RE.sub("-", text).strip("-")[:48]


def _store_dir(config: Any) -> Path:
    override = getattr(config, "cross_program_dir", None) if config is not None else None
    if not override:
        override = os.environ.get("SHROODLER_CROSS_PROGRAM_DIR")
    if override:
        return Path(str(override))
    return Path.home() / ".shroodler" / "cross_program"


def _store_path(config: Any) -> Path:
    return _store_dir(config) / "patterns.json"


def _enabled(config: Any) -> bool:
    if config is None:
        return True
    return bool(getattr(config, "cross_program_learning", True))


def _slug_digest(state: Any) -> str:
    slug = str(getattr(state, "slug", "") or "").strip()
    if not slug:
        return ""
    return hashlib.sha256(slug.encode("utf-8")).hexdigest()[:16]


def _feature_token(key: str, raw: Any) -> str | None:
    """Return ``key=value`` only if the slugified value is in key's vocabulary."""
    vocab = _FEATURE_VOCAB.get(key)
    if not vocab:
        return None
    value = _slug(raw)
    if value in vocab:
        return f"{key}={value}"
    return None


def derive_features(state: Any) -> list[str]:
    """Abstracted ``key=value`` feature tokens for this target, vocab-gated."""
    out: list[str] = []
    seen: set[str] = set()
    try:
        from shroodler.llm_agent.engagement_memory import get_facts

        facts = get_facts(state)
    except Exception:  # noqa: BLE001
        facts = {}
    if not isinstance(facts, dict):
        return out
    for key in _FEATURE_KEYS:
        row = facts.get(key)
        raw = row.get("value") if isinstance(row, dict) else None
        token = _feature_token(key, raw)
        if token and token not in seen:
            seen.add(token)
            out.append(token)
    return out[:_MAX_FEATURES_PER_ENGAGEMENT]


def _bug_class(finding: Any) -> str | None:
    label = _slug(getattr(finding, "id", "") or "")
    if not label:
        return None
    for suffix in _VARIANT_SUFFIXES:
        if label.endswith(suffix) and len(label) > len(suffix):
            label = label[: -len(suffix)]
            break
    return label if _LABEL_RE.fullmatch(label) else None


def derive_bug_classes(state: Any) -> list[str]:
    """Gate-validated bug-class labels from this run's CONFIRMED findings."""
    out: list[str] = []
    seen: set[str] = set()
    for finding in getattr(state, "findings", None) or []:
        if str(getattr(finding, "confidence", "") or "") != "confirmed":
            continue
        label = _bug_class(finding)
        if label and label not in seen:
            seen.add(label)
            out.append(label)
    return out[:_MAX_CLASSES_PER_ENGAGEMENT]


def _load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": _STORE_VERSION, "engagements": {}}
    if not isinstance(data, dict):
        return {"version": _STORE_VERSION, "engagements": {}}
    engagements = data.get("engagements")
    if not isinstance(engagements, dict):
        engagements = {}
    return {"version": _STORE_VERSION, "engagements": engagements}


def _save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _sanitize_row(features: Any, bug_classes: Any) -> dict[str, Any]:
    """Second gate at write time: re-validate every token before it hits disk."""
    feats: list[str] = []
    for token in features or []:
        if not isinstance(token, str) or "=" not in token:
            continue
        key, _, value = token.partition("=")
        if _feature_token(key, value) == token:
            feats.append(token)
    classes = [
        t for t in (bug_classes or []) if isinstance(t, str) and _LABEL_RE.fullmatch(t)
    ]
    return {
        "features": sorted(set(feats))[:_MAX_FEATURES_PER_ENGAGEMENT],
        "bug_classes": sorted(set(classes))[:_MAX_CLASSES_PER_ENGAGEMENT],
        "updated": now_iso(),
    }


def record_engagement(state: Any, config: Any) -> None:
    """Record this run's abstracted shape + confirmed bug classes. Never raises.

    Keyed by a one-way digest of the program slug, so a repeat run of the same
    program replaces its prior contribution instead of inflating the counts.
    """
    try:
        if not _enabled(config):
            return
        digest = _slug_digest(state)
        if not digest:
            return
        features = derive_features(state)
        if not features:
            # Nothing abstract enough to generalise from; skip silently.
            return
        row = _sanitize_row(features, derive_bug_classes(state))
        path = _store_path(config)
        data = _load(path)
        engagements = data["engagements"]
        engagements[digest] = row
        if len(engagements) > _MAX_ENGAGEMENTS:
            oldest = sorted(
                engagements.items(), key=lambda kv: str((kv[1] or {}).get("updated") or "")
            )[0][0]
            if oldest != digest:
                engagements.pop(oldest, None)
        _save(path, data)
    except Exception:  # noqa: BLE001 - learning must never break the loop
        return


def _aggregate(
    engagements: dict[str, Any],
) -> tuple[int, dict[str, dict[str, int]], dict[str, int]]:
    """Return (total, feature -> {bug_class: hits}, feature -> support)."""
    total = 0
    by_feature: dict[str, dict[str, int]] = {}
    support: dict[str, int] = {}
    for row in engagements.values():
        if not isinstance(row, dict):
            continue
        total += 1
        feats = [f for f in (row.get("features") or []) if isinstance(f, str)]
        classes = [c for c in (row.get("bug_classes") or []) if isinstance(c, str)]
        for feat in feats:
            support[feat] = support.get(feat, 0) + 1
            bucket = by_feature.setdefault(feat, {})
            for cls in classes:
                bucket[cls] = bucket.get(cls, 0) + 1
    return total, by_feature, support


def summarize_for(state: Any, config: Any) -> str:
    """Render a CROSS-TARGET PATTERNS block for this target's features, or ''."""
    try:
        if not _enabled(config):
            return ""
        path = _store_path(config)
        if not path.is_file():
            return ""
        engagements = _load(path).get("engagements") or {}
        current = set(derive_features(state))
        if not current:
            return ""
        # Exclude this program's own contribution so the hint reflects OTHER
        # targets, not the one we are currently looking at.
        own = _slug_digest(state)
        others = {k: v for k, v in engagements.items() if k != own}
        total_other, by_feature, support = _aggregate(others)
        if total_other < _MIN_TOTAL_ENGAGEMENTS:
            return ""

        rows: list[tuple[float, int, str]] = []
        for feat in sorted(current):
            feat_support = support.get(feat, 0)
            if feat_support < _MIN_FEATURE_SUPPORT:
                continue
            for cls, hits in (by_feature.get(feat) or {}).items():
                if hits < _MIN_CLASS_HITS:
                    continue
                frac = hits / feat_support if feat_support else 0.0
                if frac < _MIN_CONFIRM_FRACTION:
                    continue
                rows.append(
                    (frac, hits, f"- targets with {feat}: {cls} confirmed in {hits}/{feat_support}")
                )
        if not rows:
            return ""
        rows.sort(key=lambda r: (-r[0], -r[1], r[2]))
        lines = [
            f"CROSS-TARGET PATTERNS (from {total_other} prior engagements; "
            "correlation not proof -- verify, do not assume):"
        ]
        lines.extend(line for _, _, line in rows[:_MAX_HINT_LINES])
        return "\n".join(lines)
    except Exception:  # noqa: BLE001
        return ""
