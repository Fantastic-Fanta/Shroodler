"""Tests for cross-target pattern learning, incl. the scope-isolation gate."""

from __future__ import annotations

import json
from types import SimpleNamespace

from shroodler.llm_agent import cross_program_memory as cpm
from shroodler.llm_agent.context import build_context
from shroodler.models import Finding


def _facts(**kv):
    return {k: {"value": v} for k, v in kv.items()}


def _state(slug="prog", facts=None, findings=None):
    return SimpleNamespace(
        slug=slug,
        engagement_memory=facts or {},
        findings=findings or [],
    )


def _finding(fid, conf="confirmed"):
    return Finding(
        id=fid,
        severity="high",
        category="payload",
        url=f"http://127.0.0.1/{fid}",
        description="d",
        evidence="e",
        confidence=conf,
    )


def _config(tmp_path, enabled=True):
    return SimpleNamespace(cross_program_dir=str(tmp_path), cross_program_learning=enabled)


# --- feature derivation ------------------------------------------------------


def test_derive_features_vocab_hits():
    st = _state(facts=_facts(framework="Flask", id_scheme="sequential-integer"))
    feats = cpm.derive_features(st)
    assert "framework=flask" in feats
    assert "id_scheme=sequential-integer" in feats


def test_derive_features_drops_unknown_vocab():
    # A framework we do not list is dropped (fail-closed), not slugified in.
    st = _state(facts=_facts(framework="SomeBespokeFramework9000"))
    assert cpm.derive_features(st) == []


def test_waf_vendor_and_graphql_map():
    st = _state(facts=_facts(waf_vendor="Cloudflare", graphql="endpoint present"))
    feats = cpm.derive_features(st)
    assert "waf_vendor=cloudflare" in feats
    assert "graphql=endpoint-present" in feats


# --- scope isolation: the hard property --------------------------------------


def test_url_like_value_cannot_leak_as_feature():
    st = _state(facts=_facts(framework="https://victim.example.com/secret?token=abc123"))
    feats = cpm.derive_features(st)
    assert feats == []  # not in vocab -> dropped
    for tok in feats:
        assert "victim" not in tok and "example" not in tok


def test_stored_file_contains_no_target_data(tmp_path):
    cfg = _config(tmp_path)
    st = _state(
        slug="acme-corp-prod",
        facts=_facts(
            framework="django",
            id_scheme="uuid",
            waf_vendor="https://internal.acme.example/waf",  # leaky-looking -> dropped
        ),
        findings=[_finding("idor"), _finding("sqli")],
    )
    cpm.record_engagement(st, cfg)
    raw = (tmp_path / "patterns.json").read_text(encoding="utf-8")
    # No hostname, URL scheme, slug, or path separator anywhere in the store.
    for bad in ("victim", "acme", "example", "http", "://", "/", "internal"):
        assert bad not in raw, f"{bad!r} leaked into cross-program store"
    data = json.loads(raw)
    (row,) = data["engagements"].values()
    assert row["features"] == ["framework=django", "id_scheme=uuid"]
    # The on-disk key is a one-way digest, not the slug.
    assert "acme-corp-prod" not in data["engagements"]


# --- bug-class derivation ----------------------------------------------------


def test_bug_class_variant_collapse():
    st = _state(findings=[_finding("xss-reflected"), _finding("sqli-boolean")])
    classes = cpm.derive_bug_classes(st)
    assert "xss" in classes and "sqli" in classes


def test_bug_class_ignores_unconfirmed():
    st = _state(findings=[_finding("idor", conf="heuristic"), _finding("ssrf", conf="confirmed")])
    assert cpm.derive_bug_classes(st) == ["ssrf"]


# --- record / dedup ----------------------------------------------------------


def test_repeat_run_replaces_not_duplicates(tmp_path):
    cfg = _config(tmp_path)
    st = _state(slug="same", facts=_facts(framework="flask"), findings=[_finding("idor")])
    cpm.record_engagement(st, cfg)
    cpm.record_engagement(st, cfg)
    data = json.loads((tmp_path / "patterns.json").read_text(encoding="utf-8"))
    assert len(data["engagements"]) == 1


def test_disabled_writes_nothing(tmp_path):
    cfg = _config(tmp_path, enabled=False)
    st = _state(facts=_facts(framework="flask"), findings=[_finding("idor")])
    cpm.record_engagement(st, cfg)
    assert not (tmp_path / "patterns.json").exists()


def test_no_features_skips_write(tmp_path):
    cfg = _config(tmp_path)
    st = _state(facts={}, findings=[_finding("idor")])
    cpm.record_engagement(st, cfg)
    assert not (tmp_path / "patterns.json").exists()


# --- summarize / thresholds --------------------------------------------------


def _seed(cfg, n, feature_facts, bug_ids, slug_prefix="t"):
    for i in range(n):
        st = _state(
            slug=f"{slug_prefix}{i}",
            facts=_facts(**feature_facts),
            findings=[_finding(b) for b in bug_ids],
        )
        cpm.record_engagement(st, cfg)


def test_summarize_below_threshold_is_empty(tmp_path):
    cfg = _config(tmp_path)
    _seed(cfg, 2, {"id_scheme": "sequential-integer"}, ["idor"])
    cur = _state(slug="new", facts=_facts(id_scheme="sequential-integer"))
    assert cpm.summarize_for(cur, cfg) == ""


def test_summarize_surfaces_shared_pattern(tmp_path):
    cfg = _config(tmp_path)
    _seed(cfg, 5, {"id_scheme": "sequential-integer"}, ["idor"])
    cur = _state(slug="brand-new", facts=_facts(id_scheme="sequential-integer"))
    block = cpm.summarize_for(cur, cfg)
    assert "CROSS-TARGET PATTERNS" in block
    assert "id_scheme=sequential-integer" in block
    assert "idor confirmed in 5/5" in block


def test_summarize_only_for_shared_features(tmp_path):
    cfg = _config(tmp_path)
    _seed(cfg, 5, {"framework": "django"}, ["ssti"])
    # Current target shares nothing with the learned django cohort.
    cur = _state(slug="other", facts=_facts(framework="rails"))
    assert cpm.summarize_for(cur, cfg) == ""


def test_summarize_excludes_own_contribution(tmp_path):
    cfg = _config(tmp_path)
    _seed(cfg, 3, {"id_scheme": "uuid"}, ["idor"], slug_prefix="peer")
    # This same program recorded a run; it must not count toward its own hint.
    me = _state(slug="me", facts=_facts(id_scheme="uuid"), findings=[_finding("idor")])
    cpm.record_engagement(me, cfg)
    block = cpm.summarize_for(me, cfg)
    # 3 peers remain after excluding "me": still meets threshold, denominator 3.
    assert "idor confirmed in 3/3" in block


# --- integration with planner context ---------------------------------------


def test_build_context_includes_cross_target_block(tmp_path):
    cfg = SimpleNamespace(
        target="http://127.0.0.1:8087",
        program="cur",
        cross_program_dir=str(tmp_path),
        cross_program_learning=True,
        _iteration=1,
        max_iterations=10,
    )
    _seed(_config(tmp_path), 4, {"id_scheme": "sequential-integer"}, ["idor"])
    cur = _state(slug="cur", facts=_facts(id_scheme="sequential-integer"))
    text = build_context(cur, [], [], cfg)
    assert "CROSS-TARGET PATTERNS" in text


# --- robustness --------------------------------------------------------------


def test_never_raises_on_junk(tmp_path):
    cfg = _config(tmp_path)
    cpm.record_engagement(SimpleNamespace(), cfg)  # no slug/facts/findings
    assert cpm.summarize_for(SimpleNamespace(), cfg) == ""
    assert cpm.derive_features(SimpleNamespace()) == []
