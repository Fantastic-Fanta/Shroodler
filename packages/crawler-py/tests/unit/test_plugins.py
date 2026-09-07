from __future__ import annotations

from shroodler.crawler import crawl_url
from shroodler.extractors.secrets import scan_text
from shroodler.plugins import (
    load_plugins,
    merge_payload_paths,
    merge_secret_rules,
    plugin_paths_from_env,
    run_checks,
)


def _plugin_dir(tmp_path, *, with_check: bool = True):
    root = tmp_path / "my-plugin"
    (root / "packs").mkdir(parents=True)
    (root / "rules").mkdir()
    (root / "plugin.yaml").write_text(
        "name: fixture-plugin\n"
        "payloads: [packs/extra.yaml]\n"
        "secrets: [rules/extra.yaml]\n"
        + ("checks: [check.py]\n" if with_check else ""),
        encoding="utf-8",
    )
    (root / "packs" / "extra.yaml").write_text(
        "- id: plugin-xss\n"
        "  finding_id: payload-plugin-xss\n"
        "  payload: PLUGINTOKEN\n"
        "  severity: low\n"
        "  description: plugin pack\n"
        "  match:\n"
        "    any:\n"
        "      - reflected: true\n",
        encoding="utf-8",
    )
    (root / "rules" / "extra.yaml").write_text(
        "- id: plugin-fixture-secret\n"
        "  pattern: 'PLUGIN_SECRET_[A-Z0-9]{8}'\n"
        "  severity: high\n"
        "  description: plugin-loaded secret rule\n",
        encoding="utf-8",
    )
    if with_check:
        (root / "check.py").write_text(
            "def check(*, url, body, headers, status_code):\n"
            "    if 'PLUGIN_MARKER' in body:\n"
            "        return [{\n"
            "            'id': 'plugin-marker-seen',\n"
            "            'severity': 'low',\n"
            "            'category': 'scan-note',\n"
            "            'description': 'plugin saw its marker',\n"
            "        }]\n"
            "    return []\n",
            encoding="utf-8",
        )
    return root


def test_load_manifest_plugin(tmp_path):
    root = _plugin_dir(tmp_path)
    plugins = load_plugins([root])
    assert plugins[0].name == "fixture-plugin"
    assert merge_payload_paths(plugins)
    rules = merge_secret_rules(plugins)
    assert any(r["id"] == "plugin-fixture-secret" for r in rules)


def test_env_and_cli_paths(tmp_path, monkeypatch):
    root = _plugin_dir(tmp_path, with_check=False)
    other = tmp_path / "other"
    other.mkdir()
    (other / "s.yaml").write_text(
        "- id: env-secret\n  pattern: 'ENVSECRET'\n  severity: low\n  description: x\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SHROODLER_PLUGIN_PATH", str(other))
    paths = plugin_paths_from_env([str(root)])
    assert root.resolve() in paths
    assert other.resolve() in paths


def test_secret_rule_from_plugin_fires():
    findings = scan_text(
        "token=PLUGIN_SECRET_ABCDEFGH",
        "http://127.0.0.1/",
        extra_rules=[
            {
                "id": "plugin-fixture-secret",
                "pattern": r"PLUGIN_SECRET_[A-Z0-9]{8}",
                "severity": "high",
                "description": "plugin-loaded secret rule",
            }
        ],
    )
    assert any(f.id == "plugin-fixture-secret" for f in findings)


def test_python_check_runs_during_crawl(tmp_path, fx):
    root = _plugin_dir(tmp_path)
    fx.html("/", "<html>hello PLUGIN_MARKER</html>")
    result = crawl_url(
        fx.origin + "/",
        depth=0,
        ignore_robots=True,
        plugins=[str(root)],
    )
    ids = {f.id for f in result.findings}
    assert "plugin-marker-seen" in ids
    assert any(f.id == "plugin-fixture-secret" for f in result.findings) is False
    # The page body does not contain PLUGIN_SECRET_... so only the check fired.


def test_autodiscover_classifies_secrets_vs_packs(tmp_path):
    root = tmp_path / "bare"
    root.mkdir()
    (root / "secrets.yaml").write_text(
        "- id: bare-secret\n  pattern: 'BAREKEY'\n  severity: low\n  description: x\n",
        encoding="utf-8",
    )
    (root / "pack.yaml").write_text(
        "- id: bare-pack\n  payload: x\n  finding_id: payload-bare\n  severity: low\n"
        "  description: x\n  match:\n    any:\n      - reflected: true\n",
        encoding="utf-8",
    )
    plugins = load_plugins([root])
    assert any(r["id"] == "bare-secret" for r in plugins[0].secret_rules)
    assert any(p.name == "pack.yaml" for p in plugins[0].payload_paths)


def test_run_checks_unknown_category_falls_back():
    def check(*, url, body, headers, status_code):
        return [{"id": "x", "category": "not-a-real-category", "description": "d"}]

    findings = run_checks([check], url="http://127.0.0.1/", body="", headers={}, status_code=200)
    assert findings[0].category == "scan-note"
