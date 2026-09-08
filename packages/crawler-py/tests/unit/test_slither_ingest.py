from __future__ import annotations

import json

from shroodler.slither_ingest import convert_file, is_slither_report, to_findings
from shroodler.validate import validate_crawl


def _slither_doc() -> dict:
    return {
        "success": True,
        "error": None,
        "results": {
            "detectors": [
                {
                    "check": "reentrancy-eth",
                    "impact": "High",
                    "confidence": "Medium",
                    "description": "Reentrancy in Vault.withdraw(uint256)",
                    "first_markdown_element": "contracts/Vault.sol#L42",
                    "elements": [
                        {
                            "type": "function",
                            "name": "withdraw",
                            "source_mapping": {
                                "filename_relative": "contracts/Vault.sol",
                                "lines": [42, 43],
                            },
                        }
                    ],
                },
                {
                    "check": "naming-convention",
                    "impact": "Informational",
                    "confidence": "High",
                    "description": "Parameter _x is not mixedCase",
                    "first_markdown_element": "contracts/Vault.sol#L10",
                },
            ]
        },
    }


def test_is_slither_report():
    assert is_slither_report(_slither_doc())
    assert is_slither_report({"detectors": []})
    assert not is_slither_report({"success": True})
    assert not is_slither_report([])


def test_to_findings_maps_impact_and_location():
    findings = to_findings(_slither_doc())
    by_id = {f.id: f for f in findings}
    reent = by_id["slither-reentrancy-eth"]
    assert reent.severity == "high"
    assert reent.category == "smart-contract"
    assert reent.url == "contracts/Vault.sol#L42"
    assert reent.confidence == "probable"
    assert "Reentrancy" in reent.description
    naming = by_id["slither-naming-convention"]
    assert naming.severity == "info"
    assert naming.confidence == "confirmed"


def test_convert_file_validates(tmp_path):
    path = tmp_path / "slither.json"
    path.write_text(json.dumps(_slither_doc()), encoding="utf-8")
    result = convert_file(path, target="vault")
    doc = result.to_dict()
    validate_crawl(doc)
    assert doc["target"] == "vault"
    assert doc["crawler"]["mode"] == "ingest"
    ids = {f["id"] for f in doc["findings"]}
    assert "slither-reentrancy-eth" in ids
    assert "slither-naming-convention" in ids


def test_cli_slither_ingest(tmp_path):
    from shroodler.cli import main

    path = tmp_path / "slither.json"
    path.write_text(json.dumps(_slither_doc()), encoding="utf-8")
    out = tmp_path / "sc.json"
    try:
        main(["slither-ingest", str(path), "-o", str(out)])
    except SystemExit as ex:
        assert ex.code == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert any(f["id"] == "slither-reentrancy-eth" for f in doc["findings"])
