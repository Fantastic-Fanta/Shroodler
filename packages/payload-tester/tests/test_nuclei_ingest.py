from __future__ import annotations

from pathlib import Path

import yaml

from nuclei_ingest import convert_files, is_nuclei_template, to_packs
from tester import _load_pack_file


TEMPLATE = """
id: example-xss
info:
  name: Example XSS
  severity: medium
  description: Reflected XSS example
http:
  - method: GET
    path:
      - "{{BaseURL}}/?q={{xss}}"
    payloads:
      xss:
        - "<script>alert(1)</script>"
        - "\\"><img src=x>"
    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - "<script>alert(1)</script>"
      - type: status
        status:
          - 200
"""


def test_to_packs_flattens_payloads_and_word_matchers():
    obj = yaml.safe_load(TEMPLATE)
    assert is_nuclei_template(obj)
    packs = to_packs(obj)
    assert len(packs) == 2
    assert packs[0]["finding_id"] == "nuclei-example-xss"
    assert packs[0]["payload"] == "<script>alert(1)</script>"
    assert packs[0]["severity"] == "medium"
    kinds = {k for c in packs[0]["match"]["any"] for k in c}
    assert "body_contains" in kinds
    assert "status_gte" in kinds


def test_skips_non_http_and_empty_payloads(tmp_path):
    p = tmp_path / "dns.yaml"
    p.write_text("id: x\ninfo:\n  name: n\ndns:\n  - name: '{{FQDN}}'\n", encoding="utf-8")
    packs, skipped = convert_files([p])
    assert packs == []
    assert skipped
    empty = tmp_path / "http-empty.yaml"
    empty.write_text(
        "id: empty\ninfo:\n  name: n\n  severity: high\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}/']\n",
        encoding="utf-8",
    )
    packs2, skipped2 = convert_files([empty])
    assert packs2 == []
    assert any("no convertible" in s for s in skipped2)


def test_load_pack_file_accepts_nuclei_yaml(tmp_path):
    p = tmp_path / "n.yaml"
    p.write_text(TEMPLATE, encoding="utf-8")
    packs = _load_pack_file(p)
    assert packs[0]["id"].startswith("example-xss")
    assert Path(p).read_text(encoding="utf-8").lstrip().startswith("id:")


def test_header_matcher_and_requests_alias():
    obj = {
        "id": "loc",
        "info": {"name": "redir", "severity": "low"},
        "requests": [
            {
                "payloads": {"p": ["https://evil.example"]},
                "matchers": [{"type": "word", "part": "location", "words": ["evil.example"]}],
            }
        ],
    }
    packs = to_packs(obj)
    assert packs[0]["match"]["any"][0] == {"redirected_to_contains": "evil.example"}
