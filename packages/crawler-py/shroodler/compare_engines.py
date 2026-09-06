"""`shroodler compare-engines`: expose dual-engine agreement/disagreement
as a user-facing confidence signal, instead of keeping it as internal
QA (see packages/parity-tests, which treats any divergence as a bug to
fix). Nobody else ships two independent implementations of the same
scanner and can say "the Python and Go engines agree here" -- this is
close to free, since both engines and a parity-test harness already
exist; this module just reframes divergence as information for the
report reader rather than only a CI failure.

Takes a crawl JSON produced by each engine against (nominally) the same
target and merges their findings, one row per distinct (id, path,
query), each carrying which engine(s) independently reproduced it.
Agreement is a confidence signal, not proof -- and disagreement is not
proof of a false positive either: it's just as likely to mean one engine
implements a check the other doesn't have yet (see
packages/parity-tests/run_parity.py's PYTHON_ONLY_CATEGORIES) as it is
to mean a check is flaky. This module reports the fact; it doesn't judge
it.
"""

from __future__ import annotations

from urllib.parse import urlparse

from shroodler.suppress import path_of


def _key(finding: dict) -> tuple[str, str, str]:
    url = finding.get("url", "")
    return (finding.get("id", ""), path_of(url), urlparse(url).query)


def merge_engine_results(py_doc: dict, go_doc: dict) -> dict:
    """Merge two crawl documents' findings into one list, annotated with
    which engine(s) reproduced each (id, path, query). Pages/target/etc.
    are taken from whichever document is non-empty, preferring the
    Python doc's metadata (arbitrary but stable) when both have pages.
    """
    by_key: dict[tuple[str, str, str], dict] = {}
    # Severities actually observed FROM EACH ENGINE for a key, kept
    # separately rather than compared against "whatever's in the merged
    # entry so far" -- a single engine emitting the same (id, path,
    # query) twice with different severities (a real, documented case:
    # two Set-Cookie headers on one page both tripping insecure-cookie)
    # must never be reported as a cross-engine disagreement when the
    # OTHER engine found nothing at all under that key.
    severities_by_engine: dict[tuple[str, str, str], dict[str, set[str]]] = {}
    order: list[tuple[str, str, str]] = []

    for engine, doc in (("python", py_doc), ("go", go_doc)):
        for f in doc.get("findings", []):
            key = _key(f)
            if key not in by_key:
                merged = dict(f)
                merged["engines"] = []
                by_key[key] = merged
                severities_by_engine[key] = {"python": set(), "go": set()}
                order.append(key)
            entry = by_key[key]
            if engine not in entry["engines"]:
                entry["engines"].append(engine)
            severities_by_engine[key][engine].add(f.get("severity"))

    for key, entry in by_key.items():
        seen = severities_by_engine[key]
        if seen["python"] and seen["go"] and seen["python"] != seen["go"]:
            entry["severity_disagreement"] = {
                "python": sorted(seen["python"]),
                "go": sorted(seen["go"]),
            }

    merged_findings = [by_key[k] for k in order]
    target = py_doc.get("target") or go_doc.get("target", "")
    pages = py_doc.get("pages") or go_doc.get("pages", [])

    only_python = sum(1 for f in merged_findings if f["engines"] == ["python"])
    only_go = sum(1 for f in merged_findings if f["engines"] == ["go"])
    agreed = sum(1 for f in merged_findings if len(f["engines"]) > 1)

    return {
        "target": target,
        "pages": pages,
        "findings": merged_findings,
        "engine_agreement": {
            "agreed": agreed,
            "only_python": only_python,
            "only_go": only_go,
            "total_distinct": len(merged_findings),
        },
    }
