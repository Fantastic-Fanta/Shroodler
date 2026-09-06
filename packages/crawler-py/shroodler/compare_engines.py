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


class EngineOrderError(ValueError):
    """Raised when a crawl document's self-reported `crawler.name`
    contradicts the positional slot it was passed in -- both engines
    always stamp this (`shroodler-py`/`shroodler-go`; see
    shroodler/crawler.py and crawler-go/internal/crawler/crawler.go), so
    a caller running `shroodler compare-engines go.json py.json` in the
    wrong order gets a loud error instead of every finding's `engines`
    tag and the only_python/only_go counters being silently swapped --
    nothing else in either document's shape reveals which engine
    produced it."""


# The exact, canonical names each engine stamps into crawler.name. Checked
# by EXACT equality against the *other* slot's canonical name, not a
# substring test -- an earlier version used `"go" in name`/`"py" in name`,
# which both false-negatived (a name like "shroodler-go-copy" contains
# "py" via "co-py" and slipped past undetected) and would have
# false-positived on a hypothetical future name merely containing one of
# these letter pairs. Exact-name comparison has neither failure mode; the
# tradeoff is it can only catch a swap against a name it recognizes as
# literally the OTHER known engine, not against every conceivable typo.
_PY_ENGINE_NAME = "shroodler-py"
_GO_ENGINE_NAME = "shroodler-go"


def _engine_name(doc: dict) -> str:
    return str((doc.get("crawler") or {}).get("name", "")).strip().lower()


def _check_engine_order(py_doc: dict, go_doc: dict) -> None:
    py_name = _engine_name(py_doc)
    go_name = _engine_name(go_doc)
    if py_name == _GO_ENGINE_NAME:
        raise EngineOrderError(
            f"first argument's crawler.name={py_name!r} is the Go engine's own name -- "
            "pass the Python engine's crawl JSON first, Go's second"
        )
    if go_name == _PY_ENGINE_NAME:
        raise EngineOrderError(
            f"second argument's crawler.name={go_name!r} is the Python engine's own name -- "
            "pass the Python engine's crawl JSON first, Go's second"
        )


def merge_engine_results(py_doc: dict, go_doc: dict) -> dict:
    """Merge two crawl documents' findings into one list, annotated with
    which engine(s) reproduced each (id, path, query). Pages/target/etc.
    are taken from whichever document is non-empty, preferring the
    Python doc's metadata (arbitrary but stable) when both have pages.

    Raises EngineOrderError if either document's own crawler.name is
    literally the OTHER engine's canonical name. When crawler.name is
    missing/unrecognized on either side, the merge still proceeds
    (permissive, since not every synthetic/third-party crawl doc will
    carry it) -- but the result's `engine_agreement.engine_verification`
    is set to "unverified" rather than silently claiming the same
    confidence as a document pair that was actually checked, so a
    consumer can tell "we confirmed the order" from "we couldn't check".
    """
    _check_engine_order(py_doc, go_doc)
    engine_verification = (
        "verified"
        if _engine_name(py_doc) == _PY_ENGINE_NAME and _engine_name(go_doc) == _GO_ENGINE_NAME
        else "unverified"
    )
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
            "engine_verification": engine_verification,
        },
    }
