from __future__ import annotations

from urllib.parse import urlparse

from shroodler.suppress import filter_findings, path_of


def _page_path(url: str) -> str:
    return path_of(url)


def _origin_host(url: str) -> str:
    p = urlparse(url)
    if p.scheme and p.netloc:
        return f"{p.scheme}://{p.netloc}"
    return url


def document_to_baseline(
    doc: dict,
    *,
    name: str | None = None,
    suppressions: list[dict] | None = None,
) -> dict:
    pages = doc.get("pages") or []
    findings = filter_findings(doc.get("findings") or [], suppressions or [])
    expected_pages = sorted({_page_path(p.get("url", "")) for p in pages})
    expected_forms: dict[str, list[str]] = {}
    for page in pages:
        path = _page_path(page.get("url", ""))
        names: set[str] = set()
        for form in page.get("forms") or []:
            for field in form.get("fields") or []:
                n = field.get("name")
                if n:
                    names.add(n)
        if names:
            existing = set(expected_forms.get(path, []))
            expected_forms[path] = sorted(existing | names)
    expected_findings = sorted(
        ({"id": f.get("id", ""), "url": _page_path(f.get("url", ""))} for f in findings),
        key=lambda row: (row["id"], row["url"]),
    )
    target = doc.get("target") or ""
    return {
        "target_app": name or target or "local-app",
        "target": target,
        "expected_pages": expected_pages,
        "expected_forms": dict(sorted(expected_forms.items())),
        "expected_findings": expected_findings,
        "expected_not_found": [],
    }


def origin_of(url: str) -> str:
    return _origin_host(url)
