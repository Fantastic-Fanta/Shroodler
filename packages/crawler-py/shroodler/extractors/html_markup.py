from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from bs4 import BeautifulSoup, Comment

from shroodler.extractors.secrets import scan_text
from shroodler.models import Finding


def keywords_path() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "packages" / "secret-patterns" / "keywords" / "html-comments.txt"
        if candidate.is_file():
            return candidate
        alt = parent / "secret-patterns" / "keywords" / "html-comments.txt"
        if alt.is_file():
            return alt
    raise FileNotFoundError("html-comments.txt not found")


def _parse_keywords(text: str) -> list[str]:
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


@lru_cache(maxsize=1)
def load_comment_keywords() -> list[str]:
    return _parse_keywords(keywords_path().read_text(encoding="utf-8"))


def _comment_hits(text: str, keywords: list[str]) -> bool:
    lowered = text.lower()
    return any(key.lower() in lowered for key in keywords)


def _snippet(text: str, limit: int = 80) -> str:
    compact = " ".join(text.split())
    if len(compact) > limit:
        return compact[:limit]
    return compact


def extract_html_comments(body: str, page_url: str) -> list[Finding]:
    if not body:
        return []
    keywords = load_comment_keywords()
    if not keywords:
        return []
    soup = BeautifulSoup(body, "lxml")
    findings: list[Finding] = []
    seen: set[str] = set()
    for node in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = str(node).strip()
        if not text or not _comment_hits(text, keywords):
            continue
        key = text.casefold()
        if key in seen:
            continue
        seen.add(key)
        secrets = scan_text(text, page_url)
        category = "secret" if secrets else "verbose-error"
        findings.append(
            Finding(
                id="html-comment",
                severity="info",
                category=category,
                url=page_url,
                description="HTML comment contains leftover TODO or credential-like text",
                evidence=_snippet(text),
            )
        )
    return findings


def extract_meta_generator(body: str, page_url: str) -> list[Finding]:
    if not body:
        return []
    soup = BeautifulSoup(body, "lxml")
    findings: list[Finding] = []
    seen: set[str] = set()
    for tag in soup.find_all("meta"):
        name = tag.get("name")
        if not name or str(name).lower() != "generator":
            continue
        content = (tag.get("content") or "").strip()
        if not content or content.casefold() in seen:
            continue
        seen.add(content.casefold())
        findings.append(
            Finding(
                id="meta-generator",
                severity="info",
                category="header",
                url=page_url,
                description="meta generator tag discloses the application stack",
                evidence=_snippet(content, 120),
            )
        )
    return findings


def extract_html_markup(body: str, page_url: str) -> list[Finding]:
    return extract_html_comments(body, page_url) + extract_meta_generator(body, page_url)
