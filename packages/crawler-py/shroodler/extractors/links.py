from __future__ import annotations

import re

from bs4 import BeautifulSoup, Tag

from shroodler.urls import normalize_url

_CSS_URL = re.compile(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", re.I)
_META_REFRESH = re.compile(r"url\s*=\s*['\"]?([^'\";\s]+)", re.I)


def _style_hides(style: str | None) -> bool:
    if not style:
        return False
    compact = re.sub(r"\s+", "", style.lower())
    if "display:none" in compact:
        return True
    if "visibility:hidden" in compact:
        return True
    if "left:-9999" in compact or "left:-10000" in compact:
        return True
    if "opacity:0" in compact:
        return True
    return False


def is_honeypot(tag: Tag) -> bool:
    current: Tag | None = tag
    while current is not None and isinstance(current, Tag):
        if current.has_attr("hidden"):
            return True
        if (current.get("aria-hidden") or "").lower() == "true":
            return True
        cls = current.get("class") or []
        if any("honeypot" in c.lower() for c in cls):
            return True
        if _style_hides(current.get("style")):
            return True
        current = current.parent if isinstance(current.parent, Tag) else None
    return False


def extract_links(base_url: str, html: str) -> list[str]:
    soup = BeautifulSoup(html, "lxml")
    found: list[str] = []

    def add(raw: str | None) -> None:
        url = normalize_url(base_url, raw or "")
        if url:
            found.append(url)

    for a in soup.find_all("a", href=True):
        if is_honeypot(a):
            continue
        add(a.get("href"))

    for form in soup.find_all("form"):
        if is_honeypot(form):
            continue
        add(form.get("action") or base_url)

    for link in soup.find_all("link", href=True):
        add(link.get("href"))

    for script in soup.find_all("script", src=True):
        add(script.get("src"))

    for meta in soup.find_all("meta"):
        http_equiv = (meta.get("http-equiv") or "").lower()
        if http_equiv == "refresh":
            content = meta.get("content") or ""
            m = _META_REFRESH.search(content)
            if m:
                add(m.group(1))

    for style in soup.find_all("style"):
        for m in _CSS_URL.finditer(style.get_text() or ""):
            add(m.group(1))

    for tagged in soup.find_all(style=True):
        for m in _CSS_URL.finditer(tagged.get("style") or ""):
            add(m.group(1))

    # Deduplicate preserving order
    out: list[str] = []
    seen: set[str] = set()
    for u in found:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def extract_css_urls(base_url: str, css_text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in _CSS_URL.finditer(css_text):
        url = normalize_url(base_url, m.group(1))
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out
