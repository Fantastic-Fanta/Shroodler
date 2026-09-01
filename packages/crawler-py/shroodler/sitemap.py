from __future__ import annotations

import xml.etree.ElementTree as ET


def parse_robots_sitemaps(body: str) -> list[str]:
    """Return Sitemap: URLs from a robots.txt body. Never raises."""
    out: list[str] = []
    if not body:
        return out
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if not lower.startswith("sitemap:"):
            continue
        rest = line.split(":", 1)[1].strip()
        if not rest:
            continue
        token = rest.split()[0]
        if token.startswith("#"):
            continue
        out.append(token)
    return out


def _local_name(tag: str) -> str:
    if tag.startswith("{") and "}" in tag:
        return tag.rsplit("}", 1)[-1].lower()
    return tag.lower()


def parse_sitemap_xml(body: str) -> tuple[list[str], list[str]]:
    """Parse urlset/sitemapindex XML.

    Returns (url_locs, nested_sitemap_locs). Malformed XML returns empty lists.
    """
    url_locs: list[str] = []
    sitemap_locs: list[str] = []
    if not body or not body.strip():
        return url_locs, sitemap_locs
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return url_locs, sitemap_locs
    except Exception:
        return url_locs, sitemap_locs
    _walk_sitemap(root, url_locs, sitemap_locs)
    return url_locs, sitemap_locs


def _walk_sitemap(parent: ET.Element, url_locs: list[str], sitemap_locs: list[str]) -> None:
    parent_name = _local_name(parent.tag)
    for child in list(parent):
        name = _local_name(child.tag)
        if name == "loc":
            text = (child.text or "").strip()
            if not text:
                continue
            if parent_name == "sitemap":
                sitemap_locs.append(text)
            else:
                url_locs.append(text)
            continue
        _walk_sitemap(child, url_locs, sitemap_locs)
