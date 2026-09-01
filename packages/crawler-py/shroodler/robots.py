from __future__ import annotations

import re
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

DEFAULT_UA = "Shroodler/0.1.0 (+https://shroodler.local)"


def load_robots(robots_body: str, base_url: str) -> RobotFileParser:
    rp = RobotFileParser()
    origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    rp.set_url(origin + "/robots.txt")
    rp.parse(robots_body.splitlines())
    return rp


def allowed(rp: RobotFileParser | None, url: str, ua: str = DEFAULT_UA) -> bool:
    if rp is None:
        return True
    return rp.can_fetch(ua, url)


_PAGE_PATH = re.compile(r"^(.*)/page/(\d+)/?$", re.I)
_PAGE_QUERY = re.compile(r"(?:^|&)page=\d+", re.I)


def pagination_family(url: str) -> str | None:
    p = urlparse(url)
    path = p.path or "/"
    m = _PAGE_PATH.match(path)
    if m:
        return f"path:{m.group(1)}/page/N"
    if _PAGE_QUERY.search(p.query or ""):
        q = re.sub(r"(?:^|&)page=\d+", "", p.query, flags=re.I).strip("&")
        return f"query:{path}?{q}"
    return None


def is_pagination_trap(url: str, family_counts: dict[str, int], limit: int = 8) -> bool:
    fam = pagination_family(url)
    if not fam:
        return False
    return family_counts.get(fam, 0) >= limit
