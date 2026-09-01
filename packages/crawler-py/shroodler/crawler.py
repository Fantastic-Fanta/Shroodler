from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable
from datetime import datetime, timezone
from time import sleep
from urllib.parse import urljoin

from shroodler import __version__
from shroodler.extractors.cookies import extract_cookies
from shroodler.extractors.forms import extract_forms
from shroodler.extractors.headers import extract_headers
from shroodler.extractors.links import extract_css_urls, extract_links
from shroodler.extractors.verbose import extract_verbose_errors
from shroodler.models import CrawlerInfo, CrawlResult, Finding, Page
from shroodler.modes.static import FetchResult, StaticFetcher
from shroodler.robots import (
    DEFAULT_UA,
    allowed,
    is_pagination_trap,
    load_robots,
    pagination_family,
)
from shroodler.urls import canonical_key, is_loopback_or_local, query_param_names, same_origin

ProgressCb = Callable[[int, str], None]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _content_type(headers: dict[str, str]) -> str:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return v.lower()
    return ""


class Crawler:
    def __init__(
        self,
        *,
        mode: str = "static",
        depth: int | None = 5,
        ignore_robots: bool = False,
        allow_external: bool = False,
        max_pages: int = 400,
        max_redirects: int = 10,
        rate_limit_retries: int = 3,
        user_agent: str = DEFAULT_UA,
        progress: ProgressCb | None = None,
    ) -> None:
        if mode != "static":
            raise ValueError(f"mode {mode!r} is not implemented in this milestone")
        self.mode = mode
        self.depth = depth
        self.ignore_robots = ignore_robots
        self.allow_external = allow_external
        self.max_pages = max_pages
        self.max_redirects = max_redirects
        self.rate_limit_retries = rate_limit_retries
        self.user_agent = user_agent
        self.progress = progress
        self.fetcher = StaticFetcher(user_agent=user_agent)

    def close(self) -> None:
        self.fetcher.close()

    def crawl(self, start_url: str) -> CrawlResult:
        started = _now()
        if not self.allow_external and not is_loopback_or_local(start_url):
            raise ValueError(
                "refusing to crawl non-local host; pass --allow-external for listed public fixtures"
            )
        seed = start_url if "://" in start_url else "http://" + start_url
        origin_url = seed
        rp = None
        if not self.ignore_robots:
            robots_url = urljoin(seed, "/robots.txt")
            robots_res = self.fetcher.fetch(robots_url)
            if robots_res.status_code == 200 and robots_res.text:
                rp = load_robots(robots_res.text, seed)

        queue: deque[tuple[str, int]] = deque([(seed, 0)])
        seen: set[str] = set()
        pages: list[Page] = []
        findings: list[Finding] = []
        family_counts: dict[str, int] = defaultdict(int)
        redirect_hits: dict[str, int] = defaultdict(int)

        while queue and len(pages) < self.max_pages:
            url, depth = queue.popleft()
            key = canonical_key(url)
            if key in seen:
                continue
            if not same_origin(url, origin_url):
                continue
            if not self.ignore_robots and not allowed(rp, url, self.user_agent):
                continue
            if is_pagination_trap(url, family_counts):
                continue
            seen.add(key)
            fam = pagination_family(url)
            if fam:
                family_counts[fam] += 1

            result = self._fetch_with_retries(url)
            page, page_findings = self._page_from_result(result)
            pages.append(page)
            findings.extend(page_findings)
            if self.progress:
                self.progress(len(pages), result.url)

            if result.redirect_to:
                loc = urljoin(result.url, result.redirect_to)
                redirect_hits[key] += 1
                if redirect_hits[key] <= self.max_redirects:
                    loc_key = canonical_key(loc)
                    if loc_key not in seen and same_origin(loc, origin_url):
                        queue.append((loc, depth))

            if self.depth is not None and depth >= self.depth:
                continue

            ctype = _content_type(result.headers)
            next_links: list[str] = []
            if "html" in ctype or result.text.lstrip().startswith("<"):
                next_links.extend(extract_links(result.url, result.text))
            if "css" in ctype:
                next_links.extend(extract_css_urls(result.url, result.text))

            for link in next_links:
                if not same_origin(link, origin_url):
                    continue
                if canonical_key(link) in seen:
                    continue
                if is_pagination_trap(link, family_counts):
                    continue
                queue.append((link, depth + 1))

        finished = _now()
        return CrawlResult(
            target=seed,
            scan_started_at=started,
            scan_finished_at=finished,
            crawler=CrawlerInfo(name="shroodler-py", version=__version__, mode="static"),
            pages=pages,
            findings=_dedupe_findings(findings),
            js_endpoints=[],
        )

    def _fetch_with_retries(self, url: str) -> FetchResult:
        delay = 0.2
        last = self.fetcher.fetch(url)
        for _ in range(self.rate_limit_retries):
            if last.status_code != 429:
                return last
            retry_after = last.headers.get("Retry-After") or last.headers.get("retry-after")
            wait = delay
            if retry_after:
                try:
                    wait = min(float(retry_after), 5.0)
                except ValueError:
                    wait = delay
            sleep(wait)
            delay = min(delay * 2, 2.0)
            last = self.fetcher.fetch(url)
        return last

    def _page_from_result(self, result: FetchResult) -> tuple[Page, list[Finding]]:
        js_files: list[str] = []
        forms = []
        form_findings: list[Finding] = []
        if result.text:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(result.text, "lxml")
            for script in soup.find_all("script", src=True):
                src = script.get("src")
                if src:
                    js_files.append(src)
            ctype = _content_type(result.headers)
            if "html" in ctype or result.text.lstrip().startswith("<"):
                forms, form_findings = extract_forms(result.text, result.url)
        cookies, cookie_findings = extract_cookies(result.set_cookies, result.url)
        headers, header_findings = extract_headers(result.headers, result.url)
        verbose_findings = extract_verbose_errors(result.text, result.url, result.status_code)
        page = Page(
            url=result.url,
            status_code=result.status_code,
            forms=forms,
            params=query_param_names(result.url),
            cookies=cookies,
            headers=headers,
            js_files=js_files,
        )
        all_f = form_findings + cookie_findings + header_findings + verbose_findings
        return page, all_f


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for f in findings:
        key = (f.id, f.url)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def crawl_url(url: str, **kwargs) -> CrawlResult:
    c = Crawler(**kwargs)
    try:
        return c.crawl(url)
    finally:
        c.close()
