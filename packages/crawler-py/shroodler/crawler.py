from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable
from datetime import datetime, timezone
from time import monotonic, sleep
from urllib.parse import urljoin, urlparse

from shroodler import __version__
from shroodler.auth import (
    CookieSpec,
    apply_httpx_cookies,
    load_cookie_jar,
    load_login_recipe,
    load_storage_state,
    parse_cookie_pairs,
    parse_header_lines,
    resolve_recipe_url,
    run_login_httpx,
)
from shroodler.extractors.common_paths import probe_mutations, probe_paths
from shroodler.extractors.cookies import extract_cookies
from shroodler.extractors.cors import (
    candidate_from_endpoint,
    is_api_ish,
    is_api_path,
    probe_cors,
)
from shroodler.extractors.forms import extract_forms
from shroodler.extractors.graphql import probe_graphql
from shroodler.extractors.headers import extract_headers
from shroodler.extractors.js_endpoints import extract_js_endpoints, ghost_route_findings
from shroodler.extractors.links import extract_css_urls, extract_links
from shroodler.extractors.secrets import scan_text
from shroodler.extractors.sourcemap import (
    decode_data_url,
    extract_from_source_map,
    parse_source_map,
    source_mapping_url,
)
from shroodler.extractors.verbose import extract_verbose_errors
from shroodler.models import CrawlerInfo, CrawlResult, CrawlStats, Finding, JsEndpoint, Page
from shroodler.modes.static import FetchResult, StaticFetcher
from shroodler.robots import (
    DEFAULT_UA,
    allowed,
    is_pagination_trap,
    load_robots,
    pagination_family,
)
from shroodler.sitemap import parse_robots_sitemaps, parse_sitemap_xml
from shroodler.urls import (
    canonical_key,
    is_loopback_or_local,
    normalize_url,
    query_param_names,
    same_origin,
)

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
        max_time: float | None = None,
        max_redirects: int = 10,
        rate_limit_retries: int = 3,
        user_agent: str = DEFAULT_UA,
        progress: ProgressCb | None = None,
        cookies: list[str] | None = None,
        headers: list[str] | None = None,
        cookie_jar: str | None = None,
        storage_state: str | None = None,
        login_recipe: str | None = None,
        proxy: str | None = None,
        extra_seeds: list[str] | None = None,
        no_sitemap: bool = False,
    ) -> None:
        if mode not in {"static", "headless"}:
            raise ValueError(f"mode {mode!r} is not supported")
        self.mode = mode
        self.depth = depth
        self.ignore_robots = ignore_robots
        self.allow_external = allow_external
        self.max_pages = 400 if max_pages <= 0 else max_pages
        self.max_time = max_time if max_time and max_time > 0 else None
        self.max_redirects = max_redirects
        self.rate_limit_retries = rate_limit_retries
        self.user_agent = user_agent
        self.progress = progress
        self.proxy = proxy
        self.extra_seeds = extra_seeds or []
        self.no_sitemap = no_sitemap
        self._cookie_args = cookies or []
        self._cookie_jar = cookie_jar
        self._storage_state = storage_state
        self._login_recipe_path = login_recipe
        extra_headers = parse_header_lines(headers)
        self.http = StaticFetcher(user_agent=user_agent, proxy=proxy, extra_headers=extra_headers)
        if mode == "headless":
            from shroodler.modes.headless import HeadlessFetcher

            self.fetcher = HeadlessFetcher(
                user_agent=user_agent, proxy=proxy, extra_headers=extra_headers
            )
        else:
            self.fetcher = self.http

    def close(self) -> None:
        self.fetcher.close()
        if self.fetcher is not self.http:
            self.http.close()

    def crawl(self, start_url: str) -> CrawlResult:
        started = _now()
        t0 = monotonic()
        stopped = "complete"
        if not self.allow_external and not is_loopback_or_local(start_url):
            raise ValueError(
                "refusing to crawl non-local host; pass --allow-external for listed public fixtures"
            )
        seed = start_url if "://" in start_url else "http://" + start_url
        origin_url = seed
        self._prime_auth(seed)
        rp = None
        robots_body = ""
        if not self.ignore_robots or not self.no_sitemap:
            robots_url = urljoin(seed, "/robots.txt")
            robots_res = self.http.fetch(robots_url)
            if robots_res.status_code == 200 and robots_res.text:
                robots_body = robots_res.text
                if not self.ignore_robots:
                    rp = load_robots(robots_body, seed)

        queue: deque[tuple[str, int]] = deque([(seed, 0)])
        for extra in self.extra_seeds:
            if same_origin(extra, origin_url):
                queue.append((extra, 0))
        seen: set[str] = set()
        if not self.no_sitemap:
            self._enqueue_sitemap_seeds(seed, origin_url, robots_body, queue, seen)
        pages: list[Page] = []
        findings: list[Finding] = []
        js_endpoints: list = []
        cors_candidates: list[str] = []
        family_counts: dict[str, int] = defaultdict(int)
        redirect_hits: dict[str, int] = defaultdict(int)

        while queue:
            hit = self._budget_hit(t0, len(pages))
            if hit:
                stopped = hit
                break
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
            hit = self._budget_hit(t0, len(pages))
            if hit:
                stopped = hit
                break
            seen.add(key)
            fam = pagination_family(url)
            if fam:
                family_counts[fam] += 1

            result = self._fetch_with_retries(url, t0)
            page, page_findings, page_eps = self._page_from_result(result)
            pages.append(page)
            findings.extend(page_findings)
            js_endpoints.extend(page_eps)
            if is_api_ish(result.url, _content_type(result.headers)):
                cors_candidates.append(result.url)
            for ep in page_eps:
                joined = candidate_from_endpoint(result.url, ep.endpoint)
                if is_api_path(ep.endpoint) or is_api_path(joined):
                    cors_candidates.append(joined)
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
            next_links.extend(result.discovered_urls)

            for link in next_links:
                if not same_origin(link, origin_url):
                    continue
                if canonical_key(link) in seen:
                    continue
                if is_pagination_trap(link, family_counts):
                    continue
                queue.append((link, depth + 1))

        extra_pages, extra_findings = probe_paths(
            origin_url,
            self.http,
            seen,
            remaining=self.max_pages - len(pages),
            deadline=(t0 + self.max_time) if self.max_time is not None else None,
        )
        pages.extend(extra_pages)
        findings.extend(extra_findings)
        discovered = [urlparse(p.url).path for p in pages]
        mut_pages, mut_findings = probe_mutations(origin_url, self.http, seen, discovered)
        pages.extend(mut_pages)
        findings.extend(mut_findings)
        findings.extend(probe_cors(origin_url, self.http, cors_candidates))

        if not self._budget_hit(t0, len(pages)):
            gql_pages, gql_findings, gql_eps = probe_graphql(origin_url, self.http, seen)
            pages.extend(gql_pages)
            findings.extend(gql_findings)
            js_endpoints.extend(gql_eps)

        findings.extend(ghost_route_findings(origin_url, pages, js_endpoints))

        if stopped == "complete":
            later = self._budget_hit(t0, len(pages))
            if later:
                stopped = later

        finished = _now()
        requests = getattr(self.http, "requests", 0)
        if self.fetcher is not self.http:
            requests += getattr(self.fetcher, "requests", 0)
        return CrawlResult(
            target=seed,
            scan_started_at=started,
            scan_finished_at=finished,
            crawler=CrawlerInfo(name="shroodler-py", version=__version__, mode=self.mode),
            pages=pages,
            findings=_dedupe_findings(findings),
            js_endpoints=_dedupe_endpoints(js_endpoints),
            stats=CrawlStats(
                pages_crawled=len(pages),
                requests=requests,
                elapsed_ms=int((monotonic() - t0) * 1000),
                stopped_reason=stopped,
            ),
        )

    def _enqueue_sitemap_seeds(
        self,
        seed: str,
        origin_url: str,
        robots_body: str,
        queue: deque[tuple[str, int]],
        seen: set[str],
    ) -> None:
        pending: list[str] = []
        queued_sitemaps: set[str] = set()

        def offer_sitemap(raw: str, base: str) -> None:
            resolved = normalize_url(base, raw)
            if not resolved or not same_origin(resolved, origin_url):
                return
            key = canonical_key(resolved)
            if key in queued_sitemaps:
                return
            queued_sitemaps.add(key)
            pending.append(resolved)

        for sm in parse_robots_sitemaps(robots_body):
            offer_sitemap(sm, seed)
        offer_sitemap("/sitemap.xml", seed)

        fetched = 0
        while pending and fetched < 10:
            sm_url = pending.pop(0)
            if not same_origin(sm_url, origin_url):
                continue
            fetched += 1
            res = self.http.fetch(sm_url)
            if res.status_code != 200 or not res.text:
                continue
            seen.add(canonical_key(sm_url))
            url_locs, nested = parse_sitemap_xml(res.text)
            for loc in nested:
                offer_sitemap(loc, sm_url)
            for loc in url_locs:
                page = normalize_url(sm_url, loc)
                if page and same_origin(page, origin_url):
                    queue.append((page, 0))

    def _prime_auth(self, seed: str) -> None:
        specs: list[CookieSpec] = []
        specs.extend(parse_cookie_pairs(self._cookie_args))
        if self._cookie_jar:
            specs.extend(load_cookie_jar(self._cookie_jar))
        if self._storage_state:
            specs.extend(load_storage_state(self._storage_state))
        if specs:
            apply_httpx_cookies(self.http.client, specs, seed)
            setter = getattr(self.fetcher, "set_cookies", None)
            if setter is not None:
                setter(specs, seed)
        if not self._login_recipe_path:
            return
        recipe = resolve_recipe_url(load_login_recipe(self._login_recipe_path), seed)
        if self.mode == "headless":
            login_fn = getattr(self.fetcher, "login", None)
            if login_fn is not None:
                login_fn(recipe)
                return
        run_login_httpx(self.http.client, recipe)

    def _budget_hit(self, t0: float, n_pages: int) -> str | None:
        if self.max_time is not None and (monotonic() - t0) >= self.max_time:
            return "max-time"
        if n_pages >= self.max_pages:
            return "max-pages"
        return None

    def _fetch_with_retries(self, url: str, t0: float | None = None) -> FetchResult:
        delay = 0.2
        last = self.fetcher.fetch(url)
        for _ in range(self.rate_limit_retries):
            if last.status_code != 429:
                return last
            if t0 is not None and self._budget_hit(t0, 0) == "max-time":
                return last
            retry_after = last.headers.get("Retry-After") or last.headers.get("retry-after")
            wait = delay
            if retry_after:
                try:
                    wait = min(float(retry_after), 5.0)
                except ValueError:
                    wait = delay
            if t0 is not None and self.max_time is not None:
                remaining = self.max_time - (monotonic() - t0)
                if remaining <= 0:
                    return last
                wait = min(wait, remaining)
            sleep(wait)
            delay = min(delay * 2, 2.0)
            last = self.fetcher.fetch(url)
        return last

    def _page_from_result(
        self, result: FetchResult
    ) -> tuple[Page, list[Finding], list[JsEndpoint]]:
        page, findings, endpoints = page_from_fetch(result)
        if result.text and (
            "javascript" in _content_type(result.headers) or result.url.endswith(".js")
        ):
            map_eps, map_findings = self._from_source_map(result.url, result.text)
            endpoints = list(endpoints) + map_eps
            findings = list(findings) + map_findings
        return page, findings, endpoints

    def _from_source_map(self, js_url: str, js_text: str) -> tuple[list[JsEndpoint], list[Finding]]:
        spec = source_mapping_url(js_text)
        if not spec:
            return [], []
        raw: str | bytes | None = None
        if spec.startswith("data:"):
            decoded = decode_data_url(spec)
            if not decoded:
                return [], []
            raw = decoded
        else:
            map_url = urljoin(js_url, spec)
            if not same_origin(map_url, js_url):
                return [], []
            fetched = self.http.fetch(map_url)
            if fetched.status_code != 200 or not fetched.text:
                return [], []
            raw = fetched.text
        obj = parse_source_map(raw)
        if not obj:
            return [], []
        return extract_from_source_map(js_url, obj)


def page_from_fetch(result: FetchResult) -> tuple[Page, list[Finding], list[JsEndpoint]]:
    js_files: list[str] = []
    forms = []
    form_findings: list[Finding] = []
    endpoints: list[JsEndpoint] = []
    ep_findings: list[Finding] = []
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
        if "javascript" in ctype or result.url.endswith(".js"):
            endpoints, ep_findings = extract_js_endpoints(result.url, result.text)
    cookies, cookie_findings = extract_cookies(result.set_cookies, result.url)
    headers, header_findings = extract_headers(result.headers, result.url)
    verbose_findings = extract_verbose_errors(result.text, result.url, result.status_code)
    secret_findings = scan_text(result.text, result.url)
    page = Page(
        url=result.url,
        status_code=result.status_code,
        forms=forms,
        params=query_param_names(result.url),
        cookies=cookies,
        headers=headers,
        js_files=js_files,
    )
    all_f = (
        form_findings
        + cookie_findings
        + header_findings
        + verbose_findings
        + secret_findings
        + ep_findings
    )
    return page, all_f, endpoints


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


def _dedupe_endpoints(items: list[JsEndpoint]) -> list[JsEndpoint]:
    out: list[JsEndpoint] = []
    seen: set[tuple[str, str]] = set()
    for item in items:
        key = (item.source, item.endpoint)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def crawl_url(url: str, **kwargs) -> CrawlResult:
    c = Crawler(**kwargs)
    try:
        return c.crawl(url)
    finally:
        c.close()
