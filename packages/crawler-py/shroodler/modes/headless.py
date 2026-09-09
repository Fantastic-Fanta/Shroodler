from __future__ import annotations

from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

from shroodler.auth import CookieSpec, LoginRecipe, playwright_cookie_payload
from shroodler.modes.static import FetchResult, _decode_body
from shroodler.robots import DEFAULT_UA
from shroodler.urls import same_origin
from shroodler.webgoat import (
    captured_endpoint,
    is_webgoat_url,
    lesson_nav_urls,
    parse_lesson_menu,
    start_mvc_url,
    webgoat_prefix,
)

_HISTORY_HOOK = """
() => {
  window.__shroodlerRoutes = window.__shroodlerRoutes || [];
  const remember = () => window.__shroodlerRoutes.push(location.href);
  const origPush = history.pushState.bind(history);
  const origReplace = history.replaceState.bind(history);
  history.pushState = function (...args) {
    origPush(...args);
    remember();
  };
  history.replaceState = function (...args) {
    origReplace(...args);
    remember();
  };
  window.addEventListener("hashchange", remember);
}
"""

_CLICK_CANDIDATES = """
() => {
  const nodes = document.querySelectorAll("a[href], button, [role=button]");
  let n = 0;
  for (const el of nodes) {
    const style = getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden" || el.hidden) continue;
    if (el.closest("[hidden], .honeypot, [aria-hidden='true']")) continue;
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (type === "submit" || type === "reset") continue;
    if (el.tagName === "BUTTON" && type !== "button" && el.closest("form")) continue;
    n += 1;
  }
  return n;
}
"""

_CLICK_AT = """
(idx) => {
  const nodes = [...document.querySelectorAll("a[href], button, [role=button]")];
  const filtered = [];
  for (const el of nodes) {
    const style = getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden" || el.hidden) continue;
    if (el.closest("[hidden], .honeypot, [aria-hidden='true']")) continue;
    const type = (el.getAttribute("type") || "").toLowerCase();
    if (type === "submit" || type === "reset") continue;
    if (el.tagName === "BUTTON" && type !== "button" && el.closest("form")) continue;
    filtered.push(el);
  }
  const el = filtered[idx];
  if (!el) return false;
  el.click();
  return true;
}
"""


class HeadlessFetcher:
    def __init__(
        self,
        user_agent: str = DEFAULT_UA,
        max_clicks: int = 8,
        proxy: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.user_agent = user_agent
        self.max_clicks = max_clicks
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=True)
        ctx: dict = {"user_agent": user_agent}
        if proxy:
            ctx["proxy"] = {"server": proxy}
        if extra_headers:
            ctx["extra_http_headers"] = extra_headers
        self._extra_headers = dict(extra_headers or {})
        self._context = self._browser.new_context(**ctx)
        self.requests = 0

    def close(self) -> None:
        self._context.close()
        self._browser.close()
        self._pw.stop()

    def set_cookies(self, cookies: list[CookieSpec], page_url: str) -> None:
        payload = playwright_cookie_payload(cookies, page_url)
        if payload:
            self._context.add_cookies(payload)

    def set_extra_headers(self, headers: dict[str, str]) -> None:
        merged = dict(self._extra_headers)
        merged.update(headers)
        self._extra_headers = merged
        self._context.set_extra_http_headers(merged)

    def set_local_storage(self, origin_url: str, items: dict[str, str]) -> None:
        """Inject key/value pairs into localStorage for the given origin.

        Navigates to the origin first (required — localStorage is per-origin
        and cannot be written before the page has loaded), then evaluates
        localStorage.setItem for each pair.
        """
        if not items:
            return
        page = self._context.new_page()
        try:
            page.goto(origin_url, wait_until="domcontentloaded", timeout=20000)
            page.wait_for_timeout(1000)
            for key, value in items.items():
                page.evaluate("([k, v]) => localStorage.setItem(k, v)", [key, value])
        finally:
            page.close()

    def login(self, recipe: LoginRecipe) -> None:
        # localStorage injection: works independently of (or alongside) form login.
        # Used for sites that store Bearer tokens in localStorage (e.g. eToro),
        # bypassing bot-detection that blocks the login form in headless browsers.
        if recipe.local_storage:
            parsed = urlparse(recipe.url)
            origin_url = f"{parsed.scheme}://{parsed.netloc}"
            self.set_local_storage(origin_url, recipe.local_storage)
            if recipe.protected_url:
                self._verify_auth(
                    recipe.protected_url,
                    origin_url + "/login",
                    auth_marker=recipe.auth_marker,
                )
            return

        if recipe.content_type == "json":
            # JSON-API login recipe: the recipe URL points to a JSON API
            # endpoint, but WAF/bot-detection (DataDome, Cloudflare, etc.)
            # blocks direct API calls.  Instead navigate to the site's visual
            # login page and fill the form — the browser navigates through the
            # challenge naturally.  Use the recipe field names as selectors
            # first (many sites do use name= on their inputs), then fall back to
            # semantic type= selectors for username/password.
            parsed = urlparse(recipe.url)
            origin_url = f"{parsed.scheme}://{parsed.netloc}"
            login_page_url = origin_url + "/login"
            page = self._context.new_page()
            try:
                page.goto(login_page_url, wait_until="domcontentloaded", timeout=30000)
                # Give React/Next.js time to render the form.
                page.wait_for_timeout(3000)
                for name, value in recipe.fields.items():
                    loc = page.locator(f'[name="{name}"]')
                    if loc.count():
                        loc.first.fill(value)
                        continue
                    # Fallback: match by input type for common credential fields.
                    nl = name.lower()
                    if any(k in nl for k in ("user", "email", "login", "account")):
                        fb = page.locator('input[type="email"], input[type="text"][autocomplete="username"]')
                        if fb.count():
                            fb.first.fill(value)
                    elif "pass" in nl:
                        fb = page.locator('input[type="password"]')
                        if fb.count():
                            fb.first.fill(value)
                submit = page.locator('button[type="submit"], input[type="submit"], form button')
                if submit.count():
                    submit.first.click(timeout=5000)
                else:
                    page.keyboard.press("Enter")
                page.wait_for_load_state("domcontentloaded", timeout=20000)
            finally:
                page.close()
            if recipe.protected_url:
                self._verify_auth(
                    recipe.protected_url,
                    login_page_url,
                    auth_marker=recipe.auth_marker,
                )
            return

        page = self._context.new_page()
        try:
            page.goto(recipe.url, wait_until="networkidle", timeout=15000)
            for name, value in recipe.fields.items():
                loc = page.locator(f'[name="{name}"]')
                if loc.count():
                    loc.first.fill(value)
            submit = page.locator('button[type="submit"], input[type="submit"], form button')
            if submit.count():
                submit.first.click(timeout=5000)
            else:
                page.keyboard.press("Enter")
            page.wait_for_load_state("networkidle", timeout=15000)
        finally:
            page.close()

    def _verify_auth(
        self,
        protected_url: str,
        login_url: str,
        auth_marker: str | None = None,
    ) -> None:
        """Navigate to protected_url and raise if auth appears to have failed.

        Two checks are performed:
        1. URL redirect: if the final URL contains a login-path indicator the
           session was never established.
        2. Content marker: if auth_marker is set, the rendered page body must
           contain that string — this handles SPAs that return HTTP 200 even
           when unauthenticated (e.g. a login overlay rendered by JavaScript).
        """
        page = self._context.new_page()
        try:
            page.goto(protected_url, wait_until="domcontentloaded", timeout=15000)
            # Wait for SPA to finish rendering (covers React/Next.js hydration).
            page.wait_for_timeout(3000)
            final = page.url
            body = page.content() if auth_marker else ""
        finally:
            page.close()
        login_indicators = ("/login", "/signin", "/sign-in", "/auth/login")
        if any(ind in final.lower() for ind in login_indicators):
            raise RuntimeError(
                f"Headless login failed: navigating to {protected_url!r} "
                f"redirected to {final!r} — check credentials or form selectors"
            )
        if auth_marker and auth_marker not in body:
            raise RuntimeError(
                f"Headless login failed: {protected_url!r} loaded (no redirect) "
                f"but auth marker {auth_marker!r} not found in rendered body — "
                f"the session was not established (SPA login overlay still active?)"
            )

    def fetch(self, url: str) -> FetchResult:
        self.requests += 1
        page = self._context.new_page()
        captured: list[dict] = []
        try:
            page.on("request", lambda req: self._record_request(req, captured))
            page.add_init_script(_HISTORY_HOOK)
            response = page.goto(url, wait_until="networkidle", timeout=15000)
            status = response.status if response else 0
            headers = dict(response.headers) if response else {}
            if not same_origin(page.url, url):
                # The page navigated itself off-origin after load (client-side
                # SSO/redirect JS, not an HTTP 30x we could see from outside).
                # Treat like any other off-origin redirect target: record that
                # it happened, but never extract content/links from a host
                # that's out of scope, and never queue it for a follow-up
                # fetch.
                return FetchResult(
                    url=url,
                    status_code=status,
                    headers={k.title(): v for k, v in headers.items()},
                    body=b"",
                    text="",
                    redirect_to=page.url,
                    set_cookies=[],
                    discovered_urls=[],
                    xhr_requests=list(captured),
                )
            discovered = self._enumerate_routes(page, url)
            return self._result_from_page(
                page,
                url,
                response,
                discovered=discovered,
                xhr_requests=captured,
                click_routes=False,
            )
        except Exception as exc:  # playwright timeout / crash
            return FetchResult(
                url=url,
                status_code=0,
                headers={},
                body=b"",
                text="",
                redirect_to=None,
                error=str(exc),
                xhr_requests=list(captured),
            )
        finally:
            page.close()

    def seed_webgoat_lessons(
        self, start_url: str, max_lessons: int = 150
    ) -> list[FetchResult]:
        """Open each WebGoat lesson as the current browser session (owner).

        Hash routes on start.mvc never appear as distinct URLs in the BFS
        queue, so ProbeAction would otherwise see only the shell page. This
        walks ``lessonmenu.mvc`` (and DOM fallbacks), navigates each lesson,
        and returns one FetchResult per lesson with intercepted XHR pairs.
        """
        if not is_webgoat_url(start_url):
            return []
        page = self._context.new_page()
        captured: list[dict] = []
        results: list[FetchResult] = []
        try:
            page.on("request", lambda req: self._record_request(req, captured))
            page.add_init_script(_HISTORY_HOOK)
            start = start_mvc_url(start_url)
            self.requests += 1
            response = page.goto(start, wait_until="networkidle", timeout=20000)
            page.wait_for_timeout(400)
            menu = self._lesson_menu_json(page)
            links = parse_lesson_menu(menu)
            try:
                hrefs = page.evaluate(
                    """() => Array.from(document.querySelectorAll(
                      '#menu a[href], .page-sidebar a[href], nav a[href], a[href^="#"]'
                    )).map(a => a.getAttribute('href') || '')"""
                )
            except Exception:
                hrefs = []
            for href in hrefs or []:
                if href and href not in links:
                    links.append(str(href))
            nav_urls = lesson_nav_urls(webgoat_prefix(start_url), links)
            start_xhr = list(captured)
            captured.clear()
            results.append(
                self._result_from_page(
                    page,
                    start,
                    response,
                    discovered=nav_urls,
                    xhr_requests=start_xhr,
                    click_routes=False,
                )
            )
            for lesson_url in nav_urls[: max(0, int(max_lessons))]:
                captured.clear()
                self.requests += 1
                try:
                    lesson_resp = page.goto(
                        lesson_url, wait_until="networkidle", timeout=15000
                    )
                    page.wait_for_timeout(300)
                except Exception as exc:  # playwright timeout / crash
                    results.append(
                        FetchResult(
                            url=lesson_url,
                            status_code=0,
                            headers={},
                            body=b"",
                            text="",
                            redirect_to=None,
                            error=str(exc),
                            xhr_requests=list(captured),
                        )
                    )
                    continue
                results.append(
                    self._result_from_page(
                        page,
                        lesson_url,
                        lesson_resp,
                        discovered=[],
                        xhr_requests=list(captured),
                        click_routes=False,
                    )
                )
            return results
        except Exception as exc:  # playwright timeout / crash
            if not results:
                return [
                    FetchResult(
                        url=start_url,
                        status_code=0,
                        headers={},
                        body=b"",
                        text="",
                        redirect_to=None,
                        error=str(exc),
                    )
                ]
            return results
        finally:
            page.close()

    def _lesson_menu_json(self, page) -> object:
        try:
            return page.evaluate(
                """async () => {
                  const r = await fetch('service/lessonmenu.mvc', {
                    credentials: 'same-origin',
                  });
                  const text = await r.text();
                  try { return JSON.parse(text); } catch { return null; }
                }"""
            )
        except Exception:
            return None

    def _record_request(self, request, bucket: list[dict]) -> None:
        try:
            headers = request.headers or {}
            rec = captured_endpoint(
                request.url,
                request.method,
                post_data=request.post_data,
                content_type=str(headers.get("content-type") or ""),
                resource_type=str(request.resource_type or "xhr"),
            )
        except Exception:
            return
        if rec:
            bucket.append(rec)

    def _cookie_header_list(self) -> list[str]:
        set_cookies: list[str] = []
        for c in self._context.cookies():
            parts = [f"{c['name']}={c['value']}"]
            if c.get("secure"):
                parts.append("Secure")
            if c.get("httpOnly"):
                parts.append("HttpOnly")
            if c.get("sameSite"):
                parts.append(f"SameSite={c['sameSite']}")
            set_cookies.append("; ".join(parts))
        return set_cookies

    def _result_from_page(
        self,
        page,
        requested_url: str,
        response,
        *,
        discovered: list[str],
        xhr_requests: list[dict],
        click_routes: bool = True,
    ) -> FetchResult:
        status = response.status if response else 0
        headers = dict(response.headers) if response else {}
        if not same_origin(page.url, requested_url):
            return FetchResult(
                url=requested_url,
                status_code=status,
                headers={k.title(): v for k, v in headers.items()},
                body=b"",
                text="",
                redirect_to=page.url,
                set_cookies=[],
                discovered_urls=[],
                xhr_requests=list(xhr_requests),
            )
        routes = list(discovered)
        if click_routes:
            routes.extend(self._enumerate_routes(page, requested_url))
        # Preserve insertion order, drop duplicates.
        seen: set[str] = set()
        unique_routes: list[str] = []
        for item in routes:
            if item in seen:
                continue
            seen.add(item)
            unique_routes.append(item)
        body = page.content().encode("utf-8")
        return FetchResult(
            url=page.url,
            status_code=status or 200,
            headers={k.title(): v for k, v in headers.items()},
            body=body,
            text=_decode_body(body, headers.get("content-type", "text/html")),
            redirect_to=None,
            set_cookies=self._cookie_header_list(),
            discovered_urls=unique_routes,
            xhr_requests=list(xhr_requests),
        )

    def _enumerate_routes(self, page, origin_url: str) -> list[str]:
        found: list[str] = []
        seen: set[str] = set()

        def remember(raw: str | None) -> None:
            if not raw:
                return
            if not same_origin(raw, origin_url):
                return
            if raw in seen:
                return
            seen.add(raw)
            found.append(raw)

        remember(page.url)
        try:
            for href in page.evaluate(
                "() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href)"
            ):
                remember(href)
        except Exception:
            pass

        original = page.url
        n = 0
        try:
            n = int(page.evaluate(_CLICK_CANDIDATES) or 0)
        except Exception:
            n = 0
        n = min(n, self.max_clicks)
        for i in range(n):
            try:
                if page.url != original:
                    page.goto(original, wait_until="domcontentloaded", timeout=8000)
                clicked = page.evaluate(_CLICK_AT, i)
                if not clicked:
                    continue
                page.wait_for_timeout(200)
                remember(page.url)
                for extra in page.evaluate("() => window.__shroodlerRoutes || []"):
                    remember(extra)
            except Exception:
                continue
        if page.url != original:
            try:
                page.goto(original, wait_until="domcontentloaded", timeout=8000)
            except Exception:
                pass
        return [u for u in found if u.rstrip("/") != original.rstrip("/")]
