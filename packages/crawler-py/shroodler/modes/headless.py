from __future__ import annotations

import json
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

from shroodler.auth import CookieSpec, LoginRecipe, playwright_cookie_payload
from shroodler.modes.static import FetchResult, _decode_body
from shroodler.robots import DEFAULT_UA
from shroodler.urls import same_origin

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

    def login(self, recipe: LoginRecipe) -> None:
        if recipe.content_type == "json":
            # JSON-API login (e.g. eToro's /api/sts/v2/login) has no HTML form.
            # The target site may be behind a WAF/bot-challenge (e.g. Cloudflare)
            # that requires a real browser session before an API call is accepted.
            # Strategy:
            #   1. Navigate to the login page with Playwright, wait for networkidle
            #      so any JS challenge (Cloudflare Turnstile, DataDome, etc.) is
            #      solved and clearance cookies are in the browser's jar.
            #   2. Execute the JSON POST via fetch() from INSIDE that page so it
            #      carries the challenge cookies and looks like a browser request.
            #      credentials:"include" ensures Set-Cookie from the login response
            #      is committed to the shared browser context cookie jar.
            parsed = urlparse(recipe.url)
            origin_url = f"{parsed.scheme}://{parsed.netloc}"
            # Guess the login page: either the recipe URL's path stripped to
            # /login, or just the origin if the URL is already the API endpoint.
            login_page_url = origin_url + "/login"
            page = self._context.new_page()
            try:
                # Load the login page so WAF/bot-detection challenges run and
                # clearance cookies are set.  Use "load" (not "networkidle") —
                # DataDome/Cloudflare keep polling the network indefinitely, so
                # networkidle never fires.  A brief extra wait lets the JS
                # challenge complete before we make the API call.
                page.goto(login_page_url, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_timeout(6000)
                # POST via fetch() inside the live browser context.
                result = page.evaluate(
                    """
                    async ([url, body]) => {
                        const r = await fetch(url, {
                            method: "POST",
                            headers: {"Content-Type": "application/json"},
                            body: JSON.stringify(body),
                            credentials: "include",
                        });
                        return {ok: r.ok, status: r.status};
                    }
                    """,
                    [recipe.url, dict(recipe.fields)],
                )
            finally:
                page.close()
            if not result.get("ok"):
                raise RuntimeError(
                    f"JSON login to {recipe.url} failed: HTTP {result.get('status')}"
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

    def fetch(self, url: str) -> FetchResult:
        self.requests += 1
        page = self._context.new_page()
        try:
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
                )
            discovered = self._enumerate_routes(page, url)
            body = page.content().encode("utf-8")
            set_cookies = []
            for c in self._context.cookies():
                parts = [f"{c['name']}={c['value']}"]
                if c.get("secure"):
                    parts.append("Secure")
                if c.get("httpOnly"):
                    parts.append("HttpOnly")
                if c.get("sameSite"):
                    parts.append(f"SameSite={c['sameSite']}")
                set_cookies.append("; ".join(parts))
            return FetchResult(
                url=page.url,
                status_code=status,
                headers={k.title(): v for k, v in headers.items()},
                body=body,
                text=_decode_body(body, headers.get("content-type", "text/html")),
                redirect_to=None,
                set_cookies=set_cookies,
                discovered_urls=discovered,
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
            )
        finally:
            page.close()

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
