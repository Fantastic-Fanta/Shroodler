from __future__ import annotations

from playwright.sync_api import sync_playwright

from shroodler.modes.static import FetchResult, _decode_body
from shroodler.robots import DEFAULT_UA


class HeadlessFetcher:
    def __init__(self, user_agent: str = DEFAULT_UA) -> None:
        self.user_agent = user_agent
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=True)
        self._context = self._browser.new_context(user_agent=user_agent)

    def close(self) -> None:
        self._context.close()
        self._browser.close()
        self._pw.stop()

    def fetch(self, url: str) -> FetchResult:
        page = self._context.new_page()
        try:
            response = page.goto(url, wait_until="networkidle", timeout=15000)
            status = response.status if response else 0
            headers = dict(response.headers) if response else {}
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
