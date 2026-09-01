from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from shroodler.robots import DEFAULT_UA


@dataclass
class FetchResult:
    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    text: str
    redirect_to: str | None
    error: str | None = None
    set_cookies: list[str] = field(default_factory=list)
    discovered_urls: list[str] = field(default_factory=list)


def _decode_body(body: bytes, content_type: str) -> str:
    charset = "utf-8"
    if "charset=" in content_type.lower():
        charset = content_type.split("charset=", 1)[1].split(";")[0].strip().strip("\"'")
    try:
        return body.decode(charset)
    except (LookupError, UnicodeDecodeError):
        return body.decode("utf-8", errors="replace")


class StaticFetcher:
    def __init__(
        self,
        timeout: float = 10.0,
        user_agent: str = DEFAULT_UA,
        proxy: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        headers: dict[str, str] = {"User-Agent": user_agent}
        if extra_headers:
            headers.update(extra_headers)
        kwargs: dict = {
            "timeout": timeout,
            "follow_redirects": False,
            "headers": headers,
            "trust_env": False,
        }
        if proxy:
            kwargs["proxy"] = proxy
        self.client = httpx.Client(**kwargs)
        self.user_agent = user_agent
        self.proxy = proxy
        self.requests = 0

    def close(self) -> None:
        self.client.close()

    def fetch(self, url: str) -> FetchResult:
        self.requests += 1
        try:
            resp = self.client.get(url)
        except httpx.RequestError as exc:
            return FetchResult(
                url=url,
                status_code=0,
                headers={},
                body=b"",
                text="",
                redirect_to=None,
                error=str(exc),
            )
        headers = {k: v for k, v in resp.headers.items()}
        location = resp.headers.get("location")
        redirect_to = None
        if resp.status_code in {301, 302, 303, 307, 308} and location:
            redirect_to = location
        ctype = headers.get("content-type", "")
        text = _decode_body(resp.content, ctype)
        return FetchResult(
            url=str(resp.url) if resp.url else url,
            status_code=resp.status_code,
            headers=headers,
            body=resp.content,
            text=text,
            redirect_to=redirect_to,
            set_cookies=list(resp.headers.get_list("set-cookie")),
        )
