from __future__ import annotations

from dataclasses import dataclass

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


def _decode_body(body: bytes, content_type: str) -> str:
    charset = "utf-8"
    if "charset=" in content_type.lower():
        charset = content_type.split("charset=", 1)[1].split(";")[0].strip().strip("\"'")
    try:
        return body.decode(charset)
    except (LookupError, UnicodeDecodeError):
        return body.decode("utf-8", errors="replace")


class StaticFetcher:
    def __init__(self, timeout: float = 10.0, user_agent: str = DEFAULT_UA) -> None:
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": user_agent},
        )
        self.user_agent = user_agent

    def close(self) -> None:
        self.client.close()

    def fetch(self, url: str) -> FetchResult:
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
        )
