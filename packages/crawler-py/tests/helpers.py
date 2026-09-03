from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlparse

Response = tuple[int, dict[str, str], bytes]


@dataclass
class Incoming:
    path: str
    method: str
    headers: dict[str, str]
    body: bytes = b""
    cookies: str = ""


class FixtureServer:
    def __init__(self) -> None:
        self._routes: dict[str, Callable[[str], Response]] = {}
        self._prefixes: list[tuple[str, Callable[[str], Response]]] = []
        self._on: dict[tuple[str, str], Callable[[Incoming], Response]] = {}
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:
                return

            def _incoming(self, method: str, body: bytes = b"") -> Incoming:
                parsed = urlparse(self.path)
                headers = {k: v for k, v in self.headers.items()}
                return Incoming(
                    path=parsed.path,
                    method=method,
                    headers=headers,
                    body=body,
                    cookies=self.headers.get("Cookie", ""),
                )

            def _dispatch(self, method: str, body: bytes = b"") -> None:
                parsed = urlparse(self.path)
                path = parsed.path
                on_handler = server._on.get((method, path))
                if on_handler is not None:
                    status, headers, payload = on_handler(self._incoming(method, body))
                    self._send(status, headers, payload)
                    return
                if method != "GET":
                    self._send(405, {"Content-Type": "text/plain"}, b"method not allowed")
                    return
                handler = server._routes.get(path)
                if handler is None:
                    for prefix, h in server._prefixes:
                        if path.startswith(prefix):
                            handler = h
                            break
                if handler is None:
                    self._send(404, {"Content-Type": "text/plain"}, b"not found")
                    return
                status, headers, payload = handler(self.path)
                self._send(status, headers, payload)

            def _send(self, status: int, headers: dict[str, str], body: bytes) -> None:
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def do_GET(self) -> None:
                self._dispatch("GET")

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                self._dispatch("POST", body)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = Thread(target=self._httpd.serve_forever, daemon=True)

    def route(self, path: str, handler: Callable[[str], Response]) -> None:
        self._routes[path] = handler

    def on(self, method: str, path: str, handler: Callable[[Incoming], Response]) -> None:
        self._on[(method.upper(), path)] = handler

    def prefix(self, prefix: str, handler: Callable[[str], Response]) -> None:
        self._prefixes.append((prefix, handler))

    def html(
        self,
        path: str,
        body: str,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        hdrs = {"Content-Type": "text/html; charset=utf-8"}
        if headers:
            hdrs.update(headers)
        payload = body.encode("utf-8")

        def handle(_req: str) -> Response:
            return status, hdrs, payload

        self.route(path, handle)

    @property
    def origin(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> str:
        self._thread.start()
        return self.origin

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
