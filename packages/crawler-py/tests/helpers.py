from __future__ import annotations

from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlparse

Response = tuple[int, dict[str, str], bytes]


class FixtureServer:
    def __init__(self) -> None:
        self._routes: dict[str, Callable[[str], Response]] = {}
        self._prefixes: list[tuple[str, Callable[[str], Response]]] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:
                return

            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                path = parsed.path
                handler = server._routes.get(path)
                if handler is None:
                    for prefix, h in server._prefixes:
                        if path.startswith(prefix):
                            handler = h
                            break
                if handler is None:
                    self.send_response(404)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"not found")
                    return
                status, headers, body = handler(self.path)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                if body:
                    self.wfile.write(body)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = Thread(target=self._httpd.serve_forever, daemon=True)

    def route(self, path: str, handler: Callable[[str], Response]) -> None:
        self._routes[path] = handler

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
