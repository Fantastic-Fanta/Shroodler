from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.request import Request, urlopen

from shroodler.crawler import crawl_url
from shroodler.sessions import cookie_header, ingest_sessions, load_sessions, seed_urls
from shroodler.validate import validate_crawl


def _session(
    url: str,
    *,
    method: str = "GET",
    status: int = 200,
    headers: dict | None = None,
    body: str = "",
    req_headers: dict | None = None,
    req_body: str = "",
    response: dict | None | bool = True,
) -> dict:
    sess = {
        "id": "s1",
        "started_at": "2026-09-01T00:00:00Z",
        "request": {
            "method": method,
            "url": url,
            "headers": req_headers or {},
            "body": {"encoding": "utf8", "content": req_body},
        },
        "response": None,
    }
    if response is False:
        sess["response"] = None
    elif response is True:
        sess["response"] = {
            "status_code": status,
            "headers": headers or {"Content-Type": "text/html"},
            "body": {"encoding": "utf8", "content": body},
        }
    return sess


def _write_jsonl(path, sessions: list[dict]) -> None:
    path.write_text("".join(json.dumps(s) + "\n" for s in sessions), encoding="utf-8")


class _TinyProxy(ThreadingHTTPServer):
    def __init__(self):
        self.hits = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args) -> None:
                return

            def do_GET(self) -> None:
                outer.hits += 1
                req = Request(self.path, method="GET")
                for k, v in self.headers.items():
                    if k.lower() not in {"host", "proxy-connection"}:
                        req.add_header(k, v)
                with urlopen(req, timeout=5) as resp:
                    payload = resp.read()
                    self.send_response(resp.status)
                    for k, v in resp.headers.items():
                        if k.lower() in {"transfer-encoding", "content-length"}:
                            continue
                        self.send_header(k, v)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

        super().__init__(("127.0.0.1", 0), Handler)
        self._thread = Thread(target=self.serve_forever, daemon=True)

    def start(self) -> str:
        self._thread.start()
        host, port = self.server_address[:2]
        return f"http://{host}:{port}"

    def stop(self) -> None:
        self.shutdown()
        self.server_close()


def test_crawl_through_proxy(fx):
    fx.html("/", "<html>via proxy</html>")
    proxy = _TinyProxy()
    url = proxy.start()
    try:
        result = crawl_url(fx.origin + "/", depth=0, proxy=url, ignore_robots=True)
    finally:
        proxy.stop()
    assert proxy.hits >= 1
    assert result.pages[0].status_code == 200


def test_seed_visits_unlinked_path(fx):
    fx.html("/", "home")
    fx.html("/hidden", "secret")
    result = crawl_url(
        fx.origin + "/",
        depth=0,
        extra_seeds=[fx.origin + "/hidden"],
        ignore_robots=True,
    )
    urls = {p.url for p in result.pages}
    assert any(u.endswith("/hidden") for u in urls)


def test_cookie_handoff(fx):
    seen: list[str] = []

    def gated(inc):
        seen.append(inc.cookies)
        return 200, {"Content-Type": "text/html"}, b"ok"

    fx.on("GET", "/", gated)
    crawl_url(fx.origin + "/", depth=0, cookies=["sid=from-proxy"], ignore_robots=True)
    assert any("sid=from-proxy" in c for c in seen)


def test_ingest_sessions_findings(tmp_path, fx):
    html = '<form action="/login" method="post"><input name="username"></form>'
    sess = _session(
        fx.origin + "/login",
        headers={"Content-Type": "text/html", "Set-Cookie": "sid=abc; HttpOnly"},
        body=html,
    )
    p = tmp_path / "s.jsonl"
    _write_jsonl(p, [sess])
    result = ingest_sessions(p, target=fx.origin)
    validate_crawl(result.to_dict())
    assert result.crawler.mode == "ingest"
    assert any("/login" in pg.url for pg in result.pages)
    assert any(f.id == "insecure-cookie" for f in result.findings)
    assert result.pages[0].forms


def test_ingest_request_secret_and_skip_null(tmp_path):
    origin = "http://127.0.0.1:9"
    secret = _session(
        origin + "/api",
        method="POST",
        req_body="token=AKIAIOSFODNN7EXAMPLE",
        body="{}",
        headers={"Content-Type": "application/json"},
    )
    dropped = _session(origin + "/gone", response=False)
    p = tmp_path / "s.jsonl"
    _write_jsonl(p, [secret, dropped])
    result = ingest_sessions(p, target=origin)
    assert any(f.category == "secret" for f in result.findings)
    assert not any("/gone" in pg.url for pg in result.pages)


def test_cookies_and_seeds_origin_filter(tmp_path):
    a = "http://127.0.0.1:8081/login"
    b = "http://127.0.0.1:8082/other"
    sessions = [
        _session(a, headers={"Set-Cookie": "sid=one"}, body="a"),
        _session(a, headers={"Set-Cookie": "sid=two"}, body="a2"),
        _session(b, headers={"Set-Cookie": "other=x"}, body="b"),
    ]
    p = tmp_path / "s.jsonl"
    _write_jsonl(p, sessions)
    loaded = load_sessions(p)
    hdr = cookie_header(loaded, "http://127.0.0.1:8081/")
    assert "sid=two" in hdr
    assert "other=" not in hdr
    seeds = seed_urls(loaded, "http://127.0.0.1:8081/")
    assert any("/login" in u for u in seeds)
    assert not any(":8082" in u for u in seeds)


def test_cli_ingest_and_fusion_flags(fx, tmp_path):
    from shroodler.cli import main

    html = "<html><body>ok</body></html>"
    sess = _session(fx.origin + "/", headers={"Content-Type": "text/html"}, body=html)
    p = tmp_path / "s.jsonl"
    _write_jsonl(p, [sess])
    out = tmp_path / "ing.json"
    try:
        main(["ingest-sessions", str(p), "--target", fx.origin, "--output", str(out)])
    except SystemExit as ex:
        assert ex.code == 0
    assert "ingest" in out.read_text()
