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


def test_ingest_har_builds_pages_from_captured_bodies(fx, tmp_path):
    from shroodler.cli import main
    from shroodler.validate import validate_crawl

    html = "<html><body><form action='/login' method='post'><input name='q'></form></body></html>"
    har = {
        "log": {
            "creator": {"name": "Chrome", "version": "1"},
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": fx.origin + "/",
                        "headers": [{"name": "Cookie", "value": "sid=abc"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "text/html"}],
                        "content": {"mimeType": "text/html", "text": html},
                    },
                }
            ],
        }
    }
    har_path = tmp_path / "cap.har"
    har_path.write_text(json.dumps(har), encoding="utf-8")
    out = tmp_path / "from-har.json"
    try:
        main(["ingest-har", str(har_path), "--target", fx.origin, "--output", str(out)])
    except SystemExit as ex:
        assert ex.code == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    validate_crawl(doc)
    assert doc["crawler"]["mode"] == "ingest"
    assert any(p["url"].rstrip("/") == fx.origin.rstrip("/") for p in doc["pages"])
    assert any(p.get("forms") for p in doc["pages"])


def test_from_capture_skips_captured_url_and_crawls_followup(tmp_path, fx):
    fx.html("/", "<html>already captured</html>")
    fx.html("/hidden", "<html>from capture link</html>")
    sess = _session(
        fx.origin + "/",
        body='<a href="/hidden">x</a>',
        headers={"Content-Type": "text/html"},
    )
    path = tmp_path / "cap.jsonl"
    path.write_text(json.dumps(sess) + "\n", encoding="utf-8")
    result = crawl_url(
        fx.origin + "/",
        depth=0,
        ignore_robots=True,
        no_sitemap=True,
        from_capture=str(path),
    )
    urls = {p.url.rstrip("/") for p in result.pages}
    assert fx.origin.rstrip("/") in urls or (fx.origin + "/") in {p.url for p in result.pages}
    assert any(p.url.endswith("/hidden") for p in result.pages)
    # captured home page was not re-fetched
    assert ("GET", "/") not in fx.calls


def test_from_capture_skips_robots_sitemap_openapi(tmp_path, fx):
    fx.html("/", "<html>captured</html>")
    fx.html("/robots.txt", "User-agent: *\nAllow: /\nSitemap: /sitemap.xml")
    fx.html("/sitemap.xml", '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>')
    fx.route(
        "/openapi.json",
        lambda _p: (200, {"Content-Type": "application/json"}, b'{"openapi":"3.0.0","paths":{}}'),
    )
    sess = _session(
        fx.origin + "/",
        body="<html>captured</html>",
        headers={"Content-Type": "text/html"},
    )
    path = tmp_path / "cap.jsonl"
    path.write_text(json.dumps(sess) + "\n", encoding="utf-8")
    crawl_url(fx.origin + "/", depth=0, from_capture=str(path))
    paths = {p for (_m, p) in fx.calls}
    assert "/robots.txt" not in paths
    assert "/openapi.json" not in paths
    assert "/sitemap.xml" not in paths


def test_from_capture_origin_mismatch_is_visible(tmp_path, fx):
    from urllib.parse import urlparse

    parsed = urlparse(fx.origin)
    other_host = "localhost" if (parsed.hostname or "") == "127.0.0.1" else "127.0.0.1"
    other = f"{parsed.scheme}://{other_host}:{parsed.port}/"
    sess = _session(other, body="<html>x</html>", headers={"Content-Type": "text/html"})
    path = tmp_path / "cap.jsonl"
    path.write_text(json.dumps(sess) + "\n", encoding="utf-8")
    result = crawl_url(
        fx.origin + "/",
        depth=0,
        ignore_robots=True,
        no_sitemap=True,
        from_capture=str(path),
    )
    assert any(f.id == "capture-no-same-origin-sessions" for f in result.findings)


def test_ingest_marks_findings_as_capture(tmp_path, fx):
    sess = _session(
        fx.origin + "/",
        body="AKIAIOSFODNN7EXAMPLE",
        headers={"Content-Type": "text/plain"},
        req_body="AKIAIOSFODNN7EXAMPLE",
    )
    path = tmp_path / "cap.jsonl"
    _write_jsonl(path, [sess])
    ingested = ingest_sessions(path, target=fx.origin)
    assert ingested.findings
    for f in ingested.findings:
        assert "source=capture" in (f.evidence or "")


def test_ingest_caps_pages(tmp_path, fx, monkeypatch):
    from shroodler import sessions as sessmod

    monkeypatch.setattr(sessmod, "MAX_INGEST_PAGES", 2)
    sessions = [
        _session(fx.origin + f"/p{i}", body="ok", headers={"Content-Type": "text/html"})
        for i in range(5)
    ]
    path = tmp_path / "cap.jsonl"
    _write_jsonl(path, sessions)
    ingested = ingest_sessions(path, target=fx.origin)
    assert len(ingested.pages) == 2


def test_followup_caps(tmp_path, fx, monkeypatch):
    from shroodler import sessions as sessmod
    from shroodler.sessions import followup_urls_from_capture

    monkeypatch.setattr(sessmod, "MAX_FOLLOWUPS", 3)
    links = "".join(f'<a href="/f{i}">x</a>' for i in range(20))
    sess = _session(
        fx.origin + "/",
        body=f"<html>{links}</html>",
        headers={"Content-Type": "text/html"},
    )
    path = tmp_path / "cap.jsonl"
    _write_jsonl(path, [sess])
    got = followup_urls_from_capture(path, fx.origin + "/", already=set())
    assert len(got) == 3


def test_collapsed_ingest_headers_keep_capture_source():
    from shroodler.crawler import _dedupe_findings
    from shroodler.models import Finding

    findings = [
        Finding(
            id="missing-csp",
            severity="low",
            category="header",
            url=f"http://127.0.0.1/p{i}",
            description="csp",
            evidence="source=capture",
        )
        for i in range(3)
    ]
    out = _dedupe_findings(findings)
    assert len(out) == 1
    assert "source=capture" in (out[0].evidence or "")


def test_react_query_key_is_queued_as_seed(fx):
    fx.html(
        "/",
        '<html><script>useQuery(["/api/folders/list"])</script></html>',
    )
    fx.route(
        "/api/folders/list",
        lambda _p: (200, {"Content-Type": "application/json"}, b'{"folders":[]}'),
    )
    result = crawl_url(fx.origin + "/", depth=1, ignore_robots=True, no_sitemap=True)
    assert any(p.url.endswith("/api/folders/list") for p in result.pages)
    assert any(f.id == "js-react-query-key" for f in result.findings)
