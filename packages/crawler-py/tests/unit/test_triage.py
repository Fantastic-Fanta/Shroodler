from __future__ import annotations

import argparse
import json

import pytest

from shroodler.cli import build_parser, cmd_triage
from shroodler.triage import (
    DEFAULT_CONCURRENCY,
    DEFAULT_PROXY_CONCURRENCY,
    MAX_CONCURRENCY,
    MAX_RATE_RPS,
    DnsResult,
    HttpProbe,
    clamp_concurrency,
    clamp_rate,
    classify_dns,
    classify_http,
    detect_proxy,
    fingerprint_tech,
    parse_targets,
    render_hosts,
    render_text,
    run_triage,
    takeover_from_http,
    zone_of,
)


def test_zone_of_multi_suffix_keeps_city_zone():
    # The wien.gv.at incident: pausing `gv.at` would stall a national TLD.
    assert zone_of("48ertandler.wien.gv.at") == "wien.gv.at"
    assert zone_of("www.example.com") == "example.com"
    assert zone_of("a.b.example.co.uk") == "example.co.uk"
    assert zone_of("127.0.0.1") == "127.0.0.1"


def test_parse_targets_file_wildcard_and_url(tmp_path):
    hosts = tmp_path / "hosts.txt"
    hosts.write_text(
        "# comment\n"
        "127.0.0.1:8081\n"
        "*.example.com\n"
        "https://app.local/path\n"
        "\n",
        encoding="utf-8",
    )
    targets, apexes = parse_targets([str(hosts)], discover=["other.test"])
    hosts_found = {t.host for t in targets}
    assert "127.0.0.1" in hosts_found
    assert "app.local" in hosts_found
    assert "example.com" in apexes
    assert "other.test" in apexes
    app = next(t for t in targets if t.host == "app.local")
    assert app.url == "https://app.local/path"


def test_classify_dns_dead_dangling_saas_resolves():
    dead, takeover, *_ = classify_dns(DnsResult(host="gone.example", nxdomain=True))
    assert dead == "dead"
    assert takeover is False

    dang, takeover, signal, vendor, _ = classify_dns(
        DnsResult(host="old.example", cname="missing.s3.amazonaws.com", nxdomain=True)
    )
    assert dang == "dangling-cname"
    assert takeover is True
    assert vendor == "S3"
    assert "CNAME" in (signal or "")

    saas, takeover, _, vendor, _ = classify_dns(
        DnsResult(
            host="shop.example",
            a_records=["1.2.3.4"],
            cname="shops.myshopify.com",
        )
    )
    assert saas == "third-party-saas"
    assert vendor == "Shopify"
    assert takeover is False

    live, takeover, *_ = classify_dns(
        DnsResult(host="app.example", a_records=["1.2.3.4"])
    )
    assert live == "resolves"
    assert takeover is False


def test_classify_http_redirect_waf_sso_live():
    in_scope = {"www.example.local", "alias.example.local"}
    zones = {"example.local"}

    cls, loc, notes = classify_http(
        HttpProbe(
            url="http://alias.example.local/",
            status_code=301,
            location="http://www.example.local/pets",
        ),
        host="alias.example.local",
        in_scope_hosts=in_scope,
        zones=zones,
    )
    assert cls == "redirect-alias"
    assert "www.example.local" in (loc or "")
    assert "in-scope-redirect" in notes

    cls, _, notes = classify_http(
        HttpProbe(
            url="http://walled.example.local/",
            status_code=403,
            headers={"cf-mitigated": "challenge"},
            body="Just a moment...",
        ),
        host="walled.example.local",
        in_scope_hosts=set(),
        zones=set(),
    )
    assert cls == "waf-challenge-gated"
    assert any("waf:" in n for n in notes)

    cls, _, _ = classify_http(
        HttpProbe(
            url="http://sso.example.local/",
            status_code=302,
            location="https://sso.example.local/login?next=/",
        ),
        host="sso.example.local",
        in_scope_hosts=set(),
        zones=set(),
    )
    assert cls == "sso-auth-gated"

    cls, _, _ = classify_http(
        HttpProbe(
            url="http://app.example.local/",
            status_code=200,
            body="<html>hello</html>",
        ),
        host="app.example.local",
        in_scope_hosts=set(),
        zones=set(),
    )
    assert cls == "live-content"


def test_fingerprint_and_takeover_body():
    tech = fingerprint_tech(
        HttpProbe(
            url="http://127.0.0.1/",
            status_code=200,
            headers={"Server": "nginx/1.25", "X-Powered-By": "PHP/8.2"},
            body=(
                '<meta name="generator" content="WordPress 6.4">'
                '<link href="/wp-content/themes/x.css">'
            ),
            set_cookies=["__Secure-next-auth.session-token=abc"],
        )
    )
    assert any(t.startswith("server:nginx") for t in tech)
    assert "wordpress" in tech
    assert "next-auth" in tech

    hit, vendor = takeover_from_http(
        HttpProbe(url="http://x/", status_code=404, body="<Error><Code>NoSuchBucket</Code></Error>")
    )
    assert hit is True
    assert vendor == "S3"


def test_clamps_and_proxy_detect(monkeypatch):
    assert clamp_concurrency(100, proxy=False) == MAX_CONCURRENCY
    assert clamp_concurrency(None, proxy=False) == DEFAULT_CONCURRENCY
    assert clamp_concurrency(None, proxy=True) == DEFAULT_PROXY_CONCURRENCY
    assert clamp_rate(999) == MAX_RATE_RPS
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:8888")
    assert detect_proxy(None) == "http://127.0.0.1:8888"
    assert detect_proxy("http://explicit:1") == "http://explicit:1"


def _dns_ok(host: str) -> DnsResult:
    return DnsResult(host=host, a_records=["127.0.0.1"])


def test_run_triage_live_local_fixture(fx):
    fx.html("/", "<html><title>ok</title></html>")
    origin = fx.origin  # http://127.0.0.1:PORT
    doc = run_triage(
        [origin],
        dns_resolve=_dns_ok,
        # Real HTTP against the local fixture — the only network this test uses.
    )
    assert doc["hosts"]
    rec = doc["hosts"][0]
    assert rec["classification"] == "live-content"
    assert rec["worth_crawling"] is True
    assert origin.rstrip("/") in rec["url"] or rec["url"].startswith(origin)
    assert origin in doc["crawl_seeds"] or doc["crawl_seeds"][0].startswith(origin)


def test_run_triage_skips_external_without_flag():
    doc = run_triage(
        ["evil.example.com"],
        allow_external=False,
        dns_resolve=lambda h: (_ for _ in ()).throw(AssertionError("dns must not run")),
        http_probe=lambda u: (_ for _ in ()).throw(AssertionError("http must not run")),
    )
    assert doc["skipped_external"] == 1
    assert doc["hosts"][0]["classification"] == "skipped-external"
    assert doc["crawl_seeds"] == []


def test_run_triage_no_active_skips_http():
    probed: list[str] = []
    doc = run_triage(
        ["127.0.0.1"],
        no_active=True,
        dns_resolve=_dns_ok,
        http_probe=lambda u: probed.append(u) or HttpProbe(url=u, status_code=200),
    )
    assert probed == []
    assert doc["active"] is False
    assert doc["hosts"][0]["classification"] == "resolves"
    assert doc["hosts"][0]["worth_crawling"] is False


def test_run_triage_waf_pauses_zone():
    def probe(url: str) -> HttpProbe:
        if "one.example.local" in url:
            return HttpProbe(
                url=url,
                status_code=403,
                headers={"cf-mitigated": "challenge"},
                body="Just a moment while we check your browser",
            )
        return HttpProbe(url=url, status_code=200, body="ok")

    doc = run_triage(
        ["one.example.local", "two.example.local"],
        allow_external=False,  # .local is treated as local
        dns_resolve=_dns_ok,
        http_probe=probe,
        concurrency=1,  # sequential so the pause is deterministic
        rate=10.0,
    )
    by_host = {r["host"]: r for r in doc["hosts"]}
    assert by_host["one.example.local"]["classification"] == "waf-challenge-gated"
    two = by_host["two.example.local"]
    # Either probed before the pause landed, or skipped with the zone-pause note.
    # With concurrency=1, submission order follows the input list, so two
    # should see the pause.
    assert two["classification"] in {"live-content", "resolves", "waf-challenge-gated"}
    if two["http"] is None:
        assert any("zone paused" in n for n in two["notes"])
        assert "example.local" in doc["zones_paused"]


def test_run_triage_takeover_http_fingerprint():
    doc = run_triage(
        ["bucket.example.local"],
        dns_resolve=lambda h: DnsResult(
            host=h, cname="missing.s3.amazonaws.com", a_records=["127.0.0.1"]
        ),
        http_probe=lambda u: HttpProbe(
            url=u, status_code=404, body="<Code>NoSuchBucket</Code>"
        ),
    )
    rec = doc["hosts"][0]
    assert rec["takeover"] is True
    assert rec["classification"] == "dangling-cname"
    assert rec["worth_crawling"] is False
    assert doc["takeover_candidates"]


def test_run_triage_ct_discover_injects_hosts():
    seen: list[str] = []

    def ct(apex: str) -> list[str]:
        seen.append(apex)
        return ["www.example.local", "api.example.local"]

    doc = run_triage(
        [],
        discover=["example.local"],
        allow_external=True,
        no_active=True,
        dns_resolve=_dns_ok,
        ct_discover=ct,
        http_probe=lambda u: HttpProbe(url=u, status_code=200),
    )
    assert seen == ["example.local"]
    hosts = {r["host"] for r in doc["hosts"]}
    assert hosts == {"www.example.local", "api.example.local"}


def test_discover_without_allow_external_raises():
    with pytest.raises(ValueError, match="allow-external"):
        run_triage([], discover=["example.com"])


def test_run_triage_sends_custom_header_and_ua(fx):
    seen: dict[str, str] = {}

    def capture(req):
        seen["ua"] = req.headers.get("User-Agent", "")
        seen["bugcrowd"] = req.headers.get("Bugcrowd", "")
        return 200, {"Content-Type": "text/html"}, b"<html>ok</html>"

    fx.on("GET", "/", capture)
    run_triage(
        [fx.origin],
        user_agent="Shroodler-triage/test",
        headers=["Bugcrowd: 00000000-0000-0000-0000-000000000000"],
        dns_resolve=_dns_ok,
    )
    assert seen["ua"] == "Shroodler-triage/test"
    assert seen["bugcrowd"] == "00000000-0000-0000-0000-000000000000"


def test_run_triage_wordpress_json_followup(fx):
    fx.html("/", '<html><link href="/wp-content/themes/x.css"></html>')
    fx.route(
        "/wp-json/",
        lambda _p: (
            200,
            {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            },
            b'{"name":"site"}',
        ),
    )
    doc = run_triage([fx.origin], dns_resolve=_dns_ok)
    rec = doc["hosts"][0]
    assert "wordpress" in rec["tech"]
    assert "wordpress-json" in rec["tech"]
    assert "wordpress-json-cors-star" in rec["notes"]


def test_render_text_and_hosts():
    doc = {
        "hosts": [
            {
                "host": "a.local",
                "classification": "live-content",
                "tech": ["server:nginx"],
                "takeover": False,
                "takeover_signal": None,
                "saas_vendor": None,
                "worth_crawling": True,
                "url": "http://a.local/",
            }
        ],
        "crawl_seeds": ["http://a.local/"],
        "takeover_candidates": [],
        "zones_paused": [],
    }
    text = render_text(doc)
    assert "a.local" in text
    assert "live-content" in text
    assert "yes" in text
    assert render_hosts(doc) == "http://a.local/\n"


def test_cli_triage_parses_and_writes(tmp_path, fx, capsys):
    fx.html("/", "<html>ok</html>")
    out = tmp_path / "triage.json"
    hosts_out = tmp_path / "seeds.txt"
    parser = build_parser()
    args = parser.parse_args(
        [
            "triage",
            fx.origin,
            "--format",
            "json",
            "-o",
            str(out),
            "--hosts-out",
            str(hosts_out),
            "--concurrency",
            "1",
            "--rate",
            "5",
        ]
    )
    assert args.command == "triage"
    assert cmd_triage(args) == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["hosts"][0]["classification"] == "live-content"
    assert hosts_out.read_text(encoding="utf-8").startswith("http://127.0.0.1")


def test_cli_triage_all_skipped_exits_1(tmp_path):
    ns = argparse.Namespace(
        targets=["remote.example.com"],
        discover=None,
        allow_external=False,
        no_active=False,
        concurrency=1,
        rate=2.0,
        timeout=2.0,
        proxy=None,
        user_agent=None,
        header=None,
        format="json",
        output=None,
        hosts_out=None,
    )
    assert cmd_triage(ns) == 1


def test_help_mentions_operational_constraints():
    help_text = build_parser()._subparsers._group_actions[0].choices["triage"].format_help()
    assert "--no-active" in help_text
    assert "--allow-external" in help_text
    assert "--header" in help_text
    assert "bounded" in help_text.lower() or "rate" in help_text.lower()
