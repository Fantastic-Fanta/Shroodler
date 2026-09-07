"""`shroodler triage`: a fast, low-touch pre-crawl pass that classifies
hosts so crawl/payload budget goes only to ones worth it.

It classifies; it does not crawl or fire payloads. Discovery is passive
(Certificate Transparency) and the only contact with a target is one
gentle HTTP probe per live host, skippable with `--no-active`.

Hard operational constraints (the point of the command, not options):
bounded concurrency and a global rate cap (clamped, never unbounded);
proxy/egress awareness; WAF-politeness (pause a zone on challenge or
429 instead of fanning out into a block); identifying User-Agent plus
required custom headers; local-only by default.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import httpx

from shroodler.auth import parse_header_lines
from shroodler.extractors.challenge import detect_challenge
from shroodler.robots import DEFAULT_UA

# Operator-clamped ceilings — the wien.gv.at incident was an unbounded
# fan-out. A caller can ask for less, never more.
MAX_CONCURRENCY = 8
MAX_RATE_RPS = 10.0
DEFAULT_CONCURRENCY = 4
DEFAULT_PROXY_CONCURRENCY = 2
DEFAULT_RATE_RPS = 2.0
DEFAULT_TIMEOUT = 8.0

# Multi-label public suffixes we actually hit in-scope (not a full PSL).
# `wien.gv.at` must be a zone of its own — treating `gv.at` as the zone
# would pause an entire national TLD on one WAF trip.
_MULTI_SUFFIXES = {
    ("co", "uk"),
    ("ac", "uk"),
    ("gov", "uk"),
    ("com", "au"),
    ("co", "jp"),
    ("ne", "jp"),
    ("or", "jp"),
    ("co", "nz"),
    ("com", "br"),
    ("com", "cn"),
    ("gv", "at"),
    ("ac", "at"),
    ("co", "at"),
}

# CNAME target suffix → SaaS vendor. Live CNAMEs become `third-party-saas`;
# unclaimed/deprovisioned ones become takeover candidates.
SAAS_CNAME_SUFFIXES: tuple[tuple[str, str], ...] = (
    ("cloudfront.net", "CloudFront"),
    ("s3.amazonaws.com", "S3"),
    ("s3-website", "S3"),
    ("amazonaws.com", "AWS"),
    ("herokuapp.com", "Heroku"),
    ("herokudns.com", "Heroku"),
    ("github.io", "GitHub Pages"),
    ("githubmap.com", "GitHub"),
    ("zendesk.com", "Zendesk"),
    ("statuspage.io", "Statuspage"),
    ("myshopify.com", "Shopify"),
    ("shopify.com", "Shopify"),
    ("azurewebsites.net", "Azure"),
    ("cloudapp.net", "Azure"),
    ("trafficmanager.net", "Azure"),
    ("azurefd.net", "Azure Front Door"),
    ("blob.core.windows.net", "Azure Blob"),
    ("fastly.net", "Fastly"),
    ("fastlylb.net", "Fastly"),
    ("edgekey.net", "Akamai"),
    ("akamaiedge.net", "Akamai"),
    ("edgesuite.net", "Akamai"),
    ("netlify.app", "Netlify"),
    ("netlify.com", "Netlify"),
    ("vercel.app", "Vercel"),
    ("pantheonsite.io", "Pantheon"),
    ("wpengine.com", "WP Engine"),
    ("ghost.io", "Ghost"),
    ("readme.io", "ReadMe"),
    ("intercom.help", "Intercom"),
    ("hubspot.net", "HubSpot"),
    ("force.com", "Salesforce"),
    ("okta.com", "Okta"),
    ("auth0.com", "Auth0"),
    ("unbouncepages.com", "Unbounce"),
    ("helpjuice.com", "Helpjuice"),
    ("helpscoutdocs.com", "Help Scout"),
    ("surge.sh", "Surge"),
    ("bitbucket.io", "Bitbucket"),
    ("gitlab.io", "GitLab Pages"),
)

# Body/title fingerprints of an unclaimed SaaS landing page. Matched
# case-insensitively against the one HTTP probe body.
_TAKEOVER_BODY: tuple[tuple[str, str], ...] = (
    ("nosuchbucket", "S3"),
    ("the specified bucket does not exist", "S3"),
    ("nosuchwebsiteconfiguration", "S3"),
    ("unknown domain", "CloudFront/Fastly"),
    ("error: the request could not be satisfied", "CloudFront"),
    ("fastly error: unknown domain", "Fastly"),
    ("there isn't a github pages site here", "GitHub Pages"),
    ("for root users, visit github.com/login", "GitHub Pages"),
    ("no such app", "Heroku"),
    ("herokudns.com", "Heroku"),
    ("help center closed", "Zendesk"),
    ("this help center no longer exists", "Zendesk"),
    ("status page doesn't exist", "Statuspage"),
    ("sorry, this shop is currently unavailable", "Shopify"),
    ("only one step left", "Unbounce"),
    ("project not found", "Surge"),
    ("repository not found", "Bitbucket"),
    ("the gods are wise, but do not know of the site which you seek", "Pantheon"),
)

_LOGIN_LOCATION_HINTS = (
    "/login",
    "/signin",
    "/sign-in",
    "/sso",
    "/saml",
    "/oauth",
    "/oidc",
    "/auth/",
    "/api/auth",
    "accounts.google",
    "login.microsoftonline",
    "okta.com",
    "auth0.com",
    "keycloak",
)

_NEXT_AUTH_COOKIE_PREFIXES = (
    "__secure-next-auth",
    "__host-next-auth",
    "next-auth.session-token",
    "next-auth.callback-url",
    "next-auth.csrf-token",
)

# Rank used both for the human table and for `--format hosts` filtering.
# Lower is more interesting.
_CLASS_RANK = {
    "dangling-cname": 0,
    "live-content": 1,
    "sso-auth-gated": 2,
    "waf-challenge-gated": 3,
    "redirect-alias": 4,
    "third-party-saas": 5,
    "resolves": 6,
    "error": 7,
    "dead": 8,
    "skipped-external": 9,
}


@dataclass
class DnsResult:
    host: str
    a_records: list[str] = field(default_factory=list)
    cname: str | None = None
    nxdomain: bool = False
    error: str | None = None


@dataclass
class HttpProbe:
    url: str
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    location: str | None = None
    error: str | None = None
    set_cookies: list[str] = field(default_factory=list)


@dataclass
class Target:
    """One input row: a hostname (and optional URL to probe as-is)."""

    host: str
    url: str | None = None
    source: str = "input"


@dataclass
class HostRecord:
    host: str
    url: str
    classification: str
    dns: str
    http: str | None
    tech: list[str]
    takeover: bool
    takeover_signal: str | None
    saas_vendor: str | None
    worth_crawling: bool
    redirect_to: str | None
    notes: list[str]
    status_code: int | None
    zone: str

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "url": self.url,
            "classification": self.classification,
            "dns": self.dns,
            "http": self.http,
            "tech": self.tech,
            "takeover": self.takeover,
            "takeover_signal": self.takeover_signal,
            "saas_vendor": self.saas_vendor,
            "worth_crawling": self.worth_crawling,
            "redirect_to": self.redirect_to,
            "notes": self.notes,
            "status_code": self.status_code,
            "zone": self.zone,
        }


DnsFn = Callable[[str], DnsResult]
HttpFn = Callable[[str], HttpProbe]
CtFn = Callable[[str], list[str]]


def clamp_concurrency(value: int | None, *, proxy: bool) -> int:
    if value is None:
        value = DEFAULT_PROXY_CONCURRENCY if proxy else DEFAULT_CONCURRENCY
    return max(1, min(int(value), MAX_CONCURRENCY))


def clamp_rate(value: float | None) -> float:
    if value is None:
        value = DEFAULT_RATE_RPS
    return max(0.1, min(float(value), MAX_RATE_RPS))


def detect_proxy(explicit: str | None = None) -> str | None:
    if explicit:
        return explicit
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        val = os.environ.get(key)
        if val:
            return val
    return None


def zone_of(host: str) -> str:
    hostname = _hostname_of(host)
    parts = hostname.split(".")
    if _is_ip(hostname) or hostname in {"localhost"} or hostname.endswith(".local"):
        return hostname
    if len(parts) <= 2:
        return hostname
    if len(parts) >= 3 and tuple(parts[-2:]) in _MULTI_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def parse_targets(
    positional: list[str],
    *,
    discover: list[str] | None = None,
) -> tuple[list[Target], list[str]]:
    """Turn CLI args into (explicit targets, CT-discovery apexes).

    A positional argument that is an existing file is read as a host
    list (one per line, `#` comments). A `*.apex` wildcard becomes a
    discovery seed rather than a literal host.
    """
    targets: list[Target] = []
    apexes: list[str] = []
    seen_hosts: set[str] = set()
    seen_apexes: set[str] = set()

    def add_apex(raw: str) -> None:
        apex = _hostname_of(raw.lstrip("*.").lower())
        if apex and apex not in seen_apexes:
            seen_apexes.add(apex)
            apexes.append(apex)

    def add_target(raw: str, source: str) -> None:
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            return
        if raw.startswith("*.") or (raw.startswith("*") and "." in raw):
            add_apex(raw)
            return
        host, url = _host_and_url(raw)
        if not host:
            return
        if host not in seen_hosts:
            seen_hosts.add(host)
            targets.append(Target(host=host, url=url, source=source))

    for item in positional:
        path = Path(item)
        if path.is_file() and not item.startswith(("http://", "https://")):
            for line in path.read_text(encoding="utf-8").splitlines():
                add_target(line, source=str(path))
        else:
            add_target(item, source="argv")

    for apex in discover or []:
        add_apex(apex)

    return targets, apexes


def saas_vendor_for(cname: str | None) -> str | None:
    if not cname:
        return None
    lowered = cname.rstrip(".").lower()
    for suffix, vendor in SAAS_CNAME_SUFFIXES:
        if suffix == "s3-website":
            if "s3-website" in lowered:
                return vendor
            continue
        if lowered == suffix or lowered.endswith("." + suffix):
            return vendor
    return None


def classify_dns(dns: DnsResult) -> tuple[str, bool, str | None, str | None, list[str]]:
    """Return (dns_class, takeover, takeover_signal, saas_vendor, notes)."""
    notes: list[str] = []
    vendor = saas_vendor_for(dns.cname)
    if dns.error and not dns.a_records and not dns.cname:
        return "error", False, None, vendor, [dns.error]
    if dns.nxdomain and not dns.cname:
        return "dead", False, None, None, notes
    if dns.cname and not dns.a_records:
        signal = f"CNAME {dns.cname} has no A/AAAA (unclaimed?)"
        # A CNAME to a known SaaS with nothing behind it is the takeover
        # candidate the spec exists to surface. A CNAME to an unknown
        # name that NXDOMAINs is still dangling, just without a vendor.
        return "dangling-cname", True, signal, vendor, notes
    if vendor and dns.cname:
        return "third-party-saas", False, None, vendor, notes
    if dns.a_records:
        return "resolves", False, None, vendor, notes
    return "dead", False, None, vendor, notes


def classify_http(
    probe: HttpProbe,
    *,
    host: str,
    in_scope_hosts: set[str],
    zones: set[str],
) -> tuple[str, str | None, list[str]]:
    """Return (http_class, redirect_to, notes)."""
    notes: list[str] = []
    if probe.error or probe.status_code == 0:
        return "error", None, [probe.error or "no response"]

    challenge = detect_challenge(
        probe.headers, probe.body, probe.status_code, probe.set_cookies
    )
    if challenge or probe.status_code == 429:
        vendor = (challenge.evidence if challenge else None) or "rate-limit"
        notes.append(f"waf:{vendor}")
        return "waf-challenge-gated", None, notes

    location = probe.location or _header(probe.headers, "location")
    if probe.status_code in {301, 302, 303, 307, 308} and location:
        loc_host = _hostname_of(urlparse(location).hostname or "")
        if not loc_host and location.startswith("/"):
            # Same-host path redirect — not an alias.
            loc_host = host
        if loc_host and loc_host != host:
            in_scope = loc_host in in_scope_hosts or zone_of(loc_host) in zones
            notes.append("in-scope-redirect" if in_scope else "out-of-scope-redirect")
            return "redirect-alias", location, notes
        if _looks_like_login(location, probe):
            return "sso-auth-gated", location, notes

    if _looks_like_login(location, probe) or probe.status_code == 401:
        return "sso-auth-gated", location, notes

    if 200 <= probe.status_code < 400:
        return "live-content", location, notes

    return "error", location, [f"http {probe.status_code}"]


def fingerprint_tech(probe: HttpProbe) -> list[str]:
    tech: list[str] = []
    server = _header(probe.headers, "server")
    if server:
        tech.append(f"server:{server.split()[0][:40]}")
    powered = _header(probe.headers, "x-powered-by")
    if powered:
        tech.append(f"powered-by:{powered.split()[0][:40]}")
    liferay = _header(probe.headers, "liferay-portal")
    if liferay:
        tech.append("liferay")
    body = probe.body or ""
    lowered = body.lower()
    cookies = " ".join(probe.set_cookies).lower()
    if any(cookies.startswith(p) or f"{p}" in cookies for p in _NEXT_AUTH_COOKIE_PREFIXES):
        tech.append("next-auth")
    if "__next_data__" in lowered or "/_next/" in lowered:
        tech.append("next.js")
    if "wp-content" in lowered or "wp-json" in lowered or "wordpress" in lowered:
        tech.append("wordpress")
    if "__viewstate" in lowered or "x-aspnet" in {k.lower() for k in probe.headers}:
        tech.append("asp.net")
    if "/c/portal/" in lowered or liferay:
        if "liferay" not in tech:
            tech.append("liferay")
    if "keycloak" in lowered or "kc_session" in cookies:
        tech.append("keycloak")
    if "config.json" in lowered and ("spa" in lowered or "react" in lowered or "__next" in lowered):
        tech.append("spa-config")
    # De-dupe while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for item in tech:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def takeover_from_http(probe: HttpProbe) -> tuple[bool, str | None]:
    body = (probe.body or "").lower()
    for needle, vendor in _TAKEOVER_BODY:
        if needle in body:
            return True, vendor
    return False, None


def _looks_like_login(location: str | None, probe: HttpProbe) -> bool:
    hay = " ".join(
        [
            (location or "").lower(),
            (probe.body or "")[:4000].lower(),
            " ".join(probe.set_cookies).lower(),
        ]
    )
    if any(hint in hay for hint in _LOGIN_LOCATION_HINTS):
        return True
    if any(p in hay for p in _NEXT_AUTH_COOKIE_PREFIXES):
        return True
    if _header(probe.headers, "www-authenticate"):
        return True
    return False


class RateLimiter:
    """Global request-per-second cap shared across worker threads."""

    def __init__(self, rate_rps: float) -> None:
        self.min_interval = 1.0 / rate_rps if rate_rps > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            sleep_for = self._next - now
            self._next = max(now, self._next) + self.min_interval
        if sleep_for > 0:
            time.sleep(sleep_for)


class ZonePause:
    """Pause further HTTP for a zone after the first challenge/429/connect-fail burst."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._paused: set[str] = set()
        self._fail_streak: dict[str, int] = {}

    def paused(self, zone: str) -> bool:
        with self._lock:
            return zone in self._paused

    def paused_zones(self) -> list[str]:
        with self._lock:
            return sorted(self._paused)

    def note_waf(self, zone: str) -> None:
        with self._lock:
            self._paused.add(zone)
            self._fail_streak[zone] = 0

    def note_failure(self, zone: str) -> None:
        # Connection failures back off: two in a row for the same zone
        # pause remaining HTTP rather than hammering a dead egress path.
        with self._lock:
            streak = self._fail_streak.get(zone, 0) + 1
            self._fail_streak[zone] = streak
            if streak >= 2:
                self._paused.add(zone)

    def note_success(self, zone: str) -> None:
        with self._lock:
            self._fail_streak[zone] = 0


def run_triage(
    positional: list[str],
    *,
    discover: list[str] | None = None,
    allow_external: bool = False,
    no_active: bool = False,
    concurrency: int | None = None,
    rate: float | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    proxy: str | None = None,
    user_agent: str | None = None,
    headers: list[str] | None = None,
    dns_resolve: DnsFn | None = None,
    http_probe: HttpFn | None = None,
    ct_discover: CtFn | None = None,
) -> dict:
    proxy_url = detect_proxy(proxy)
    workers = clamp_concurrency(concurrency, proxy=bool(proxy_url))
    rate_rps = clamp_rate(rate)
    ua = user_agent or DEFAULT_UA
    extra_headers = parse_header_lines(headers)

    targets, apexes = parse_targets(positional, discover=discover)
    if not targets and not apexes:
        raise ValueError("triage needs at least one host, hosts file, or --discover apex")

    dns_fn = dns_resolve or (lambda host: resolve_dns(host))
    http_fn = http_probe or (
        lambda url: probe_http(
            url,
            timeout=timeout,
            user_agent=ua,
            headers=extra_headers,
            proxy=proxy_url,
        )
    )
    ct_fn = ct_discover or (
        lambda apex: discover_from_ct(
            apex, timeout=timeout, user_agent=ua, allow_external=allow_external
        )
    )

    # Passive discovery first — hits CT logs, not the target.
    skipped_external = 0
    for apex in apexes:
        if not allow_external:
            raise ValueError(
                "Certificate Transparency discovery contacts crt.sh "
                "(not the target); pass --allow-external to enable --discover"
            )
        for name in ct_fn(apex):
            host, url = _host_and_url(name)
            if not host:
                continue
            if not any(t.host == host for t in targets):
                targets.append(Target(host=host, url=url, source=f"ct:{apex}"))

    in_scope = {t.host for t in targets}
    zones = {zone_of(t.host) for t in targets}

    limiter = RateLimiter(rate_rps)
    pause = ZonePause()
    records: list[HostRecord] = []

    def classify_one(target: Target) -> HostRecord:
        url = target.url or _default_url(target.host)
        notes: list[str] = []
        if not allow_external and not _host_is_local(target.host) and not _url_is_local(url):
            return HostRecord(
                host=target.host,
                url=url,
                classification="skipped-external",
                dns="skipped-external",
                http=None,
                tech=[],
                takeover=False,
                takeover_signal=None,
                saas_vendor=None,
                worth_crawling=False,
                redirect_to=None,
                notes=["pass --allow-external to probe non-local hosts"],
                status_code=None,
                zone=zone_of(target.host),
            )

        dns = dns_fn(target.host)
        dns_class, takeover, takeover_signal, saas_vendor, dns_notes = classify_dns(dns)
        notes.extend(dns_notes)
        http_class: str | None = None
        redirect_to: str | None = None
        tech: list[str] = []
        status_code: int | None = None
        zone = zone_of(target.host)

        should_probe = not no_active and dns_class in {
            "resolves",
            "third-party-saas",
            "dangling-cname",
        }
        if should_probe and pause.paused(zone):
            notes.append("http skipped: zone paused after WAF/rate-limit/egress failures")
            should_probe = False

        if should_probe:
            limiter.wait()
            probe = http_fn(url)
            status_code = probe.status_code or None
            tech = fingerprint_tech(probe)
            http_takeover, http_vendor = takeover_from_http(probe)
            if http_takeover:
                takeover = True
                takeover_signal = takeover_signal or http_vendor
                saas_vendor = saas_vendor or http_vendor
                dns_class = "dangling-cname"
            http_class, redirect_to, http_notes = classify_http(
                probe, host=target.host, in_scope_hosts=in_scope, zones=zones
            )
            notes.extend(http_notes)
            if http_class == "waf-challenge-gated":
                pause.note_waf(zone)
            elif probe.error or probe.status_code == 0:
                pause.note_failure(zone)
            else:
                pause.note_success(zone)
            # One extra CMS probe only when WordPress is already evident
            # from the first response — still rate-limited, still one host.
            if "wordpress" in tech and not pause.paused(zone):
                wp_url = _origin_of(url).rstrip("/") + "/wp-json/"
                limiter.wait()
                wp = http_fn(wp_url)
                if wp.status_code == 200 and "application/json" in (
                    _header(wp.headers, "content-type") or ""
                ):
                    tech.append("wordpress-json")
                    acao = _header(wp.headers, "access-control-allow-origin")
                    if acao == "*":
                        notes.append("wordpress-json-cors-star")

        classification = http_class or dns_class
        if takeover:
            classification = "dangling-cname"
        worth = classification == "live-content" and not takeover
        return HostRecord(
            host=target.host,
            url=url,
            classification=classification,
            dns=dns_class,
            http=http_class,
            tech=tech,
            takeover=takeover,
            takeover_signal=takeover_signal,
            saas_vendor=saas_vendor,
            worth_crawling=worth,
            redirect_to=redirect_to,
            notes=notes,
            status_code=status_code,
            zone=zone,
        )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(classify_one, t) for t in targets]
        for fut in as_completed(futures):
            rec = fut.result()
            if rec.classification == "skipped-external":
                skipped_external += 1
            records.append(rec)

    records.sort(
        key=lambda r: (
            _CLASS_RANK.get(r.classification, 99),
            r.host,
        )
    )
    counts: dict[str, int] = {}
    for rec in records:
        counts[rec.classification] = counts.get(rec.classification, 0) + 1
    crawl_seeds = [r.url for r in records if r.worth_crawling]
    takeovers = [r.to_dict() for r in records if r.takeover]
    return {
        "hosts": [r.to_dict() for r in records],
        "counts": counts,
        "takeover_candidates": takeovers,
        "crawl_seeds": crawl_seeds,
        "skipped_external": skipped_external,
        "zones_paused": pause.paused_zones(),
        "concurrency": workers,
        "rate_rps": rate_rps,
        "proxy": proxy_url,
        "active": not no_active,
    }


def render_text(doc: dict) -> str:
    rows = doc.get("hosts") or []
    if not rows:
        return "No hosts to classify.\n"
    headers = (
        "HOST",
        "CLASS",
        "TECH",
        "TAKEOVER",
        "CRAWL?",
    )
    table = [
        [
            r["host"],
            r["classification"],
            ",".join(r.get("tech") or []) or "-",
            (r.get("takeover_signal") or r.get("saas_vendor") or "yes")
            if r.get("takeover")
            else "-",
            "yes" if r.get("worth_crawling") else "no",
        ]
        for r in rows
    ]
    widths = [len(h) for h in headers]
    for row in table:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))]
    lines.append("  ".join("-" * w for w in widths))
    for row in table:
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))))
    paused = doc.get("zones_paused") or []
    if paused:
        lines.append("")
        lines.append("zones paused (WAF/rate-limit/egress): " + ", ".join(paused))
    seeds = doc.get("crawl_seeds") or []
    lines.append("")
    n_takeover = len(doc.get("takeover_candidates") or [])
    lines.append(f"worth crawling: {len(seeds)}   takeover candidates: {n_takeover}")
    return "\n".join(lines) + "\n"


def render_hosts(doc: dict) -> str:
    seeds = doc.get("crawl_seeds") or []
    return "".join(s + "\n" for s in seeds)


def resolve_dns(host: str) -> DnsResult:
    hostname = _hostname_of(host)
    if _host_is_local(hostname):
        addr = "127.0.0.1"
        if hostname in {"::1"}:
            addr = "::1"
        return DnsResult(host=hostname, a_records=[addr])
    result = DnsResult(host=hostname)
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        result.a_records = sorted({str(i[4][0]) for i in infos})
    except socket.gaierror as exc:
        errno = getattr(exc, "errno", None)
        if errno in {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -1)}:
            result.nxdomain = True
        else:
            result.error = str(exc)
    result.cname = _query_cname(hostname)
    if result.cname and not result.a_records:
        result.nxdomain = True
    return result


def probe_http(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_UA,
    headers: dict[str, str] | None = None,
    proxy: str | None = None,
) -> HttpProbe:
    hdrs = {"User-Agent": user_agent}
    if headers:
        hdrs.update(headers)
    kwargs: dict = {
        "timeout": timeout,
        "follow_redirects": False,
        "headers": hdrs,
        "trust_env": False,
    }
    if proxy:
        kwargs["proxy"] = proxy
    try:
        with httpx.Client(**kwargs) as client:
            resp = client.get(url)
    except httpx.RequestError as exc:
        return HttpProbe(url=url, error=str(exc))
    set_cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    if not set_cookies:
        raw = resp.headers.get("set-cookie")
        if raw:
            set_cookies = [raw]
    try:
        body = resp.text[:8000]
    except Exception:  # noqa: BLE001 - never let a decoder kill the probe
        body = ""
    return HttpProbe(
        url=str(resp.url) if resp.url else url,
        status_code=resp.status_code,
        headers={k: v for k, v in resp.headers.items()},
        body=body,
        location=resp.headers.get("location"),
        set_cookies=list(set_cookies),
    )


def discover_from_ct(
    apex: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    user_agent: str = DEFAULT_UA,
    allow_external: bool = False,
) -> list[str]:
    if not allow_external:
        raise ValueError("crt.sh discovery requires --allow-external")
    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    try:
        client = httpx.Client(
            timeout=timeout, headers={"User-Agent": user_agent}, trust_env=False
        )
        with client:
            resp = client.get(url)
            resp.raise_for_status()
            payload = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"crt.sh discovery failed for {apex!r}: {exc}") from exc
    names: list[str] = []
    seen: set[str] = set()
    if not isinstance(payload, list):
        return names
    for row in payload:
        if not isinstance(row, dict):
            continue
        raw = str(row.get("name_value") or "")
        for part in raw.split("\n"):
            part = part.strip().lower().lstrip("*.")
            if not part or part in seen:
                continue
            seen.add(part)
            names.append(part)
    return names


def _header(headers: dict[str, str], name: str) -> str | None:
    lowered = name.lower()
    for k, v in headers.items():
        if k.lower() == lowered:
            return v
    return None


def _hostname_of(raw: str) -> str:
    raw = (raw or "").strip().lower().rstrip(".")
    if "://" in raw:
        host = urlparse(raw).hostname or ""
        return host.lower().rstrip(".")
    if raw.startswith("[") and "]" in raw:
        return raw[1 : raw.index("]")].lower()
    if raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            return host.lower()
    return raw


def _host_and_url(raw: str) -> tuple[str, str | None]:
    raw = raw.strip()
    if "://" in raw:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").lower().rstrip(".")
        return host, raw
    host = _hostname_of(raw)
    return host, None


def _default_url(host: str) -> str:
    if host.startswith("[") or ":" in host and not _is_ip(host.split(":")[0]):
        # host:port
        hostname, port = _split_hostport(host)
        scheme = "http" if _host_is_local(hostname) else "https"
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        return f"{scheme}://{hostname}:{port}/" if port else f"{scheme}://{hostname}/"
    scheme = "http" if _host_is_local(host) else "https"
    if _is_ip(host) and ":" in host:
        return f"{scheme}://[{host}]/"
    return f"{scheme}://{host}/"


def _split_hostport(raw: str) -> tuple[str, int | None]:
    if raw.startswith("["):
        end = raw.find("]")
        host = raw[1:end]
        rest = raw[end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, None
    if raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            return host, int(port)
    return raw, None


def _host_is_local(host: str) -> bool:
    hostname = _hostname_of(host)
    if hostname in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        return True
    if hostname.endswith(".local"):
        return True
    return False


def _url_is_local(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return _host_is_local(host)


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False


def _origin_of(url: str) -> str:
    parsed = urlparse(url)
    netloc = parsed.netloc
    return f"{parsed.scheme}://{netloc}"


def _query_cname(hostname: str) -> str | None:
    """Best-effort CNAME lookup via a single UDP DNS query.

    Failures return None rather than raising — A-record classification
    still works, and takeover tagging just won't fire without a CNAME.
    """
    try:
        ns = _system_nameserver()
        if not ns:
            return None
        query = _build_dns_query(hostname, qtype=5)  # CNAME
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        try:
            sock.sendto(query, (ns, 53))
            data, _ = sock.recvfrom(512)
        finally:
            sock.close()
        return _parse_cname_answer(data)
    except OSError:
        return None


def _system_nameserver() -> str | None:
    try:
        text = Path("/etc/resolv.conf").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            return parts[1]
    return None


def _build_dns_query(name: str, qtype: int) -> bytes:
    txid = b"\x12\x34"
    flags = b"\x01\x00"  # recursion desired
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.split(".") if label
    )
    qname += b"\x00"
    question = qname + qtype.to_bytes(2, "big") + b"\x00\x01"
    return txid + flags + counts + question


def _parse_cname_answer(data: bytes) -> str | None:
    if len(data) < 12:
        return None
    ancount = int.from_bytes(data[6:8], "big")
    if ancount == 0:
        return None
    # Skip question.
    offset = 12
    try:
        offset = _skip_name(data, offset) + 4  # qtype + qclass
        for _ in range(ancount):
            offset = _skip_name(data, offset)
            if offset + 10 > len(data):
                return None
            rtype = int.from_bytes(data[offset : offset + 2], "big")
            rdlength = int.from_bytes(data[offset + 8 : offset + 10], "big")
            rdata_at = offset + 10
            if rtype == 5 and rdata_at + rdlength <= len(data):
                name, _ = _read_name(data, rdata_at)
                return name
            offset = rdata_at + rdlength
    except (IndexError, ValueError):
        return None
    return None


def _skip_name(data: bytes, offset: int) -> int:
    _, offset = _read_name(data, offset)
    return offset


def _read_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 10:
        raise ValueError("dns pointer loop")
    labels: list[str] = []
    jumped = False
    original = offset
    while True:
        if offset >= len(data):
            raise ValueError("truncated dns name")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("truncated dns pointer")
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            suffix, _ = _read_name(data, ptr, depth + 1)
            labels.append(suffix)
            offset += 2
            jumped = True
            break
        offset += 1
        labels.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), (original + 2 if jumped else offset)
