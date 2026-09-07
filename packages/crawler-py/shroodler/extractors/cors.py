from __future__ import annotations

from urllib.parse import urljoin, urlparse

from shroodler.models import Finding
from shroodler.modes.static import StaticFetcher
from shroodler.urls import canonical_key, is_loopback_or_local, same_origin

ATTACKER_ORIGIN = "https://evil.example"
MAX_CORS_PROBES = 32


def _attacker_origins_for(target_origin: str) -> list[str]:
    """Return the ordered list of Origin header values to probe for a target.

    Beyond the baseline https://evil.example we test the four patterns that
    bypass the most common server-side CORS implementations:

    1. Suffix-append  — server checks endsWith(".example.com") so
       "https://evil.example.com" passes.  For a target like
       "https://api.foo.com" we send "https://evil.api.foo.com".
    2. Prefix-append  — server uses indexOf() so "https://foo.com.evil.example"
       passes a naive `origin.contains("foo.com")` check.
    3. Subdomain-bypass — server has *.target.com trusted; we send a crafted
       sub that looks like target's own subdomain space.
    4. null            — sandboxed <iframe sandbox> sends null; many servers
       allowlist it explicitly.
    """
    parsed = urlparse(target_origin)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    origins: list[str] = [ATTACKER_ORIGIN]
    if host:
        # Pattern 1: evil. prefix on the real host (bypasses endsWith check)
        origins.append(f"{scheme}://evil.{host}")
        # Pattern 2: real host as prefix on evil domain (bypasses contains/indexOf check)
        origins.append(f"{scheme}://{host}.evil.example")
        # Pattern 3: subdomain-look-alike under the real TLD
        # e.g. api.foo.com → notfoo.foo.com
        parts = host.split(".")
        if len(parts) >= 2:
            root = ".".join(parts[-2:])
            origins.append(f"{scheme}://shroodler-test.{root}")
    # Pattern 4: null origin (sandboxed iframe)
    origins.append("null")
    return origins
STATIC_SUFFIXES = (
    ".js",
    ".css",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".webp",
    ".avif",
)


def header_get(headers: dict[str, str], name: str) -> str:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return (v or "").strip()
    return ""


def is_static_asset(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_SUFFIXES)


def is_api_path(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path == "/api" or path.startswith("/api/") or "/api/" in path


def is_json_content_type(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return "application/json" in ct or "application/problem+json" in ct


def is_api_ish(url: str, content_type: str = "") -> bool:
    if is_static_asset(url):
        return False
    return is_api_path(url) or is_json_content_type(content_type)


def candidate_from_endpoint(page_url: str, endpoint: str) -> str:
    return urljoin(page_url, endpoint)


def findings_from_cors_headers(
    headers: dict[str, str],
    page_url: str,
    probed_origin: str = ATTACKER_ORIGIN,
) -> list[Finding]:
    acao = header_get(headers, "access-control-allow-origin")
    acac = header_get(headers, "access-control-allow-credentials")
    if not acao:
        return []
    creds = acac.lower() == "true"
    evidence = f"Origin: {probed_origin} → ACAO={acao}"
    if acac:
        evidence += f" ACAC={acac}"
    out: list[Finding] = []
    if acao == "*" and creds:
        out.append(
            Finding(
                id="cors-wildcard-credentials",
                severity="high",
                category="header",
                url=page_url,
                description=(
                    "Access-Control-Allow-Origin is * with "
                    "Access-Control-Allow-Credentials true"
                ),
                evidence=evidence,
            )
        )
    elif acao == "*":
        out.append(
            Finding(
                id="cors-allow-any",
                severity="info",
                category="header",
                url=page_url,
                description="Access-Control-Allow-Origin is * (credentials not enabled)",
                evidence=evidence,
            )
        )
    # Server reflected our probed origin (or null) back — this is a finding
    # regardless of which bypass variant triggered it.
    if acao == probed_origin and probed_origin != "*":
        severity = "high" if creds else "medium"
        if probed_origin == ATTACKER_ORIGIN:
            desc = "Access-Control-Allow-Origin reflects the attacker Origin"
        elif probed_origin == "null":
            desc = "Access-Control-Allow-Origin allows null origin (sandboxed iframe exploit)"
            severity = "high" if creds else "low"
        else:
            desc = (
                f"Access-Control-Allow-Origin reflects bypass variant '{probed_origin}' — "
                "server's origin validation is bypassable"
            )
        out.append(
            Finding(
                id="cors-reflect-origin",
                severity=severity,
                category="header",
                url=page_url,
                description=desc,
                evidence=evidence,
            )
        )
    return out


def probe_cors(
    origin: str,
    fetcher: StaticFetcher,
    candidates: list[str],
    allow_external: bool = False,
) -> list[Finding]:
    if not is_loopback_or_local(origin) and not allow_external:
        return [
            Finding(
                id="cors-probe-skipped",
                severity="info",
                category="scan-note",
                url=origin,
                description=(
                    "Active CORS probe was skipped because the target is not "
                    "local and --allow-external was not passed. An empty "
                    "CORS result on a remote scan does not mean CORS is safe."
                ),
                evidence=None,
            )
        ]
    findings: list[Finding] = []
    seen: set[str] = set()
    n = 0
    attacker_origins = _attacker_origins_for(origin)
    for url in candidates:
        if n >= MAX_CORS_PROBES:
            break
        if not url or not same_origin(url, origin):
            continue
        if not allow_external and not is_loopback_or_local(url):
            continue
        if is_static_asset(url):
            continue
        key = canonical_key(url)
        if key in seen:
            continue
        seen.add(key)
        n += 1
        for attacker_origin in attacker_origins:
            hdrs = _probe_headers(fetcher, url, attacker_origin)
            new = findings_from_cors_headers(hdrs, url, probed_origin=attacker_origin)
            if new:
                findings.extend(new)
                # Found a bypass for this URL; no need to try remaining variants
                break
    return findings


def _probe_headers(
    fetcher: StaticFetcher, url: str, attacker_origin: str = ATTACKER_ORIGIN
) -> dict[str, str]:
    extra = {
        "Origin": attacker_origin,
        "Access-Control-Request-Method": "GET",
    }
    opt = fetcher.request("OPTIONS", url, extra)
    if header_get(opt.headers, "access-control-allow-origin"):
        return opt.headers
    got = fetcher.request("GET", url, {"Origin": attacker_origin})
    return got.headers
