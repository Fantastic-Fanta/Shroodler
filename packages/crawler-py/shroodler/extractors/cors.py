from __future__ import annotations

from urllib.parse import urljoin, urlparse

from shroodler.models import Finding
from shroodler.modes.static import StaticFetcher
from shroodler.urls import canonical_key, is_loopback_or_local, same_origin

ATTACKER_ORIGIN = "https://evil.example"
MAX_CORS_PROBES = 32
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


def findings_from_cors_headers(headers: dict[str, str], page_url: str) -> list[Finding]:
    acao = header_get(headers, "access-control-allow-origin")
    acac = header_get(headers, "access-control-allow-credentials")
    if not acao:
        return []
    creds = acac.lower() == "true"
    evidence = f"ACAO={acao}"
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
    if acao == ATTACKER_ORIGIN:
        out.append(
            Finding(
                id="cors-reflect-origin",
                severity="high" if creds else "medium",
                category="header",
                url=page_url,
                description="Access-Control-Allow-Origin reflects the attacker Origin",
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
        findings.extend(findings_from_cors_headers(_probe_headers(fetcher, url), url))
    return findings


def _probe_headers(fetcher: StaticFetcher, url: str) -> dict[str, str]:
    extra = {
        "Origin": ATTACKER_ORIGIN,
        "Access-Control-Request-Method": "GET",
    }
    opt = fetcher.request("OPTIONS", url, extra)
    if header_get(opt.headers, "access-control-allow-origin"):
        return opt.headers
    got = fetcher.request("GET", url, {"Origin": ATTACKER_ORIGIN})
    return got.headers
