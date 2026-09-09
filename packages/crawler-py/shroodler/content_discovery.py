"""One-shot content discovery for exposed git, env, config, and admin paths."""

from __future__ import annotations

from urllib.parse import urlparse

import httpx

from shroodler.models import Finding
from shroodler.pacer import Pacer
from shroodler.probes.common import body_text, dedupe, request

GIT_PATHS = ("/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG", "/.git/index")
ENV_PATHS = (
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.example",
    "/.env.dev",
    "/.env.development",
)
LOG_PATHS = (
    "/server.log",
    "/error.log",
    "/access.log",
    "/debug.log",
    "/app.log",
    "/logs/error.log",
)
CONFIG_PATHS = (
    "/config.php",
    "/config.yml",
    "/config.json",
    "/config.xml",
    "/settings.py",
    "/settings.json",
    "/database.yml",
    "/wp-config.php",
    "/web.config",
    "/application.properties",
    "/application.yml",
    "/appsettings.json",
    "/.aws/credentials",
    "/composer.json",
    "/package.json",
    "/Dockerfile",
    "/.dockerenv",
    "/.htaccess",
    "/.htpasswd",
    "/web.xml",
    "/backup.sql",
    "/dump.sql",
)
ADMIN_PATHS = (
    "/admin/",
    "/administrator/",
    "/phpmyadmin/",
    "/adminer.php",
    "/console/",
    "/admin/login",
    "/wp-admin/",
    "/server-status",
)
MISC_PATHS = (
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/.DS_Store",
    "/thumbs.db",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/humans.txt",
    "/security.txt",
    "/.well-known/security.txt",
)
SWAGGER_PATHS = (
    "/api/swagger.json",
    "/v1/swagger.json",
    "/api/v1/swagger.json",
    "/swagger-ui.html",
    "/swagger.json",
    "/openapi.json",
    "/api/openapi.json",
)
GRAPHQL_PATHS = ("/graphql", "/graphiql", "/api/graphql")

WORDLIST: tuple[str, ...] = (
    GIT_PATHS
    + ENV_PATHS
    + LOG_PATHS
    + CONFIG_PATHS
    + ADMIN_PATHS
    + MISC_PATHS
    + SWAGGER_PATHS
    + GRAPHQL_PATHS
)

_LOGIN_HINTS = ("login", "signin", "sign-in", "log-in", "authenticate")
_STACK_HINTS = ("traceback", "stack trace", "exception", "at 0x", "error")
_TS_HINTS = (
    "1970-",
    "2020-",
    "2021-",
    "2022-",
    "2023-",
    "2024-",
    "2025-",
    "2026-",
    "[error]",
    "info[",
)


def _origin(target: str) -> str:
    parsed = urlparse(target)
    if not parsed.scheme or not parsed.netloc:
        return target.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}"


def _status(resp: httpx.Response | None) -> int:
    if resp is None:
        return 0
    try:
        return int(getattr(resp, "status_code", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _redirects_to_login(resp: httpx.Response | None) -> bool:
    if resp is None:
        return False
    code = _status(resp)
    if code not in {301, 302, 303, 307, 308}:
        return False
    headers = getattr(resp, "headers", None) or {}
    try:
        location = str(headers.get("location") or headers.get("Location") or "").lower()
    except Exception:  # noqa: BLE001
        return False
    return any(hint in location for hint in _LOGIN_HINTS)


def _interesting(resp: httpx.Response | None, *, min_len: int = 50) -> bool:
    if resp is None or _status(resp) != 200:
        return False
    if _redirects_to_login(resp):
        return False
    body = body_text(resp)
    return len(body) > min_len


def _env_like(body: str) -> bool:
    if "=" not in body:
        return False
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key and key.upper() == key and any(c.isalpha() for c in key):
                return True
    return False


def _log_like(body: str) -> bool:
    lowered = body.lower()
    if any(hint in lowered for hint in _STACK_HINTS):
        return True
    return any(hint in body or hint in lowered for hint in _TS_HINTS)


def _finding(
    finding_id: str,
    severity: str,
    url: str,
    description: str,
    evidence: str,
    *,
    category: str = "exposed-file",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,  # type: ignore[arg-type]
        category=category,  # type: ignore[arg-type]
        url=url,
        description=description,
        evidence=evidence,
        confidence="confirmed",
    )


def classify_path(path: str, body: str, url: str) -> Finding | None:
    lowered = path.lower()
    if path in GIT_PATHS or "/.git/" in lowered:
        if "ref: refs/" in body or "[core]" in body:
            return _finding(
                "git-repo-exposed",
                "critical",
                url,
                "A .git object is publicly readable.",
                f"path={path} snippet={body[:120]!r}",
            )
        return None
    if path in ENV_PATHS or lowered.endswith(".env") or "/.env" in lowered:
        if _env_like(body):
            return _finding(
                "env-file-exposed",
                "critical",
                url,
                "An environment file with assignment keys is publicly readable.",
                f"path={path}",
            )
        return None
    if path in LOG_PATHS or lowered.endswith(".log"):
        if _log_like(body):
            return _finding(
                "log-file-exposed",
                "medium",
                url,
                "A log file with timestamps or stack traces is publicly readable.",
                f"path={path}",
            )
        return None
    if path in GRAPHQL_PATHS:
        return _finding(
            "graphql-endpoint-found",
            "info",
            url,
            "A GraphQL endpoint responded with a non-empty body.",
            f"path={path}",
            category="scan-note",
        )
    if path in SWAGGER_PATHS or "swagger" in lowered or "openapi" in lowered:
        return _finding(
            "openapi-spec-found",
            "info",
            url,
            "An OpenAPI/Swagger document is publicly reachable.",
            f"path={path}",
            category="scan-note",
        )
    if path in ADMIN_PATHS:
        return _finding(
            "admin-interface-exposed",
            "medium",
            url,
            "An admin or management interface is reachable without a login redirect.",
            f"path={path}",
        )
    if path in CONFIG_PATHS:
        return _finding(
            "config-file-exposed",
            "high",
            url,
            "A configuration file is publicly readable.",
            f"path={path}",
        )
    return None


def discover_content(
    target: str,
    cookie_header: str = "",
    *,
    client: httpx.Client | None = None,
    pacer: Pacer | None = None,
    paths: tuple[str, ...] | None = None,
) -> list[Finding]:
    """GET a wordlist of sensitive paths on the target origin."""
    findings: list[Finding] = []
    for path in paths or WORDLIST:
        url = _origin(target).rstrip("/") + path
        resp = request(
            "GET",
            url,
            cookie_header=cookie_header,
            client=client,
            pacer=pacer,
        )
        body = body_text(resp)
        git_hit = path in GIT_PATHS and ("ref: refs/" in body or "[core]" in body)
        if git_hit:
            hit = classify_path(path, body, url)
            if hit is not None:
                findings.append(hit)
            continue
        min_len = 0 if path in GRAPHQL_PATHS or path in GIT_PATHS else 50
        if path in GIT_PATHS:
            continue
        if not _interesting(resp, min_len=min_len) and not (
            path in GRAPHQL_PATHS and _status(resp) == 200 and len(body) > 0
        ):
            continue
        hit = classify_path(path, body, url)
        if hit is not None:
            findings.append(hit)
    return dedupe(findings)
