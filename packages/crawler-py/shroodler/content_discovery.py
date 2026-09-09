"""One-shot content discovery for exposed git, env, config, and admin paths."""

from __future__ import annotations

import re
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

_SENSITIVE_TOKENS = (
    "password",
    "secret",
    "key=",
    "token=",
    "db_",
    "DATABASE_URL",
    "mysql://",
    "postgres://",
    "mongodb://",
    "redis://",
    "[database]",
    "credentials",
    "private_key",
    "access_key",
)
_HIGH_SIGNAL_CONFIG_MARKERS = (
    ".env",
    ".sql",
    ".bak",
    ".key",
    ".pem",
    "credentials",
    ".htpasswd",
)
_ADMIN_CONTENT_HINTS = (
    "<table",
    "dashboard",
    "user list",
    "userlist",
    "admin panel",
    "phpmyadmin",
    "adminer",
    "wp-admin",
    "manage users",
    "control panel",
    "server-status",
    "administrator",
)

_KEY_VALUE_LINE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S{9,}", re.M)
_PASSWORD_ASSIGN = re.compile(r"password\s*[=:]\s*\S+", re.I)
_ENV_FORMAT = re.compile(r"[A-Z_]{4,}=\S{8,}")
_CONN_STRING = re.compile(r"(?:mysql|postgres(?:ql)?|mongodb|redis)://", re.I)
_PEM_HEADER = re.compile(r"-----BEGIN")
_SQL_DDL = re.compile(r"\b(?:INSERT\s+INTO|CREATE\s+TABLE)\b", re.I)
_SPA_ROOT = re.compile(r'<div\s+id=["\'](?:root|app)["\']', re.I)
_HTML_FORM = re.compile(r"<form\b", re.I)
_PASSWORD_INPUT_TYPE = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']password[\"']", re.I)
_PASSWORD_INPUT_NAME = re.compile(
    r"<input\b[^>]*\bname\s*=\s*[\"'](?:password|pass|passwd)[\"']",
    re.I,
)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_REDIRECT_CODES = {301, 302, 303, 307, 308}


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


def _header(headers: object, name: str) -> str:
    if not headers:
        return ""
    getter = getattr(headers, "get", None)
    if not callable(getter):
        return ""
    try:
        value = getter(name) or getter(name.title()) or getter(name.lower())
    except Exception:  # noqa: BLE001
        return ""
    return str(value or "")


def _path_extension(path_or_url: str) -> str:
    parsed = urlparse(path_or_url)
    path = parsed.path or path_or_url
    if "." not in path.rsplit("/", 1)[-1]:
        return ""
    return path.rsplit(".", 1)[-1].lower()


def _login_in_url(url: str) -> bool:
    if not url:
        return False
    path = (urlparse(url).path or "").lower()
    haystack = path if path else url.lower()
    return any(hint in haystack for hint in _LOGIN_HINTS)


def _redirects_to_login(resp: httpx.Response | None) -> bool:
    if resp is None:
        return False
    code = _status(resp)
    if code not in _REDIRECT_CODES:
        return False
    headers = getattr(resp, "headers", None) or {}
    location = _header(headers, "location")
    return _login_in_url(location) or any(
        hint in location.lower() for hint in _LOGIN_HINTS
    )


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


def has_sensitive_tokens(body: str) -> bool:
    lowered = body.lower()
    for token in _SENSITIVE_TOKENS:
        needle = token.lower()
        if needle in lowered or needle in body:
            return True
    return False


def is_spa_shell(body: str) -> bool:
    """True when the body is a generic SPA index with no sensitive tokens."""
    if not body:
        return False
    if not _SPA_ROOT.search(body):
        return False
    if "<script" not in body.lower():
        return False
    return not has_sensitive_tokens(body)


def looks_like_html(body: str, content_type: str = "") -> bool:
    ctype = (content_type or "").lower()
    if "html" in ctype:
        return True
    stripped = body.lstrip()[:200].lower()
    return stripped.startswith("<!doctype html") or stripped.startswith("<html") or bool(
        _SPA_ROOT.search(body)
    )


def has_sensitive_config_patterns(body: str) -> bool:
    """True when the body contains at least one high-signal config/secret pattern."""
    if not body:
        return False
    if _KEY_VALUE_LINE.search(body):
        return True
    if _PASSWORD_ASSIGN.search(body):
        return True
    if _ENV_FORMAT.search(body):
        return True
    if _CONN_STRING.search(body):
        return True
    if _PEM_HEADER.search(body):
        return True
    if _SQL_DDL.search(body):
        return True
    return False


def is_high_signal_config_path(path_or_url: str) -> bool:
    lowered = (path_or_url or "").lower()
    return any(marker in lowered for marker in _HIGH_SIGNAL_CONFIG_MARKERS)


def is_login_wall(
    body: str,
    *,
    status_code: int = 200,
    location: str = "",
    final_url: str = "",
) -> bool:
    """True when the response is an auth wall rather than an open admin UI."""
    if _HTML_FORM.search(body or ""):
        if _PASSWORD_INPUT_TYPE.search(body) or _PASSWORD_INPUT_NAME.search(body):
            return True
    title = _TITLE.search(body or "")
    if title and "login" in title.group(1).lower():
        return True
    if status_code in _REDIRECT_CODES:
        loc = location or ""
        if _login_in_url(loc) or any(hint in loc.lower() for hint in _LOGIN_HINTS):
            return True
    if final_url and _login_in_url(final_url):
        requested_path = (urlparse(final_url).path or "").lower()
        if any(hint in requested_path for hint in _LOGIN_HINTS):
            return True
    return False


def has_admin_content(body: str) -> bool:
    lowered = (body or "").lower()
    return any(hint in lowered for hint in _ADMIN_CONTENT_HINTS)


def _finding(
    finding_id: str,
    severity: str,
    url: str,
    description: str,
    evidence: str,
    *,
    category: str = "exposed-file",
    confidence: str = "confirmed",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,  # type: ignore[arg-type]
        category=category,  # type: ignore[arg-type]
        url=url,
        description=description,
        evidence=evidence,
        confidence=confidence,  # type: ignore[arg-type]
    )


def classify_config_file(
    body: str,
    url: str,
    content_type: str = "",
    *,
    path: str = "",
) -> Finding | None:
    """Classify a config-file wordlist hit from body/url/content-type alone."""
    path = path or urlparse(url).path or url
    if len(body) < 20:
        return _finding(
            "config-file-exposed",
            "info",
            url,
            "A configuration path returned an empty or tiny body.",
            f"[empty-response] path={path}",
            confidence="heuristic",
        )
    if is_spa_shell(body):
        return None
    ext = _path_extension(path)
    if ext not in {"html", "htm"} and looks_like_html(body, content_type):
        if not has_sensitive_tokens(body) and not has_sensitive_config_patterns(body):
            return None
        if is_spa_shell(body):
            return None
    if is_high_signal_config_path(path) and not has_sensitive_config_patterns(body):
        return _finding(
            "config-file-exposed",
            "medium",
            url,
            "A configuration file is publicly readable.",
            f"path={path}",
            confidence="heuristic",
        )
    return _finding(
        "config-file-exposed",
        "high",
        url,
        "A configuration file is publicly readable.",
        f"path={path}",
    )


def classify_admin_interface(
    body: str,
    url: str,
    *,
    path: str = "",
    status_code: int = 200,
    location: str = "",
    final_url: str = "",
) -> Finding | None:
    """Classify an admin wordlist hit: login wall, SPA shell, or real admin UI."""
    path = path or urlparse(url).path or url
    if is_login_wall(
        body,
        status_code=status_code,
        location=location,
        final_url=final_url or url,
    ):
        return _finding(
            "admin-login-page-found",
            "info",
            url,
            f"Admin login page reachable at {url}",
            f"path={path}",
            category="scan-note",
            confidence="confirmed",
        )
    if is_spa_shell(body):
        return None
    if has_admin_content(body):
        return _finding(
            "admin-interface-exposed",
            "medium",
            url,
            "An admin or management interface is reachable without a login redirect.",
            f"path={path}",
        )
    return None


def classify_path(
    path: str,
    body: str,
    url: str,
    *,
    content_type: str = "",
    status_code: int = 200,
    location: str = "",
    final_url: str = "",
) -> Finding | None:
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
        return classify_admin_interface(
            body,
            url,
            path=path,
            status_code=status_code,
            location=location,
            final_url=final_url,
        )
    if path in CONFIG_PATHS:
        return classify_config_file(body, url, content_type, path=path)
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
        headers = getattr(resp, "headers", None) or {}
        content_type = _header(headers, "content-type")
        location = _header(headers, "location")
        code = _status(resp)
        final_url = str(getattr(resp, "url", "") or url)
        extra = dict(
            content_type=content_type,
            status_code=code,
            location=location,
            final_url=final_url,
        )
        git_hit = path in GIT_PATHS and ("ref: refs/" in body or "[core]" in body)
        if git_hit:
            hit = classify_path(path, body, url, **extra)
            if hit is not None:
                findings.append(hit)
            continue
        if path in GIT_PATHS:
            continue
        if path in ADMIN_PATHS and code in _REDIRECT_CODES:
            hit = classify_path(path, body, url, **extra)
            if hit is not None:
                findings.append(hit)
            continue
        if path in CONFIG_PATHS and code == 200:
            hit = classify_path(path, body, url, **extra)
            if hit is not None:
                findings.append(hit)
            continue
        min_len = (
            0
            if path in GRAPHQL_PATHS
            or path in GIT_PATHS
            or path in ADMIN_PATHS
            else 50
        )
        if not _interesting(resp, min_len=min_len) and not (
            path in GRAPHQL_PATHS and _status(resp) == 200 and len(body) > 0
        ):
            continue
        hit = classify_path(path, body, url, **extra)
        if hit is not None:
            findings.append(hit)
    return dedupe(findings)
