from __future__ import annotations

from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse


def origin(url: str) -> str:
    p = urlparse(url)
    netloc = p.hostname or ""
    if p.port:
        netloc = f"{netloc}:{p.port}"
    return f"{p.scheme}://{netloc}"


def is_loopback_or_local(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        return True
    if host.endswith(".local"):
        return True
    return False


def same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    port_a = pa.port or (443 if pa.scheme == "https" else 80)
    port_b = pb.port or (443 if pb.scheme == "https" else 80)
    return (
        pa.scheme == pb.scheme
        and (pa.hostname or "").lower() == (pb.hostname or "").lower()
        and port_a == port_b
    )


def normalize_url(base: str, href: str) -> str | None:
    if href is None:
        return None
    href = href.strip()
    if not href or href.startswith(("#", "javascript:", "mailto:", "data:", "tel:")):
        return None
    joined = urljoin(base, href)
    parsed = urlparse(joined)
    if parsed.scheme not in {"http", "https"}:
        return None
    # Drop fragment — fragment-only diffs are duplicates.
    parsed = parsed._replace(fragment="")
    path = parsed.path or "/"
    return urlunparse(parsed._replace(path=path))


def canonical_key(url: str) -> str:
    """Identity used for duplicate detection."""
    p = urlparse(url)
    path = p.path or "/"
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    query_items = sorted(parse_qsl(p.query, keep_blank_values=True))
    query = "&".join(f"{k}={v}" for k, v in query_items)
    host = (p.hostname or "").lower()
    port = p.port
    if port and not ((p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    return urlunparse((p.scheme, netloc, path, "", query, ""))


def path_of(url: str) -> str:
    return urlparse(url).path or "/"


def query_param_names(url: str) -> list[str]:
    p = urlparse(url)
    names = []
    seen = set()
    for k, _ in parse_qsl(p.query, keep_blank_values=True):
        if k not in seen:
            seen.add(k)
            names.append(k)
    return names
