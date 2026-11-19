"""Route live probe traffic through the recording proxy (packages/proxy-go).

When a scan runs through the recording proxy, every request/response is captured
and each response comes back stamped with ``X-Shroodler-Session`` (see
:mod:`shroodler.evidence`), so any probe's finding, not just the impact checks,
can bind a proof that points at the full recorded exchange. This module builds
the httpx client that routes there.

It is strictly opt-in: with no proxy configured, probes build their client
exactly as before. Enabling it only adds capture; it does not change what a probe
sends. For an HTTPS target the proxy MITMs TLS with its own CA, so the client
must trust that CA bundle (``ca_cert``); without it, HTTPS requests through the
proxy would fail verification.
"""

from __future__ import annotations

import httpx


def proxied_client(
    proxy_url: str,
    *,
    ca_cert: str | None = None,
    timeout: float = 8.0,
    follow_redirects: bool = False,
) -> httpx.Client:
    """Build an httpx client that routes through the recording proxy.

    ``ca_cert`` is a path to the proxy's CA bundle, needed so HTTPS targets
    verify through the proxy's MITM certificate; omit it for HTTP-only targets.
    """
    verify: object = ca_cert if ca_cert else True
    return httpx.Client(
        proxy=proxy_url,
        verify=verify,
        timeout=timeout,
        follow_redirects=follow_redirects,
    )


def client_from_config(config: object) -> httpx.Client | None:
    """Build a recording-proxy client from config, or None if not configured.

    Reads ``recording_proxy_url`` (and optional ``recording_proxy_ca``) off the
    config object. Returns None when no proxy URL is set, so callers fall back to
    their normal client and behaviour is unchanged.
    """
    proxy_url = str(getattr(config, "recording_proxy_url", "") or "").strip()
    if not proxy_url:
        return None
    ca_cert = str(getattr(config, "recording_proxy_ca", "") or "").strip() or None
    return proxied_client(proxy_url, ca_cert=ca_cert)
