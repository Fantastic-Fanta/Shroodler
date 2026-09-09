"""Active injection-class probes (SQLi, XSS, path traversal, JWT, IDOR, SSRF).

Opt-in via `--run-probes`. Each probe calls `paced_fetch.pace` before every
live request and fails closed on transport errors.
"""

from __future__ import annotations

from shroodler.probes.host_header import probe_host_header
from shroodler.probes.idor import probe_idor
from shroodler.probes.jwt import probe_jwt
from shroodler.probes.open_redirect import probe_open_redirect
from shroodler.probes.path_traversal import probe_path_traversal
from shroodler.probes.sqli import probe_sqli
from shroodler.probes.ssrf import probe_ssrf
from shroodler.probes.xss import probe_xss

__all__ = [
    "probe_host_header",
    "probe_idor",
    "probe_jwt",
    "probe_open_redirect",
    "probe_path_traversal",
    "probe_sqli",
    "probe_ssrf",
    "probe_xss",
]
