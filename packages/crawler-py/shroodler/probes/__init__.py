"""Active injection-class probes (SQLi, XSS, path traversal, JWT, IDOR).

Opt-in via `--run-probes`. Each probe calls `paced_fetch.pace` before every
live request and fails closed on transport errors.
"""

from __future__ import annotations

from shroodler.probes.idor import probe_idor
from shroodler.probes.jwt import probe_jwt
from shroodler.probes.path_traversal import probe_path_traversal
from shroodler.probes.sqli import probe_sqli
from shroodler.probes.xss import probe_xss

__all__ = [
    "probe_idor",
    "probe_jwt",
    "probe_path_traversal",
    "probe_sqli",
    "probe_xss",
]
