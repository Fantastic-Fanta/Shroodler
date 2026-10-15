"""Active injection-class probes (SQLi, XSS, path traversal, JWT, IDOR, SSRF).

Opt-in via `--run-probes`. Each probe calls `paced_fetch.pace` before every
live request and fails closed on transport errors.
"""

from __future__ import annotations

from shroodler.probes.auth_bypass import probe_auth_bypass
from shroodler.probes.cache_poisoning import probe_cache_poisoning
from shroodler.probes.crlf import probe_crlf
from shroodler.probes.dom_xss import probe_dom_xss
from shroodler.probes.enum_id import probe_enumerable_id
from shroodler.probes.file_upload import probe_file_upload
from shroodler.probes.graphql import probe_graphql
from shroodler.probes.host_header import probe_host_header
from shroodler.probes.idor import probe_idor
from shroodler.probes.jwt import probe_jwt
from shroodler.probes.mass_assignment import probe_mass_assignment
from shroodler.probes.nosql import probe_nosql
from shroodler.probes.open_redirect import probe_open_redirect
from shroodler.probes.path_traversal import probe_path_traversal
from shroodler.probes.prototype_pollution import probe_prototype_pollution
from shroodler.probes.race_condition import probe_race_condition
from shroodler.probes.rate_limit import probe_rate_limit, probe_rate_limit_bypass
from shroodler.probes.smuggling import probe_smuggling
from shroodler.probes.sqli import probe_sqli
from shroodler.probes.ssrf import probe_ssrf
from shroodler.probes.ssti import probe_ssti
from shroodler.probes.unauth_exposure import probe_unauth_exposure
from shroodler.probes.websocket import probe_websocket
from shroodler.probes.xss import probe_xss
from shroodler.probes.xxe import probe_xxe

__all__ = [
    "probe_cache_poisoning",
    "probe_crlf",
    "probe_dom_xss",
    "probe_graphql",
    "probe_host_header",
    "probe_idor",
    "probe_jwt",
    "probe_mass_assignment",
    "probe_nosql",
    "probe_open_redirect",
    "probe_path_traversal",
    "probe_prototype_pollution",
    "probe_race_condition",
    "probe_rate_limit",
    "probe_rate_limit_bypass",
    "probe_unauth_exposure",
    "probe_auth_bypass",
    "probe_enumerable_id",
    "probe_file_upload",
    "probe_smuggling",
    "probe_sqli",
    "probe_ssrf",
    "probe_ssti",
    "probe_websocket",
    "probe_xss",
    "probe_xxe",
]
