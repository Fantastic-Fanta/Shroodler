"""Agent action and configuration types.

The AgentConfig knobs, the per-action marker dataclasses, and AgentResult,
split out of agent.py so the decision loop and executors read against a
small, dependency-free types module. Re-exported by agent.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentConfig:
    program: str
    target: str
    max_iterations: int = 10
    max_pages_per_crawl: int = 30
    login_recipe: str | None = None
    reauth_max_retries: int = 3
    higher_priv_jar: str | None = None
    lower_priv_jar: str | None = None
    owner_cookie: str | None = None
    peer_cookie: str | None = None
    dry_run: bool = False
    llm_triage: bool = False  # opt-in; requires the provider API key in env
    run_discovery: bool = False  # run discover() before the first iteration
    ignore_robots: bool = False  # bypass robots.txt (use for API-first targets)
    harvest_robots: bool = False  # aggressive: seed + surface robots Disallow leads
    write_authz_spec: str | None = None
    write_authz_endpoints: list[dict] | None = None
    run_probes: bool = False  # opt-in; default off
    probe_sqli: bool = True
    probe_nosql: bool = True
    probe_time_sqli: bool = True
    probe_xss: bool = True
    probe_path_traversal: bool = True
    probe_jwt: bool = True
    probe_idor: bool = True
    run_ssrf: bool = True
    run_open_redirect: bool = True
    run_host_header: bool = True
    run_cache_poisoning: bool = True
    run_file_upload: bool = True
    run_race_condition: bool = False  # side-effecting; aggressive mode only
    run_ssti: bool = True
    run_xxe: bool = True
    run_graphql: bool = True
    auto_register: bool = True
    reprobe: bool = False  # reset tested_payload before the loop
    run_diff: bool = False  # opt-in; also auto-runs when a previous run exists
    run_business_logic: bool = False  # --llm-business-logic
    chain_specs: list[str] = field(default_factory=list)
    # --workflow-mutate: for each chain-spec, also run skip-step/replay bypass
    # mutations of that workflow and flag mutations that still succeed.
    workflow_mutate: bool = False
    run_openapi_discovery: bool = True  # on by default; mapping, not probing
    run_openapi_probes: bool = True
    run_dom_xss: bool = False  # opt-in; headless / slow
    run_crlf: bool = True
    run_prototype_pollution: bool = True
    run_content_discovery: bool = True
    run_tls_check: bool = True
    run_rate_limit: bool = True
    run_unauth_exposure: bool = True  # anon read of sensitive API endpoints
    run_mass_assignment: bool = True
    run_smuggling: bool = False  # opt-in; aggressive
    aggressive: bool = False  # --aggressive: no pacing, parallel probing, all probes
    run_websocket: bool = True
    allow_external: bool = False
    scope_file: str | None = None
    # Operator-supplied context about the target (what it is, what matters, what
    # abuse means here). Grounds the LLM's business-logic reasoning.
    context_note: str = ""
    # --prove-impact: after the scan, demonstrate bounded read-only impact for
    # confirmed findings (e.g. read back the DB version for a confirmed SQLi).
    prove_impact: bool = False
    llm_agent: bool = False  # --llm-agent; requires the provider API key
    llm_provider: str = "deepseek"  # "deepseek" | "anthropic"
    llm_agent_model: str = "deepseek-chat"  # cheap, high-volume planner model
    # Stronger model reserved for hard reasoning (analyze_logic, verify_finding).
    # Blank resolves to the provider default reasoner (deepseek-reasoner / opus).
    llm_agent_reasoning_model: str = "deepseek-reasoner"
    llm_agent_max_cost_usd: float = 5.0
    # Auto-verify tentative findings against fresh evidence before reporting.
    llm_auto_verify: bool = True
    # --llm-verify: run the LLM verifier over findings after a deterministic
    # scan (the deterministic loop never calls report(), so report-time
    # auto-verify doesn't fire). Requires a provider key.
    llm_verify: bool = False
    run_js_analysis: bool = True  # --no-js-analysis to skip
    run_waf_detect: bool = True  # --no-waf-detect to skip
    idor_methods: list[str] = field(default_factory=lambda: ["GET"])
    peer_recipe: str | None = None
    oob: bool = False  # --oob; local HTTP callback collaborator
    oob_listen: str = "127.0.0.1:8765"
    oob_public_url: str = ""
    # Network engine for crawling. The Go engine (shroodler-go via go_engine)
    # is now the sole crawl path; the in-process Python crawler was retired in
    # the Go consolidation. Retained for CLI compatibility -- the agent always
    # crawls through the Go engine regardless of this value.
    engine: str = "go"


@dataclass
class LoginAction:
    pass


@dataclass
class TLSCheckAction:
    pass


@dataclass
class WafDetectAction:
    pass


@dataclass
class ContentDiscoverAction:
    pass


@dataclass
class CrawlAction:
    urls: list[str]


@dataclass
class JSAnalysisAction:
    urls: list[str] = field(default_factory=list)


@dataclass
class DiffAction:
    pass


@dataclass
class OpenApiDiscoverAction:
    pass


@dataclass
class AutoRegisterAction:
    pass


@dataclass
class AuthzDiffAction:
    urls: list[str]


@dataclass
class IDORScanAction:
    pass


@dataclass
class WriteAuthzAction:
    endpoints: list[dict]


@dataclass
class PeerWriteAction:
    object_ids: list[str]


@dataclass
class ProbeAction:
    urls: list[str]


@dataclass
class OpenApiProbeAction:
    endpoints: list[dict]


@dataclass
class BusinessLogicAction:
    pass


@dataclass
class ChainAction:
    pass


@dataclass
class ReportAction:
    pass


AgentAction = (
    LoginAction
    | TLSCheckAction
    | WafDetectAction
    | ContentDiscoverAction
    | CrawlAction
    | JSAnalysisAction
    | DiffAction
    | OpenApiDiscoverAction
    | AutoRegisterAction
    | AuthzDiffAction
    | IDORScanAction
    | WriteAuthzAction
    | PeerWriteAction
    | ProbeAction
    | OpenApiProbeAction
    | BusinessLogicAction
    | ChainAction
    | ReportAction
)


@dataclass
class AgentResult:
    iterations: int
    confirmed: int
    log: list[dict[str, Any]]
    state_path: str = ""
    errors: list[str] = field(default_factory=list)
