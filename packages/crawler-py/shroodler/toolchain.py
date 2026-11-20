"""Approval-gated argv runner for external tools.

Commands are a list of arguments, never a shell string. A rule matches a
single command whose leading tokens equal the rule's argv prefix. Pipes,
redirects, shell wrappers, and environment-assignment prefixes are rejected
before anything is executed. Destinations have to sit in program scope, and
a non-local host still needs ``--allow-external``.

Apache-2.0. Shroodler's own gate. It does not copy another project's code.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from shroodler.program import program_dir
from shroodler.urls import is_loopback_or_local
from shroodler.util import now_iso

# Binaries the agent may run once an approval rule (or a human) says so.
# Anything else needs a rule whose prefix names that binary. curl is
# deliberately NOT here: it is a general-purpose HTTP client (arbitrary methods,
# redirects, exfiltration), so it must be named by an explicit operator allow
# rule rather than run as a "known scanner". The HTTP a probe needs goes through
# send_request / replay, which are scoped.
KNOWN_BINARIES = frozenset(
    {"nmap", "nuclei", "httpx", "katana", "ffuf", "sqlmap"}
)
_SHELLS = frozenset(
    {"bash", "sh", "zsh", "dash", "ash", "cmd", "powershell", "pwsh", "fish"}
)
_SHELL_CHARS = set("|;&<>`$()\n\r")
_MAX_ARGV = 64
_MAX_PREFIX = 8


@dataclass
class ToolDecision:
    allowed: bool
    reason: str = ""
    decider: str = "rule"  # human | rule | scope | budget
    argv: list[str] | None = None


def approvals_path(slug: str) -> Path:
    return program_dir(slug) / "approvals.json"


def audit_path(slug: str) -> Path:
    return program_dir(slug) / "audit.jsonl"


def load_approvals(slug: str) -> list[dict[str, Any]]:
    path = approvals_path(slug)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    rows = data.get("rules") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        argv = row.get("argv")
        effect = str(row.get("effect") or "").strip().lower()
        action = str(row.get("action") or "").strip()
        if effect not in {"allow", "deny"}:
            continue
        tokens: list[str] = []
        if isinstance(argv, list):
            tokens = [str(tok) for tok in argv if str(tok)]
            if len(tokens) > _MAX_PREFIX:
                continue
        if not tokens and not action:
            continue
        out.append({"argv": tokens, "effect": effect, "action": action})
    return out


def save_approvals(slug: str, rules: list[dict[str, Any]]) -> Path:
    path = approvals_path(slug)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"rules": rules}, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def append_audit(slug: str, record: dict[str, Any]) -> None:
    if not slug:
        return
    path = audit_path(slug)
    path.parent.mkdir(parents=True, exist_ok=True)
    row = dict(record)
    row.setdefault("at", now_iso())
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, default=str) + "\n")


def reject_shell(argv: list[Any]) -> str | None:
    """Return a reason when argv is not one plain command."""
    if not isinstance(argv, list) or not argv:
        return "argv must be a non-empty list"
    if len(argv) > _MAX_ARGV:
        return "argv is too long"
    for index, raw in enumerate(argv):
        if not isinstance(raw, str) or not raw.strip():
            return "argv tokens must be non-empty strings"
        token = raw.strip()
        if any(ch in token for ch in _SHELL_CHARS):
            return "shell syntax is rejected"
        if index == 0 and "=" in token and not token.startswith("-"):
            return "environment assignment prefix is rejected"
        # Only http/https targets. file://, gopher://, dict://, ftp:// etc. carry
        # no host (so the scope check cannot see them) and are classic local-file
        # read / SSRF vectors.
        if "://" in token and token.split("://", 1)[0].lower() not in {"http", "https"}:
            return "only http/https URL schemes are allowed"
    first = str(argv[0]).strip()
    # The gate authorizes by basename, so the binary must BE a bare name:
    # a path like /tmp/evil/nmap would pass a name check but execute the path.
    if "/" in first or "\\" in first:
        return "binary must be a bare name, not a path"
    if first in _SHELLS:
        return "shell wrapper is rejected"
    return None


def match_rule(argv: list[str], rules: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Longest argv-prefix rule whose tokens equal the command's leading tokens.

    Flags after the prefix are covered. A different second token is not.
    """
    best: dict[str, Any] | None = None
    best_len = 0
    for rule in rules:
        prefix = [str(tok) for tok in (rule.get("argv") or [])]
        if not prefix or len(prefix) > _MAX_PREFIX or len(prefix) > len(argv):
            continue
        if argv[: len(prefix)] != prefix:
            continue
        if len(prefix) > best_len:
            best = rule
            best_len = len(prefix)
    return best


def _match_action_rule(name: str, rules: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Longest action-name prefix, then an argv prefix of that same name."""
    best: dict[str, Any] | None = None
    best_len = 0
    for rule in rules:
        action = str(rule.get("action") or "")
        if not action:
            continue
        if name != action and not name.startswith(action + "-"):
            continue
        if len(action) > best_len:
            best = rule
            best_len = len(action)
    if best is not None:
        return best
    return match_rule([name], rules)


def authorize_action(
    name: str,
    *,
    slug: str,
    rules: list[dict[str, Any]] | None = None,
    interactive: bool = False,
    approve_active: bool = False,
    prompter: Callable[[list[str]], bool] | None = None,
    audit: bool = True,
) -> ToolDecision:
    """Decide whether a built-in mutating action may run.

    With ``approve_active`` off, checklist actions stay allowed and nothing
    prompts. With it on, the action needs an allow rule or a single terminal
    yes. ``run_tool`` is not this gate; argv stays deny-by-default.
    """
    label = str(name or "").strip()
    if not approve_active:
        decision = ToolDecision(True, "built-in action allowed", "rule", [label])
        _maybe_audit(slug, decision, audit, None)
        return decision
    loaded = list(rules) if rules is not None else load_approvals(slug)
    rule = _match_action_rule(label, loaded)
    if rule is not None and rule.get("effect") == "deny":
        decision = ToolDecision(False, "denied by approval rule", "rule", [label])
        _maybe_audit(slug, decision, audit, None)
        return decision
    if rule is not None and rule.get("effect") == "allow":
        decision = ToolDecision(True, "allowed by approval rule", "rule", [label])
        _maybe_audit(slug, decision, audit, None)
        return decision
    if interactive:
        ask = prompter or _prompt_stdin
        try:
            approved = bool(ask([label]))
        except Exception:  # noqa: BLE001 - a broken prompt denies
            approved = False
        if approved:
            decision = ToolDecision(True, "approved by human", "human", [label])
        else:
            decision = ToolDecision(False, "denied by human", "human", [label])
        _maybe_audit(slug, decision, audit, None)
        return decision
    decision = ToolDecision(False, "no matching approval rule", "rule", [label])
    _maybe_audit(slug, decision, audit, None)
    return decision


def hosts_in_argv(argv: list[str]) -> list[str]:
    hosts: list[str] = []
    for token in argv[1:]:
        if token.startswith("-"):
            continue
        host = ""
        if "://" in token:
            try:
                host = (urlparse(token).hostname or "").lower()
            except Exception:  # noqa: BLE001
                host = ""
        elif _looks_like_host(token):
            host = token.lower().strip("[]")
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def _looks_like_host(token: str) -> bool:
    text = token.strip().strip("[]")
    if not text or "/" in text or text.startswith("-"):
        return False
    if text.count(".") == 3 and all(part.isdigit() for part in text.split(".")):
        return True
    return "." in text and " " not in text and not text.startswith(".")


def host_in_scope(host: str, scope_hosts: list[str] | None) -> bool:
    """Loopback is always in scope. Any other host must match a declared pattern."""
    if _is_loopback_host(host):
        return True
    patterns = [str(item).lower() for item in (scope_hosts or []) if str(item)]
    if not patterns:
        return False
    lowered = host.lower()
    for pattern in patterns:
        if pattern.startswith("*."):
            suffix = pattern[1:]
            apex = pattern[2:]
            if lowered == apex or lowered.endswith(suffix):
                return True
        elif lowered == pattern or lowered.endswith("." + pattern):
            return True
    return False


def _is_loopback_host(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        return True
    if host.startswith("127."):
        return True
    return is_loopback_or_local(f"http://{host}/")


def scope_hosts_from(scope_urls: list[str] | None, extra: list[str] | None = None) -> list[str]:
    hosts: list[str] = []
    for raw in list(scope_urls or []) + list(extra or []):
        text = str(raw or "").strip()
        if not text:
            continue
        if "://" in text:
            host = (urlparse(text).hostname or "").lower()
        else:
            host = text.lower().lstrip("*.").split("/")[0]
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def authorize(
    argv: list[Any],
    *,
    slug: str,
    allow_external: bool = False,
    scope_hosts: list[str] | None = None,
    rules: list[dict[str, Any]] | None = None,
    interactive: bool = False,
    prompter: Callable[[list[str]], bool] | None = None,
    audit: bool = True,
    trace_id: str | None = None,
) -> ToolDecision:
    """Decide whether this argv may run. Writes an audit line when ``audit`` is set."""
    tokens = [str(item) for item in argv] if isinstance(argv, list) else []
    shell_reason = reject_shell(argv if isinstance(argv, list) else [])
    if shell_reason:
        decision = ToolDecision(False, shell_reason, "scope", tokens)
        _maybe_audit(slug, decision, audit, trace_id)
        return decision

    binary = Path(tokens[0]).name
    argv_hosts = hosts_in_argv(tokens)
    for host in argv_hosts:
        if not host_in_scope(host, scope_hosts):
            decision = ToolDecision(False, f"out of scope: {host}", "scope", tokens)
            _maybe_audit(slug, decision, audit, trace_id)
            return decision
        if not allow_external and not _is_loopback_host(host):
            decision = ToolDecision(
                False,
                f"{host} requires --allow-external",
                "scope",
                tokens,
            )
            _maybe_audit(slug, decision, audit, trace_id)
            return decision

    # A network scanner that names no host in argv (e.g. nuclei -l targets.txt)
    # would run against a target set the scope check never sees. Require an
    # in-scope host on the command line so scope stays verifiable, even for an
    # operator-allowed binary.
    if binary in KNOWN_BINARIES and not argv_hosts:
        decision = ToolDecision(
            False,
            f"{binary} names no target host in argv; target scope cannot be verified",
            "scope",
            tokens,
        )
        _maybe_audit(slug, decision, audit, trace_id)
        return decision

    loaded = list(rules) if rules is not None else load_approvals(slug)
    rule = match_rule(tokens, loaded)
    if rule is not None and rule.get("effect") == "deny":
        decision = ToolDecision(False, "denied by approval rule", "rule", tokens)
        _maybe_audit(slug, decision, audit, trace_id)
        return decision
    if rule is not None and rule.get("effect") == "allow":
        decision = ToolDecision(True, "allowed by approval rule", "rule", tokens)
        _maybe_audit(slug, decision, audit, trace_id)
        return decision

    if binary not in KNOWN_BINARIES:
        decision = ToolDecision(
            False,
            f"{binary} needs an approval rule that names it",
            "rule",
            tokens,
        )
        _maybe_audit(slug, decision, audit, trace_id)
        return decision

    if interactive:
        ask = prompter or _prompt_stdin
        try:
            approved = bool(ask(tokens))
        except Exception:  # noqa: BLE001 - a broken prompt denies
            approved = False
        if approved:
            decision = ToolDecision(True, "approved by human", "human", tokens)
        else:
            decision = ToolDecision(False, "denied by human", "human", tokens)
        _maybe_audit(slug, decision, audit, trace_id)
        return decision

    decision = ToolDecision(False, "no matching approval rule", "rule", tokens)
    _maybe_audit(slug, decision, audit, trace_id)
    return decision


def _prompt_stdin(argv: list[str]) -> bool:
    answer = input("approve " + " ".join(argv) + "? [y/N] ")
    return answer.strip().lower() in {"y", "yes"}


def _maybe_audit(slug: str, decision: ToolDecision, audit: bool, trace_id: str | None) -> None:
    if not audit or not slug:
        return
    append_audit(
        slug,
        {
            "argv": list(decision.argv or []),
            "allowed": decision.allowed,
            "decider": decision.decider,
            "reason": decision.reason,
            "trace_id": trace_id,
        },
    )


def resolve_binary(argv: list[str]) -> str | None:
    if not argv:
        return None
    return shutil.which(Path(argv[0]).name)


def execute_approved(
    argv: list[Any],
    *,
    slug: str,
    allow_external: bool = False,
    scope_hosts: list[str] | None = None,
    rules: list[dict[str, Any]] | None = None,
    interactive: bool = False,
    prompter: Callable[[list[str]], bool] | None = None,
    runner: Callable[..., Any] | None = None,
    timeout: float = 30.0,
    output_cap: int = 4096,
    pacer: Any = None,
) -> dict[str, Any]:
    """Authorize, pace, and run. The returned record is never verified.

    ``runner`` replaces the process spawn in tests. When it is omitted, the
    binary must be on PATH.
    """
    from shroodler.exploration import append_trace

    gate = authorize(
        argv,
        slug=slug,
        allow_external=allow_external,
        scope_hosts=scope_hosts,
        rules=rules,
        interactive=interactive,
        prompter=prompter,
        audit=True,
    )
    if not gate.allowed:
        return {
            "verified": False,
            "error": gate.reason,
            "decider": gate.decider,
            "output": "",
            "trace_id": "",
        }
    tokens = list(gate.argv or [])
    if runner is None and resolve_binary(tokens) is None:
        return {
            "verified": False,
            "error": f"{tokens[0]} is not on PATH",
            "decider": gate.decider,
            "output": "",
            "trace_id": "",
        }
    if pacer is not None:
        for host in hosts_in_argv(tokens) or [""]:
            if host:
                pacer.wait(host)
    ran = run_argv(tokens, timeout=timeout, output_cap=output_cap, runner=runner)
    output = str(ran.get("output") or "")
    trace_id = ""
    if slug:
        trace_id = append_trace(slug, action="run_tool", output=output, argv=tokens)
    return {
        "verified": False,
        "error": ran.get("error") or "",
        "decider": gate.decider,
        "output": output,
        "returncode": ran.get("returncode"),
        "trace_id": trace_id,
        "argv": tokens,
    }


def run_argv(
    argv: list[str],
    *,
    timeout: float = 30.0,
    output_cap: int = 4096,
    runner: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Run argv with ``shell=False``. A fake ``runner`` is for tests.

    The result is text. It is never a verified finding.
    """
    invoke = runner or subprocess.run
    try:
        completed = invoke(
            list(argv),
            capture_output=True,
            text=True,
            timeout=float(timeout),
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _clip(getattr(exc, "stdout", "") or "", output_cap)
        return {
            "returncode": None,
            "output": stdout,
            "error": "timeout",
            "verified": False,
        }
    stdout = _clip(getattr(completed, "stdout", "") or "", output_cap)
    stderr = _clip(getattr(completed, "stderr", "") or "", output_cap)
    text = stdout
    if stderr:
        text = f"{stdout}\n{stderr}".strip()
    return {
        "returncode": getattr(completed, "returncode", None),
        "output": text[:output_cap],
        "error": "",
        "verified": False,
    }


def _clip(text: Any, limit: int) -> str:
    raw = text if isinstance(text, str) else ""
    if limit <= 0:
        return ""
    return raw[:limit]


def frame_untrusted(text: str, nonce: str) -> str:
    """Wrap tool output so a planner treats it as data, not instructions."""
    token = (nonce or "data").strip() or "data"
    body = text or ""
    return f"BEGIN UNTRUSTED {token}\n{body}\nEND UNTRUSTED {token}"


def in_wrap_up(config: Any) -> bool:
    """True when the remaining token or turn budget is inside the reserve.

    A zero budget is unlimited. Inside the reserve the loop may only report.
    The token reserve is 5% of the budget, and at least 20,000 once the
    budget itself is at least 20,000. The turn reserve is 2 (or 1 when the
    budget is smaller than that).
    """
    token_budget = int(getattr(config, "token_budget", 0) or 0)
    turn_budget = int(getattr(config, "turn_budget", 0) or 0)
    tokens = int(getattr(config, "_llm_tokens", 0) or 0)
    turns = int(getattr(config, "_llm_turns", 0) or 0)
    if token_budget > 0:
        reserve = max(int(token_budget * 0.05), 1)
        if token_budget >= 20_000:
            reserve = max(reserve, 20_000)
        if token_budget - tokens <= reserve:
            return True
    if turn_budget > 0:
        reserve_turns = 2 if turn_budget > 2 else 1
        if turn_budget - turns <= reserve_turns:
            return True
    return False
