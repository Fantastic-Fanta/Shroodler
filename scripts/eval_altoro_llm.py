#!/usr/bin/env python3
"""Score the opt-in LLM agent against Altoro Mutual (demo.testfire.net).

Run from anywhere:
  /Users/manta/Shroodler/.venv/bin/python /Users/manta/Shroodler/scripts/eval_altoro_llm.py

Exits 2 if the target is unreachable or ANTHROPIC_API_KEY is missing.
Exits 0 if recall ≥ 0.75 against the four ground-truth categories.
This is an eval script, not a pytest test.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
RECIPE_PATH = REPO_ROOT / "reports" / "altoro" / "login-recipe.json"
TARGET = "http://demo.testfire.net"
LOGIN_URL = f"{TARGET}/doLogin"
PROTECTED = f"{TARGET}/bank/main.jsp"
STATE_PATH = Path.home() / ".shroodler" / "programs" / "altoro" / "state.json"
AGENT_TIMEOUT = 900
RECALL_THRESHOLD = 0.75

# Public Altoro Mutual demo credentials (not secrets).
_DEMO_UID = "jsmith"
_DEMO_PASS = "demo1234"

_DEFAULT_RECIPE = {
    "url": LOGIN_URL,
    "method": "POST",
    "fields": {
        "uid": _DEMO_UID,
        "passw": _DEMO_PASS,
        "btnSubmit": "Login",
    },
}

_GROUND_TRUTH = (
    ("GT-1 XSS", "gt1"),
    ("GT-2 IDOR", "gt2"),
    ("GT-3 missing-csp", "gt3"),
    ("GT-4 open-redirect/ssrf", "gt4"),
)


def _die(message: str, code: int = 2) -> int:
    print(message, file=sys.stderr)
    return code


def _ensure_recipe() -> dict:
    RECIPE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if RECIPE_PATH.is_file():
        try:
            data = json.loads(RECIPE_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = None
        if isinstance(data, dict) and data.get("url") and isinstance(data.get("fields"), dict):
            return data
    RECIPE_PATH.write_text(json.dumps(_DEFAULT_RECIPE, indent=2) + "\n", encoding="utf-8")
    return dict(_DEFAULT_RECIPE)


def _login(recipe: dict) -> str | None:
    url = str(recipe.get("url") or LOGIN_URL)
    fields = recipe.get("fields") or {}
    if not isinstance(fields, dict) or not fields:
        return None
    try:
        with httpx.Client(timeout=8.0, follow_redirects=True) as client:
            client.get(f"{TARGET}/login.jsp")
            client.post(url, data=fields)
            value = client.cookies.get("JSESSIONID")
            if not value:
                for name, val in client.cookies.items():
                    if val:
                        return f"{name}={val}"
            return f"JSESSIONID={value}" if value else None
    except httpx.HTTPError:
        return None


def _session_live(cookie_header: str) -> tuple[bool, str | None]:
    try:
        resp = httpx.get(
            PROTECTED,
            headers={"Cookie": cookie_header},
            timeout=8.0,
            follow_redirects=False,
        )
    except httpx.ConnectError:
        return False, "connect"
    except httpx.HTTPError as exc:
        return False, f"http:{type(exc).__name__}"
    return resp.status_code in {200, 302}, None


def _load_findings() -> list[dict]:
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[dict] = []
    for item in data.get("findings") or []:
        if isinstance(item, dict):
            out.append(item)
    return out


def _confirmed(finding: dict) -> bool:
    return finding.get("confidence") == "confirmed"


def _fid(finding: dict) -> str:
    return str(finding.get("id") or "").lower()


def _url(finding: dict) -> str:
    return str(finding.get("url") or "").lower()


def gt1(findings: list[dict]) -> bool:
    for finding in findings:
        if not _confirmed(finding):
            continue
        if "xss" not in _fid(finding):
            continue
        url = _url(finding)
        if "search.jsp" in url or "sendfeedback" in url:
            return True
    return False


def gt2(findings: list[dict]) -> bool:
    for finding in findings:
        if not _confirmed(finding):
            continue
        fid = _fid(finding)
        url = _url(finding)
        if "api/account" not in url:
            continue
        if "idor" in fid or "authz" in fid:
            return True
    return False


def gt3(findings: list[dict]) -> bool:
    return any(_confirmed(f) and "missing-csp" in _fid(f) for f in findings)


def gt4(findings: list[dict]) -> bool:
    for finding in findings:
        if not _confirmed(finding):
            continue
        fid = _fid(finding)
        if "open-redirect" in fid or "ssrf" in fid:
            return True
    return False


_CHECKERS = {"gt1": gt1, "gt2": gt2, "gt3": gt3, "gt4": gt4}


def _shroodler_bin() -> str:
    venv = REPO_ROOT / ".venv" / "bin" / "shroodler"
    if venv.is_file():
        return str(venv)
    found = shutil.which("shroodler")
    if found:
        return found
    return "shroodler"


def _run_agent(cookie_header: str) -> int:
    cmd = [
        _shroodler_bin(),
        "agent",
        "--program",
        "altoro",
        "--target",
        TARGET,
        "--login-recipe",
        str(RECIPE_PATH),
        "--owner-cookie",
        cookie_header,
        "--llm-agent",
        "--max-iterations",
        "20",
        "--ignore-robots",
        "--run-probes",
    ]
    print("Running:", " ".join(cmd), flush=True)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError:
        print("ERROR: shroodler CLI not found", file=sys.stderr)
        return 2
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            print(line, end="", flush=True)
        return proc.wait(timeout=AGENT_TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        print("ERROR: agent timed out", file=sys.stderr)
        return 1


def _score() -> int:
    findings = _load_findings()
    rows: list[tuple[str, bool]] = []
    for label, key in _GROUND_TRUTH:
        passed = _CHECKERS[key](findings)
        rows.append((label, passed))
        print(f"{label}: {'PASS' if passed else 'FAIL'}")
    hits = sum(1 for _, passed in rows if passed)
    total = len(rows)
    recall = hits / total if total else 0.0
    print(f"recall: {hits}/{total} = {recall:.2f}")
    return 0 if recall >= RECALL_THRESHOLD else 1


def main() -> int:
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return _die("ERROR: --llm-agent requires ANTHROPIC_API_KEY")
    try:
        probe = httpx.get(TARGET, timeout=5.0, follow_redirects=True)
        if probe.status_code >= 500:
            return _die(f"ERROR: Altoro returned HTTP {probe.status_code} at {TARGET}")
    except httpx.ConnectError:
        return _die(f"ERROR: Altoro is not reachable at {TARGET}")
    except httpx.HTTPError as exc:
        return _die(f"ERROR: Altoro is not reachable: {exc}")

    recipe = _ensure_recipe()
    cookie = _login(recipe)
    if not cookie:
        return _die("ERROR: Altoro login failed (jsmith/demo1234)")
    live, err = _session_live(cookie_header=cookie)
    if err == "connect":
        return _die(f"ERROR: Altoro is not reachable at {TARGET}")
    if not live:
        return _die("ERROR: Altoro session is not live after login")

    agent_rc = _run_agent(cookie)
    if agent_rc not in (0, None):
        print(f"WARNING: agent exited {agent_rc}; scoring saved state anyway", flush=True)
    return _score()


if __name__ == "__main__":
    sys.exit(main())
