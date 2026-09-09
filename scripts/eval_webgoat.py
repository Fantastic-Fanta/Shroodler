#!/usr/bin/env python3
"""Score Shroodler against a local WebGoat instance.

Run from anywhere:
  /Users/manta/Shroodler/.venv/bin/python /Users/manta/Shroodler/scripts/eval_webgoat.py
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
OWNER_SESSION = REPO_ROOT / "reports" / "webgoat" / "owner-session.json"
PEER_SESSION = REPO_ROOT / "reports" / "webgoat" / "peer-session.json"
OWNER_RECIPE = REPO_ROOT / "reports" / "webgoat" / "login-recipe-owner.json"
PEER_RECIPE = REPO_ROOT / "reports" / "webgoat" / "login-recipe-peer.json"
TARGET = "http://localhost:8080/WebGoat"
PROTECTED = f"{TARGET}/service/lessonoverview.mvc"
STATE_PATH = Path.home() / ".shroodler" / "programs" / "webgoat" / "state.json"
AGENT_TIMEOUT = 900
RECALL_THRESHOLD = 0.75

_GROUND_TRUTH = (
    ("GT-1 IDOR", "gt1"),
    ("GT-2 Access Control", "gt2"),
    ("GT-3 SQL Injection", "gt3"),
    ("GT-4 XSS", "gt4"),
    ("GT-5 Path Traversal", "gt5"),
    ("GT-6 JWT", "gt6"),
    ("GT-7 Security Headers", "gt7"),
    ("GT-8 Private Key / Secrets", "gt8"),
)


def _die(message: str, code: int = 2) -> int:
    print(message, file=sys.stderr)
    return code


def _jsessionid_from_storage(path: Path) -> str | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    for cookie in data.get("cookies") or []:
        if not isinstance(cookie, dict):
            continue
        if cookie.get("name") == "JSESSIONID":
            value = cookie.get("value")
            if value:
                return str(value)
    return None


def _session_live(jsessionid: str) -> tuple[bool, str | None]:
    try:
        resp = httpx.get(
            PROTECTED,
            headers={"Cookie": f"JSESSIONID={jsessionid}"},
            timeout=8.0,
            follow_redirects=False,
        )
    except httpx.ConnectError:
        return False, "connect"
    except httpx.HTTPError as exc:
        return False, f"http:{type(exc).__name__}"
    return resp.status_code == 200, None


def _write_jsessionid(path: Path, value: str) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = {"cookies": [], "origins": []}
    if not isinstance(data, dict):
        data = {"cookies": [], "origins": []}
    cookies = list(data.get("cookies") or [])
    updated = False
    for cookie in cookies:
        if isinstance(cookie, dict) and cookie.get("name") == "JSESSIONID":
            cookie["value"] = value
            updated = True
            break
    if not updated:
        cookies.append(
            {
                "name": "JSESSIONID",
                "value": value,
                "domain": "localhost",
                "path": "/WebGoat",
                "expires": -1,
                "httpOnly": True,
                "secure": False,
                "sameSite": "Lax",
            }
        )
    data["cookies"] = cookies
    path.write_text(json.dumps(data), encoding="utf-8")


def _relogin(recipe_path: Path) -> str | None:
    if not recipe_path.is_file():
        return None
    try:
        recipe = json.loads(recipe_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(recipe, dict):
        return None
    url = str(recipe.get("url") or "")
    fields = recipe.get("fields") or {}
    if not url or not isinstance(fields, dict) or not fields:
        return None
    try:
        with httpx.Client(timeout=8.0, follow_redirects=True) as client:
            client.get(url)
            client.post(url, data=fields)
            value = client.cookies.get("JSESSIONID")
    except httpx.HTTPError:
        return None
    if not value:
        return None
    live, _ = _session_live(value)
    return value if live else None


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
    return str(finding.get("id") or "")


def _url(finding: dict) -> str:
    return str(finding.get("url") or "")


def gt1(findings: list[dict]) -> bool:
    for finding in findings:
        if not _confirmed(finding):
            continue
        fid, url = _fid(finding), _url(finding)
        if "idor" in fid:
            return True
        if "authz" in fid and "IDOR/profile" in url:
            return True
    return False


def gt2(findings: list[dict]) -> bool:
    for finding in findings:
        if not _confirmed(finding):
            continue
        if "authz" in _fid(finding) and "access-control" in _url(finding):
            return True
    return False


def gt3(findings: list[dict]) -> bool:
    return any(_confirmed(f) and "sqli" in _fid(f) for f in findings)


def gt4(findings: list[dict]) -> bool:
    return any(_confirmed(f) and "xss" in _fid(f) for f in findings)


def gt5(findings: list[dict]) -> bool:
    return any(_confirmed(f) and "path-traversal" in _fid(f) for f in findings)


def gt6(findings: list[dict]) -> bool:
    for finding in findings:
        if not _confirmed(finding):
            continue
        fid = _fid(finding)
        if "generic-jwt" in fid:
            continue
        if "jwt" in fid:
            return True
    return False


def gt7(findings: list[dict]) -> bool:
    return any(_confirmed(f) and "missing-csp" in _fid(f) for f in findings)


def gt8(findings: list[dict]) -> bool:
    for finding in findings:
        if not _confirmed(finding):
            continue
        fid = _fid(finding)
        if "private-key" in fid or "generic-api-key" in fid:
            return True
    return False


_CHECKERS = {
    "gt1": gt1,
    "gt2": gt2,
    "gt3": gt3,
    "gt4": gt4,
    "gt5": gt5,
    "gt6": gt6,
    "gt7": gt7,
    "gt8": gt8,
}


def _shroodler_bin() -> str:
    venv = REPO_ROOT / ".venv" / "bin" / "shroodler"
    if venv.is_file():
        return str(venv)
    found = shutil.which("shroodler")
    if found:
        return found
    return "shroodler"


def _reset_state_for_crawl() -> None:
    """Clear last_seen and tested_* so CrawlAction runs first and warms up lesson contexts."""
    if not STATE_PATH.is_file():
        return
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(state, dict):
        return
    for meta in (state.get("endpoints") or {}).values():
        if not isinstance(meta, dict):
            continue
        meta["last_seen"] = None
        meta.pop("tested_authz", None)
        meta.pop("tested_payload", None)
    STATE_PATH.write_text(json.dumps(state), encoding="utf-8")


def _run_agent(owner_id: str, peer_id: str) -> int:
    _reset_state_for_crawl()
    cmd = [
        _shroodler_bin(),
        "agent",
        "--program",
        "webgoat",
        "--target",
        TARGET,
        "--higher-priv-jar",
        str(OWNER_SESSION),
        "--lower-priv-jar",
        str(PEER_SESSION),
        "--owner-cookie",
        f"JSESSIONID={owner_id}",
        "--peer-cookie",
        f"JSESSIONID={peer_id}",
        "--max-iterations",
        "8",
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
    try:
        probe = httpx.get(f"{TARGET}/login", timeout=5.0, follow_redirects=False)
        probe.raise_for_status() if probe.status_code >= 500 else None
    except httpx.ConnectError:
        return _die("ERROR: WebGoat is not running at http://localhost:8080/WebGoat")
    except httpx.HTTPError as exc:
        return _die(f"ERROR: WebGoat is not reachable: {exc}")

    owner_id = _jsessionid_from_storage(OWNER_SESSION)
    peer_id = _jsessionid_from_storage(PEER_SESSION)
    if not owner_id or not peer_id:
        return _die("ERROR: sessions expired — re-login first")

    owner_ok, owner_err = _session_live(owner_id)
    peer_ok, peer_err = _session_live(peer_id)
    if owner_err == "connect" or peer_err == "connect":
        return _die("ERROR: WebGoat is not running at http://localhost:8080/WebGoat")

    if not owner_ok:
        refreshed = _relogin(OWNER_RECIPE)
        if refreshed:
            owner_id = refreshed
            _write_jsessionid(OWNER_SESSION, owner_id)
            owner_ok = True
    if not peer_ok:
        refreshed = _relogin(PEER_RECIPE)
        if refreshed:
            peer_id = refreshed
            _write_jsessionid(PEER_SESSION, peer_id)
            peer_ok = True
    if not owner_ok or not peer_ok:
        return _die("ERROR: sessions expired — re-login first")

    if not STATE_PATH.is_file():
        return _die("ERROR: state not seeded — run a full crawl first")
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _die("ERROR: state not seeded — run a full crawl first")
    endpoints = state.get("endpoints") if isinstance(state, dict) else None
    if not isinstance(endpoints, dict) or len(endpoints) < 50:
        return _die("ERROR: state not seeded — run a full crawl first")

    agent_rc = _run_agent(owner_id, peer_id)
    if agent_rc not in (0, None):
        print(f"WARNING: agent exited {agent_rc}; scoring saved state anyway", flush=True)

    return _score()


if __name__ == "__main__":
    sys.exit(main())
