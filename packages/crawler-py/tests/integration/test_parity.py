from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]
SCRIPT = ROOT / "packages" / "parity-tests" / "run_parity.py"


def _up(port: int) -> bool:
    import httpx

    try:
        return httpx.get(f"http://127.0.0.1:{port}/", timeout=1.0).status_code in {200, 401}
    except httpx.HTTPError:
        return False


@pytest.mark.skipif(not (_up(8081) and _up(8083) and _up(8084)), reason="targets not running")
def test_parity_app1_app3_app4():
    env = os.environ.copy()
    env["PATH"] = str(ROOT / ".venv" / "bin") + ":" + env.get("PATH", "")
    r = subprocess.run(
        [str(ROOT / ".venv" / "bin" / "python"), str(SCRIPT)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr
