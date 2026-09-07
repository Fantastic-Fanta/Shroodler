"""Recommended flag bundles for PR / nightly / weekly scan cadence.

Profiles (`safe`/`balanced`/`aggressive`) already exist; this is the
packaging layer the roadmap asked for: which of those to run when, plus
whether to fire payloads. It prints commands — it does not scan.
"""

from __future__ import annotations

TIERS: dict[str, dict] = {
    "pr": {
        "summary": (
            "Passive, cheap, PR-time. Safe profile only; skip payload packs."
        ),
        "crawl": ["--profile", "safe"],
        "payload": None,
    },
    "nightly": {
        "summary": (
            "Full same-origin active scan: balanced crawl plus IDOR leads "
            "and the default payload packs."
        ),
        "crawl": ["--profile", "balanced", "--check-idor"],
        "payload": [],
    },
    "weekly": {
        "summary": (
            "Aggressive crawl plus adaptive payloads. Still local-only; add "
            "--allow-external yourself when the target is authorized and remote."
        ),
        "crawl": ["--profile", "aggressive", "--check-idor"],
        "payload": ["--adaptive"],
    },
}


def recommend(tier: str, url: str = "http://127.0.0.1:8081") -> dict:
    name = (tier or "").strip().lower()
    if name not in TIERS:
        raise ValueError(f"unknown cadence tier {tier!r}; choose pr, nightly, or weekly")
    spec = TIERS[name]
    crawl_cmd = ["shroodler", "crawl", url, *spec["crawl"], "-o", "scan.json"]
    payload_flags = spec["payload"]
    payload_cmd = None
    if payload_flags is not None:
        payload_cmd = ["shroodler", "payload", "scan.json", *payload_flags, "-o", "hits.json"]
    return {
        "tier": name,
        "summary": spec["summary"],
        "url": url,
        "crawl": crawl_cmd,
        "payload": payload_cmd,
    }


def render_text(rec: dict) -> str:
    lines = [
        f"# {rec['tier']}: {rec['summary']}",
        " ".join(rec["crawl"]),
    ]
    if rec["payload"] is None:
        lines.append("# skip payload (passive-only)")
    else:
        lines.append(" ".join(rec["payload"]))
    return "\n".join(lines) + "\n"
