from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import httpx
import yaml


def packs_dir() -> Path:
    here = Path(__file__).resolve().parent
    candidate = here / "packs"
    if candidate.is_dir():
        return candidate
    for parent in here.parents:
        alt = parent / "packages" / "payload-tester" / "packs"
        if alt.is_dir():
            return alt
    raise FileNotFoundError("payload-tester/packs not found")


def _load_pack_file(path: Path) -> list[dict]:
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(loaded, list):
        raise TypeError(f"{path} must be a YAML list of packs")
    packs: list[dict] = []
    for item in loaded:
        if not isinstance(item, dict) or "id" not in item or "payload" not in item:
            raise ValueError(f"{path} has a pack missing id/payload")
        packs.append(item)
    return packs


def load_packs(
    directory: Path | None = None,
    extra: list[Path] | None = None,
) -> list[dict]:
    d = directory or packs_dir()
    packs: list[dict] = []
    for path in sorted(d.glob("*.yaml")):
        packs.extend(_load_pack_file(path))
    for raw in extra or []:
        p = Path(raw)
        if p.is_dir():
            packs.extend(load_packs(directory=p, extra=None))
        else:
            packs.extend(_load_pack_file(p))
    return packs


def pack_finding_id(pack: dict) -> str:
    return str(pack.get("finding_id") or pack["id"])


def _local(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in {"127.0.0.1", "localhost", "::1"} or host.endswith(".local")


def _clause_matches(clause: dict, *, status: int, body: str, payload: str) -> bool:
    if "status_gte" in clause and status >= int(clause["status_gte"]):
        return True
    needle = clause.get("body_contains")
    if needle is not None and str(needle).lower() in body.lower():
        return True
    return bool(clause.get("reflected") and payload in body)


def pack_matches(pack: dict, *, status: int, body: str, payload: str) -> bool:
    match = pack.get("match") or {}
    if "all" in match:
        clauses = match["all"] or []
        return bool(clauses) and all(
            _clause_matches(c, status=status, body=body, payload=payload) for c in clauses
        )
    clauses = match.get("any") or []
    return any(_clause_matches(c, status=status, body=body, payload=payload) for c in clauses)


def _finding(pack: dict, action: str, payload: str) -> dict:
    ev = payload if len(payload) <= 80 else payload[:80]
    return {
        "id": pack_finding_id(pack),
        "severity": pack.get("severity", "medium"),
        "category": "payload",
        "url": action,
        "description": pack.get("description", pack_finding_id(pack)),
        "evidence": ev,
    }


def run(
    crawl_doc: dict,
    *,
    client: httpx.Client | None = None,
    packs: list[dict] | None = None,
) -> dict:
    target = crawl_doc.get("target", "")
    if not _local(target):
        raise ValueError("payload tester refuses non-local targets")
    http = client or httpx.Client(timeout=5.0, follow_redirects=True)
    own = client is None
    findings = []
    seen: set[tuple[str, str]] = set()
    loaded = packs if packs is not None else load_packs()
    try:
        for page in crawl_doc.get("pages", []):
            url = page.get("url", "")
            if not _local(url):
                continue
            for form in page.get("forms", []):
                action = form.get("action") or url
                if action.startswith("/"):
                    p = urlparse(url)
                    action = f"{p.scheme}://{p.netloc}{action}"
                if not _local(action):
                    continue
                method = (form.get("method") or "GET").upper()
                fields = [f.get("name") for f in form.get("fields", []) if f.get("name")]
                if not fields:
                    fields = ["q"]
                for pack in loaded:
                    payload = str(pack["payload"])
                    data = {name: payload for name in fields}
                    if method == "GET":
                        resp = http.get(action, params=data)
                    else:
                        resp = http.post(action, data=data)
                    if not pack_matches(
                        pack, status=resp.status_code, body=resp.text, payload=payload
                    ):
                        continue
                    key = (pack_finding_id(pack), action)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(_finding(pack, action, payload))
    finally:
        if own:
            http.close()
    return {"target": target, "findings": findings}


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("crawl_json")
    p.add_argument("--output", "-o")
    p.add_argument(
        "--pack",
        action="append",
        default=[],
        metavar="PATH",
        help="Extra YAML pack file or directory (repeatable); merged with default packs/",
    )
    args = p.parse_args(argv)
    doc = json.loads(Path(args.crawl_json).read_text(encoding="utf-8"))
    extra = [Path(x) for x in args.pack]
    out = run(doc, packs=load_packs(extra=extra) if extra else None)
    text = json.dumps(out, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
