from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import httpx

PAYLOADS = [
    ("'", "payload-sql-error"),
    ("' OR '1'='1", "payload-sql-error"),
    ("<script>alert(1)</script>", "payload-xss-reflect"),
]


def _local(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in {"127.0.0.1", "localhost", "::1"} or host.endswith(".local")


def run(crawl_doc: dict, *, client: httpx.Client | None = None) -> dict:
    target = crawl_doc.get("target", "")
    if not _local(target):
        raise ValueError("payload tester refuses non-local targets")
    http = client or httpx.Client(timeout=5.0, follow_redirects=True)
    own = client is None
    findings = []
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
                method = (form.get("method") or "GET").upper()
                fields = [f.get("name") for f in form.get("fields", []) if f.get("name")]
                if not fields:
                    fields = ["q"]
                for payload, fid in PAYLOADS:
                    data = {name: payload for name in fields}
                    if method == "GET":
                        resp = http.get(action, params=data)
                    else:
                        resp = http.post(action, data=data)
                    body = resp.text.lower()
                    if fid == "payload-sql-error" and (
                        resp.status_code >= 500 or "sql" in body or "syntax error" in body
                    ):
                        findings.append(
                            {
                                "id": fid,
                                "severity": "high",
                                "category": "payload",
                                "url": action,
                                "description": "Payload triggered a database-looking error",
                                "evidence": payload,
                            }
                        )
                    if fid == "payload-xss-reflect" and payload in resp.text:
                        findings.append(
                            {
                                "id": fid,
                                "severity": "medium",
                                "category": "payload",
                                "url": action,
                                "description": "Payload reflected in response",
                                "evidence": payload[:40],
                            }
                        )
    finally:
        if own:
            http.close()
    return {"target": target, "findings": findings}


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("crawl_json")
    p.add_argument("--output", "-o")
    args = p.parse_args(argv)
    doc = json.loads(Path(args.crawl_json).read_text(encoding="utf-8"))
    out = run(doc)
    text = json.dumps(out, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
