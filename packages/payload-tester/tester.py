from __future__ import annotations

import json
import secrets
import string
from pathlib import Path
from urllib.parse import urlparse

import httpx
import yaml

MARKER_HOST = "shroodler-oob-test.invalid"
BASELINE_VALUE = "shroodler-baseline-probe"


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


def _path_only(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}{p.path}"


def gen_token(length: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "shrdlr" + "".join(secrets.choice(alphabet) for _ in range(length))


def build_marker_host(token: str, oob_host: str | None) -> str:
    """The host used for {{MARKER_HOST}} this run.

    Without --oob-host, this is a non-resolving placeholder: still useful
    for checks that observe success locally (e.g. an open-redirect
    Location header echoing it back), but nothing on the internet will
    ever actually reach it. With --oob-host, it's a fresh random
    subdomain of a real, reachable server the caller controls (their own
    Interactsh instance, a public oast.* service, or any box that logs
    incoming requests) -- so a payload marked "blind" can genuinely prove
    a callback happened, once the caller checks their own server's logs
    for this run's token.
    """
    if oob_host:
        return f"{token}.{oob_host}"
    return MARKER_HOST


def render_payload(raw: str, *, token: str, marker_host: str = MARKER_HOST) -> str:
    return raw.replace("{{TOKEN}}", token).replace("{{MARKER_HOST}}", marker_host)


def _clause_matches(
    clause: dict,
    *,
    status: int,
    body: str,
    payload: str,
    elapsed_ms: float | None = None,
    redirected_to: str = "",
    baseline_status: int | None = None,
    baseline_body: str = "",
    baseline_elapsed_ms: float | None = None,
    marker_host: str = MARKER_HOST,
) -> bool:
    if "status_gte" in clause and status >= int(clause["status_gte"]):
        return True
    if clause.get("error_status_changed"):
        if (
            baseline_status is not None
            and status != baseline_status
            and status >= 400
        ):
            return True
    needle = clause.get("body_contains")
    if needle is not None:
        needle_l = str(needle).lower()
        if needle_l in body.lower():
            if clause.get("new_only") and needle_l in baseline_body.lower():
                pass
            else:
                return True
    if clause.get("reflected") and payload in body:
        return True
    if "time_delta_gte_ms" in clause and elapsed_ms is not None and baseline_elapsed_ms is not None:
        if (elapsed_ms - baseline_elapsed_ms) >= float(clause["time_delta_gte_ms"]):
            return True
    marker = clause.get("redirected_to_contains")
    if marker is not None:
        needle = str(marker).replace("{{MARKER_HOST}}", marker_host).lower()
        if needle in redirected_to.lower():
            return True
    return False


def pack_matches(pack: dict, *, status: int, body: str, payload: str, **ctx) -> bool:
    match = pack.get("match") or {}
    if "all" in match:
        clauses = match["all"] or []
        return bool(clauses) and all(
            _clause_matches(c, status=status, body=body, payload=payload, **ctx) for c in clauses
        )
    clauses = match.get("any") or []
    return any(_clause_matches(c, status=status, body=body, payload=payload, **ctx) for c in clauses)


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
    allow_external: bool = False,
    oob_host: str | None = None,
) -> dict:
    target = crawl_doc.get("target", "")

    def allowed(url: str) -> bool:
        return allow_external or _local(url)

    if not allowed(target):
        raise ValueError(
            "payload tester refuses non-local targets without --allow-external "
            "(only scan hosts you are authorized to test)"
        )
    # follow_redirects=False is deliberate: a payload can put an arbitrary,
    # attacker-influenced URL in a Location header (that's exactly what the
    # open-redirect packs test for), and this tool must never actually
    # connect to it -- both because that host may not exist/respond (which
    # previously made httpx raise and silently swallow the whole check via
    # the except below) and because blindly chasing a payload-controlled
    # redirect is not something a scanner should do. Redirect detection
    # reads the immediate Location header of the single response instead.
    http = client or httpx.Client(timeout=8.0, follow_redirects=False)
    own = client is None
    findings = []
    oob_probes = []
    seen: set[tuple[str, str]] = set()
    loaded = packs if packs is not None else load_packs()
    token = gen_token()
    marker_host = build_marker_host(token, oob_host)
    try:
        for page in crawl_doc.get("pages", []):
            url = page.get("url", "")
            if not allowed(url):
                continue
            targets = list(page.get("forms", []))
            # Both crawlers already extract query-parameter names for every
            # page (plain query-string parsing populates Page.params), but
            # that data went unused here -- a bare GET endpoint with no
            # surrounding <form> (the common case for API-style targets)
            # got zero fuzzing even though its real parameter names were
            # sitting in the crawl JSON. Treat the page itself as a
            # synthetic GET-only "form" so it flows through the exact same
            # baseline/pack/dedup path as a real form below -- but only
            # when no existing form already targets the same underlying
            # path (ignoring query string): a page whose own URL has a
            # query string AND has a <form> extracted from its HTML with
            # an action resolving to that same path would otherwise get
            # the same endpoint sent every payload twice, doubling request
            # volume/side effects for no extra coverage.
            params = [p for p in page.get("params", []) if p]
            if params:
                existing_paths = set()
                for form in targets:
                    action = form.get("action") or url
                    if action.startswith("/"):
                        p = urlparse(url)
                        action = f"{p.scheme}://{p.netloc}{action}"
                    existing_paths.add(_path_only(action))
                if _path_only(url) not in existing_paths:
                    targets.append(
                        {"action": url, "method": "GET", "fields": [{"name": p} for p in params]}
                    )
            for form in targets:
                action = form.get("action") or url
                if action.startswith("/"):
                    p = urlparse(url)
                    action = f"{p.scheme}://{p.netloc}{action}"
                if not allowed(action):
                    continue
                method = (form.get("method") or "GET").upper()
                fields = [f.get("name") for f in form.get("fields", []) if f.get("name")]
                if not fields:
                    fields = ["q"]

                def send(values: dict) -> httpx.Response:
                    if method == "GET":
                        return http.get(action, params=values)
                    return http.post(action, data=values)

                baseline_data = {name: BASELINE_VALUE for name in fields}
                try:
                    baseline_resp = send(baseline_data)
                    baseline_status = baseline_resp.status_code
                    baseline_body = baseline_resp.text
                    baseline_elapsed_ms = baseline_resp.elapsed.total_seconds() * 1000
                except httpx.HTTPError:
                    baseline_status, baseline_body, baseline_elapsed_ms = None, "", None

                for pack in loaded:
                    payload = render_payload(
                        str(pack["payload"]), token=token, marker_host=marker_host
                    )
                    if pack.get("blind") and oob_host:
                        oob_probes.append(
                            {
                                "pack": pack_finding_id(pack),
                                "url": action,
                                "marker_host": marker_host,
                                "note": (
                                    "Check your OOB server's logs for a hit on "
                                    f"{marker_host} to confirm this fired."
                                ),
                            }
                        )
                    if pack.get("raw_body"):
                        if method != "POST":
                            continue
                        content_type = pack.get("content_type", "application/xml")
                        try:
                            resp = http.post(
                                action,
                                content=payload.encode("utf-8"),
                                headers={"Content-Type": content_type},
                            )
                        except httpx.HTTPError:
                            continue
                    else:
                        data = {name: payload for name in fields}
                        try:
                            resp = send(data)
                        except httpx.HTTPError:
                            continue
                    elapsed_ms = resp.elapsed.total_seconds() * 1000
                    redirected_to = resp.headers.get("location", "")
                    if not pack_matches(
                        pack,
                        status=resp.status_code,
                        body=resp.text,
                        payload=payload,
                        elapsed_ms=elapsed_ms,
                        redirected_to=redirected_to,
                        baseline_status=baseline_status,
                        baseline_body=baseline_body,
                        baseline_elapsed_ms=baseline_elapsed_ms,
                        marker_host=marker_host,
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
    return {"target": target, "findings": findings, "oob_probes": oob_probes}


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        description="Send payload packs against forms discovered by a Shroodler crawl."
    )
    p.add_argument("crawl_json")
    p.add_argument("--output", "-o")
    p.add_argument(
        "--pack",
        action="append",
        default=[],
        metavar="PATH",
        help="Extra YAML pack file or directory (repeatable); merged with default packs/",
    )
    p.add_argument(
        "--allow-external",
        action="store_true",
        help="Allow sending active payloads to non-local targets. "
        "Only use against hosts you are authorized to test.",
    )
    p.add_argument(
        "--oob-host",
        metavar="HOST",
        help="Your own out-of-band collaborator-style server (self-hosted "
        "Interactsh, an oast.* instance, or any host you control that logs "
        "incoming requests). A fresh random subdomain of it is used as "
        "{{MARKER_HOST}} in payloads each run. Shroodler cannot poll your "
        "server for you -- for 'blind' packs, check its logs afterward for "
        "the token printed in --output's oob_probes list.",
    )
    args = p.parse_args(argv)
    doc = json.loads(Path(args.crawl_json).read_text(encoding="utf-8"))
    extra = [Path(x) for x in args.pack]
    out = run(
        doc,
        packs=load_packs(extra=extra) if extra else None,
        allow_external=args.allow_external,
        oob_host=args.oob_host,
    )
    text = json.dumps(out, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
