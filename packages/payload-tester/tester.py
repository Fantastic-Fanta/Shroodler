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


# The riskiest idea on the roadmap ("LLM-generated/adapted payload
# mutation") is scoped deliberately narrowly here: at most ONE extra,
# enforcer-gated request per pack per baseline miss, never a second
# round of mutation on top of a mutation, and off unless a caller
# explicitly opts in (`adaptive=True`). This is a place a small team
# could plausibly beat a static-pack scanner's coverage without needing
# CVE-signature scale -- but it's also live payload generation against a
# real target, so the same scope/rate/blast-radius guardrail that gates
# every other active send here gates this too (see `run()`'s
# `request_allowed()`).
_KEYWORD_CASE_TARGETS = (
    "select",
    "union",
    "script",
    "alert",
    "or",
    "and",
    "from",
    "where",
)


def _default_mutate(payload: str) -> str:
    """Built-in fallback mutator, used when SHROODLER_PAYLOAD_MUTATE_CMD
    isn't set: alternates the case of common filtered/signature-matched
    keywords (SeLeCt, ScRiPt, ...) plus an inline SQL comment between two
    of them -- classic, well-documented WAF/naive-filter evasion shapes,
    not a claim of novel attack research. Deterministic (no randomness)
    so a run is reproducible.
    """
    mutated = payload
    for keyword in _KEYWORD_CASE_TARGETS:
        if keyword not in mutated.lower():
            continue
        alternated = "".join(
            c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(keyword)
        )
        # Case-insensitive single replace of the first occurrence.
        idx = mutated.lower().find(keyword)
        mutated = mutated[:idx] + alternated + mutated[idx + len(keyword) :]
    if mutated == payload:
        # No recognizable keyword to case-flip -- fall back to wrapping
        # the payload in an inline comment, a generic filter-bypass shape
        # that doesn't depend on recognizing specific keywords.
        mutated = f"/**/{payload}/**/"
    return mutated


def mutate_payload(payload: str, *, context: dict) -> str | None:
    """Returns an adapted payload, or None if mutation isn't applicable/
    configured. If SHROODLER_PAYLOAD_MUTATE_CMD is set, it's invoked with
    `context` (finding_id, pack_id, original payload, and the first
    probe's response status/snippet) as JSON on stdin and must print a
    single replacement payload on stdout (empty output means "no
    mutation"); otherwise falls back to `_default_mutate`.
    """
    import os
    import shlex
    import subprocess

    cmd = os.environ.get("SHROODLER_PAYLOAD_MUTATE_CMD")
    if not cmd:
        return _default_mutate(payload)
    try:
        # shlex's POSIX mode (the default) treats "\" as an escape
        # character, which mangles an unquoted Windows path like
        # "C:\Program Files\mutate.exe" -- non-POSIX mode leaves
        # backslashes alone, matching how Windows command lines are
        # actually written.
        argv = shlex.split(cmd, posix=(os.name != "nt"))
    except ValueError:
        return None
    if not argv:
        return None
    try:
        proc = subprocess.run(
            argv,
            input=json.dumps({**context, "payload": payload}),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    result = proc.stdout.strip()
    return result or None


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
    response_headers: httpx.Headers | None = None,
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
    header_needle = clause.get("header_contains")
    if header_needle is not None and response_headers is not None:
        # Checks every response header VALUE (not just Location), because
        # a real HTTP response-splitting bug lands the injected text in
        # whichever header the client's own HTTP parser happens to split
        # it into (often an extra Set-Cookie/X-* line, not the header the
        # vulnerable field was originally building) -- redirected_to_contains
        # alone only ever sees Location and would miss that.
        needle = str(header_needle).lower()
        if any(needle in str(v).lower() for v in response_headers.values()):
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


def _clause_kinds(pack: dict) -> set[str]:
    match = pack.get("match") or {}
    clauses = match.get("all") or match.get("any") or []
    return {k for c in clauses if isinstance(c, dict) for k in c}


def _matched_clause_kinds(pack: dict, **ctx) -> set[str]:
    """Which clause(s) actually matched THIS response, not the pack's
    static clause inventory. A pack combining a strong marker clause and
    a weak `reflected: true` fallback in one `any:` block must not be
    classified by "the pack contains a reflected clause" when the run
    that matched did so via the strong clause -- see `_confidence_for`.
    For an `all:` pack every listed clause had to match, so this is the
    union of every clause's kind either way.
    """
    match = pack.get("match") or {}
    clauses = match.get("all") or match.get("any") or []
    kinds: set[str] = set()
    for c in clauses:
        if isinstance(c, dict) and _clause_matches(c, **ctx):
            kinds |= set(c)
    return kinds


def _confidence_for(pack: dict, matched_kinds: set[str]) -> str:
    """Confidence classification driven by which clause(s) actually fired
    on this response (`matched_kinds`), not merely which clause *types*
    the pack happens to contain -- so a pack that combines a strong
    marker/error-signature clause with a weaker `reflected: true`
    fallback in the same `any:` block is graded by whichever of them
    actually matched, never downgraded just because a weaker clause is
    also present in the pack. An explicit per-pack `confidence:` key
    always wins over this inference.
    """
    if pack.get("confidence"):
        return str(pack["confidence"])
    if pack.get("blind"):
        return "probable"
    # Anything beyond "reflected"/"time_delta_gte_ms" required the target
    # to compute/execute something or produced an unambiguous
    # error-signature -- confirmed, even if a weaker clause also fired.
    strong = matched_kinds - {"reflected", "time_delta_gte_ms"}
    if strong:
        return "confirmed"
    if "time_delta_gte_ms" in matched_kinds:
        return "probable"
    if matched_kinds:
        return "heuristic"
    # No context available (e.g. a caller classifying a pack in the
    # abstract, without a matched response) -- fall back to the pack's
    # static clause inventory.
    kinds = _clause_kinds(pack)
    if "time_delta_gte_ms" in kinds:
        return "probable"
    if kinds and kinds <= {"reflected"}:
        return "heuristic"
    return "confirmed"


def infer_confidence(pack: dict) -> str:
    """Static, per-pack confidence classification with no match context
    available -- used by callers that only have the pack definition
    (e.g. documentation/listing tools). Prefer `_confidence_for` with
    `matched_kinds` from an actual response wherever one exists.
    """
    return _confidence_for(pack, matched_kinds=set())


_CONFIDENCE_RANK = {"confirmed": 0, "probable": 1, "heuristic": 2}


def _finding(pack: dict, action: str, payload: str, confidence: str, *, mutated: bool = False) -> dict:
    ev = payload if len(payload) <= 80 else payload[:80]
    description = pack.get("description", pack_finding_id(pack))
    if mutated:
        description += (
            " (matched only after an adaptive payload mutation -- the static "
            "pack's own payload did not trigger this; verify manually.)"
        )
    return {
        "id": pack_finding_id(pack),
        "severity": pack.get("severity", "medium"),
        "category": "payload",
        "url": action,
        "description": description,
        "evidence": ev,
        "confidence": confidence,
    }


def run(
    crawl_doc: dict,
    *,
    client: httpx.Client | None = None,
    packs: list[dict] | None = None,
    allow_external: bool = False,
    oob_host: str | None = None,
    enforcer=None,
    adaptive: bool = False,
) -> dict:
    """`enforcer`, if given, is a `shroodler_guardrails.policy.PolicyEnforcer`
    consulted before every live request (baseline probe and each payload
    send): scope, rate-limit, and blast-radius decisions all flow through
    it, and every attempt -- allowed or blocked -- lands in its audit log.
    A blocked URL is skipped for the rest of this run (all of its packs),
    not just the one send that tripped the limit.

    `adaptive`, if set, allows exactly ONE extra mutated-payload retry per
    pack per baseline miss (see `mutate_payload`) -- never a second round
    on top of that mutation, and every mutated send still goes through
    the same `enforcer`/`request_allowed()` gate as every other request
    here. Off by default.
    """
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

                def request_allowed(target_url: str = action) -> bool:
                    # Checked once per actual outbound HTTP request (baseline
                    # probe AND every payload send below), not once per form
                    # -- a form fuzzed with N packs makes N+1 live requests,
                    # and a rate/blast-radius budget that only counted the
                    # first of those would let real traffic run at up to
                    # len(packs)x the configured limit.
                    if enforcer is None:
                        return True
                    ok, _reason = enforcer.check(target_url)
                    return ok

                if not request_allowed():
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

                # Multiple packs can fire the same finding id against this
                # action (several SQLi payloads all trip the same
                # "payload-sql-error" id, say); rather than reporting
                # whichever happened to run first, keep the shortest
                # payload that matched -- a smaller repro is less noise to
                # paste into a bug report, without needing an actual
                # binary search over each pack's own variants.
                best_by_id: dict[str, tuple[str, dict, int, str, bool]] = {}
                for pack in loaded:
                    was_mutated = False
                    if not request_allowed():
                        break
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
                    match_ctx = dict(
                        status=resp.status_code,
                        body=resp.text,
                        payload=payload,
                        elapsed_ms=elapsed_ms,
                        redirected_to=redirected_to,
                        baseline_status=baseline_status,
                        baseline_body=baseline_body,
                        baseline_elapsed_ms=baseline_elapsed_ms,
                        marker_host=marker_host,
                        response_headers=resp.headers,
                    )
                    if not pack_matches(pack, **match_ctx):
                        if not adaptive or pack.get("raw_body") or pack.get("blind"):
                            continue
                        if not request_allowed():
                            continue
                        mutated = mutate_payload(
                            payload,
                            context={
                                "finding_id": pack_finding_id(pack),
                                "pack_id": pack.get("id", ""),
                                "response_status": resp.status_code,
                                "response_snippet": resp.text[:500],
                            },
                        )
                        if mutated is None or mutated == payload:
                            continue
                        data = {name: mutated for name in fields}
                        try:
                            resp = send(data)
                        except httpx.HTTPError:
                            continue
                        elapsed_ms = resp.elapsed.total_seconds() * 1000
                        redirected_to = resp.headers.get("location", "")
                        match_ctx = dict(
                            status=resp.status_code,
                            body=resp.text,
                            payload=mutated,
                            elapsed_ms=elapsed_ms,
                            redirected_to=redirected_to,
                            baseline_status=baseline_status,
                            baseline_body=baseline_body,
                            baseline_elapsed_ms=baseline_elapsed_ms,
                            marker_host=marker_host,
                            response_headers=resp.headers,
                        )
                        if not pack_matches(pack, **match_ctx):
                            continue
                        payload = mutated
                        was_mutated = True
                    fid = pack_finding_id(pack)
                    confidence = _confidence_for(pack, _matched_clause_kinds(pack, **match_ctx))
                    if was_mutated and confidence == "confirmed":
                        # An adaptively-mutated match is a scanner
                        # improvisation, not the pack author's carefully
                        # designed unambiguous signal -- never report it
                        # at the top confidence tier even if the matched
                        # clause would otherwise qualify.
                        confidence = "probable"
                    rank = _CONFIDENCE_RANK.get(confidence, 99)
                    existing = best_by_id.get(fid)
                    # Prefer the strongest-confidence match first; only use
                    # payload length to break ties within the same
                    # confidence tier -- a shorter-but-weaker match (e.g. a
                    # bare reflection) must never displace a longer payload
                    # that triggered an unambiguous marker/error signature,
                    # or "minimal repro" would quietly downgrade the
                    # evidence a human actually wants to see.
                    if existing is None or (rank, len(payload)) < (existing[2], len(existing[0])):
                        best_by_id[fid] = (payload, pack, rank, confidence, was_mutated)

                for fid, (payload, pack, _rank, confidence, mutated_flag) in best_by_id.items():
                    key = (fid, action)
                    if key in seen:
                        continue
                    seen.add(key)
                    finding = _finding(pack, action, payload, confidence, mutated=mutated_flag)
                    finding["minimal_repro"] = True
                    findings.append(finding)
    finally:
        if own:
            http.close()
    out = {"target": target, "findings": findings, "oob_probes": oob_probes}
    if enforcer is not None:
        out["guardrail"] = enforcer.summary()
    return out


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
    p.add_argument(
        "--require-policy",
        action="store_true",
        help="Refuse to run unless the target publishes a "
        ".well-known/scan-policy.json consent manifest (see shroodler_guardrails).",
    )
    p.add_argument(
        "--policy-file",
        metavar="PATH",
        help="Use a local scan-policy.json instead of fetching one from the target "
        "(e.g. for a target that hasn't deployed its manifest yet).",
    )
    p.add_argument(
        "--audit-log",
        metavar="PATH",
        help="Append a JSONL audit trail of every active request the guardrail "
        "allowed or blocked.",
    )
    p.add_argument(
        "--adaptive",
        action="store_true",
        help="On a baseline miss, retry once with an adapted payload (via "
        "SHROODLER_PAYLOAD_MUTATE_CMD if set, else a built-in keyword-case/comment "
        "mutator) instead of giving up after the pack's own static payload. Never "
        "reports a mutated match at confidence=confirmed. Still gated by the same "
        "rate/blast-radius limits as every other request.",
    )
    args = p.parse_args(argv)
    doc = json.loads(Path(args.crawl_json).read_text(encoding="utf-8"))
    extra = [Path(x) for x in args.pack]

    enforcer = None
    if args.require_policy or args.policy_file or args.audit_log:
        from shroodler_guardrails.policy import (
            PolicyEnforcer,
            fetch_policy,
            origin_of,
            parse_policy,
        )

        if args.policy_file:
            manifest = json.loads(Path(args.policy_file).read_text(encoding="utf-8"))
            policy = parse_policy(manifest, origin=origin_of(doc.get("target", "")))
        else:
            policy = fetch_policy(doc.get("target", ""))
        enforcer = PolicyEnforcer(
            policy=policy,
            require_policy=args.require_policy,
            audit_path=Path(args.audit_log) if args.audit_log else None,
        )

    out = run(
        doc,
        packs=load_packs(extra=extra) if extra else None,
        allow_external=args.allow_external,
        oob_host=args.oob_host,
        enforcer=enforcer,
        adaptive=args.adaptive,
    )
    text = json.dumps(out, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
