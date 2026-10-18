# Shroodler usage manual

How to run Shroodler on a real target, in the order you actually run things.
For the per-command reference see [cli-reference.md](cli-reference.md); for
engagement tradecraft see the local `docs/bug-bounty-playbook.md`.

Applies to shroodler 0.2.0.

## 1. The mental model

Shroodler is a pipeline built around one artifact, a **crawl JSON** file. Most
commands produce it, enrich it, or consume it.

```
          triage            crawl / ingest-har / ingest-sessions
   (scope a host list)  ->  (produce crawl JSON: pages + passive findings)
                                        |
                        +---------------+----------------+
                        |               |                |
                     payload         authz-diff        report
                  (active hits)   (access control)   (HTML/SARIF/...)
                        |               |                |
                        +------> merge back into crawl JSON / program state
```

- **Local by default.** Every network-touching command refuses any host
  outside `127.0.0.1`/`localhost` until you pass `--allow-external` -- your
  assertion that you are authorised to test the target.
- **Findings carry a confidence grade.** `confirmed` (observed directly, e.g. a
  header or TLS fact), `probable` (a strong lead such as authz/IDOR), or
  `heuristic` (entropy guesses, fingerprints). Verify `heuristic` secrets and
  `probable` leads by hand; they are not proven bugs.
- **One crawl engine.** The `shroodler` CLI (Python) drives `shroodler-go` for
  all crawling/network work (static and headless). Engine-independent analysis
  -- JS bundle analysis, TLS, subresource/SRI, deep extractors -- runs in Python
  on the crawl documents Go emits.

## 2. Setup

```bash
make bootstrap     # pull the vulnerable local-target submodule (local testing only)
make install-cli   # build shroodler / shroodler-go / shroodler-proxy, symlink into ~/.local/bin
make verify        # lint + unit + integration tests
```

`make up` starts the bundled target apps on `127.0.0.1:8081-8084`; `make down`
stops them. They are intentionally vulnerable -- do not "fix" them.

If the binaries are not on `PATH`, prefix with their location: `.venv/bin/shroodler`,
`packages/crawler-go/shroodler-go`, `packages/proxy-go/shroodler-proxy`. The rest
of this manual assumes they are on `PATH`.

LLM features (the `agent` and `--llm-*` flags) read provider settings from
`.env`: `LLM_PROVIDER` (anthropic, deepseek, or ollama), an optional `LLM_MODEL`
override, and the matching API key. Off unless you ask for them.

## 3. The core loop: crawl, payload, report

For a target you can hit directly (no WAF in the way).

### Crawl

```bash
shroodler crawl http://127.0.0.1:8081 --output out.json
```

Walks the site (static HTML parse by default, `--mode headless` for SPAs) and
writes pages plus passive findings (missing headers, exposed secrets, JWT
issues, CORS, TLS, mixed content, and more). Shape it with:

- `--profile safe|balanced|aggressive` -- depth/page/time/robots defaults.
  `safe` respects robots.txt, `balanced` ignores it, `aggressive` harvests
  Disallow paths as recon leads. Individual flags still override.
- `--depth N` (`-1` unbounded), `--max-pages N` (default 400), `--max-time
  SECONDS` (`0` = no limit).
- `--seed URL` adds a same-origin seed; `--exclude-path /markets/` skips a
  section.
- `--spec openapi.json` seeds paths from an OpenAPI/Swagger doc or Postman
  collection; `--gql-schema` / `--gql-wordlist` feed GraphQL field names for
  replay when introspection is blocked.

### Payload

```bash
shroodler payload out.json --output hits.json
```

Fires active packs (SQLi, XSS, SSTI, path traversal, SSRF, open redirect, XXE,
OS command injection, CRLF/header injection, LFI/RFI) at the parameters the
crawl found.

- `--pack FILE` adds a YAML pack (or a Nuclei-shaped file, auto-detected).
- `--oob-host HOST` enables blind/out-of-band checks via a collaborator you
  control. Shroodler cannot poll it; check its logs for the token in the
  output's `oob_probes` list.
- `--adaptive` retries once with a mutated payload on a baseline miss (never
  reports a mutated match as `confirmed`).
- `--require-policy` / `--policy-file` / `--audit-log` -- the guardrails in
  section 9.

### Report

```bash
shroodler report hits.json --format html --output out.html
```

Formats: `html`, `md`/`markdown`, `csv`, `json`, `sarif` (GitHub code
scanning), `junit` (CI panels), `pentest`/`pentest-html`, `submit`. HTML and
Markdown carry an executive risk score (0-100, A-F) weighted by distinct finding
type per severity, so one systemic issue across 500 pages does not drown five
distinct critical bugs. `--merge-sarif semgrep.sarif` folds in an external SARIF
file.

## 4. Scope before you crawl

Do not spend crawl budget on dead or blocked hosts. `triage` is a fast,
low-touch pre-crawl pass (CT expansion, DNS/CNAME classification, one gentle
probe per host) that labels redirect aliases, WAF walls, SSO gates, and live
content. It classifies; it does not crawl or fire payloads.

```bash
shroodler triage hosts.txt --format hosts --hosts-out seeds.txt
shroodler triage --discover example.com --allow-external --header "Bugcrowd: <uuid>"
```

`--format hosts` (or `--hosts-out`) writes a crawl-ready URL list of just the
hosts worth crawling. `cadence` prints recommended flags for a slot (does not
scan):

```bash
shroodler cadence --tier pr        # passive/safe, PR-time
shroodler cadence --tier nightly   # balanced + payload
shroodler cadence --tier weekly    # aggressive + adaptive payload
```

## 5. Authenticated crawling

Simplest case -- pass a session the crawler can replay:

```bash
shroodler crawl http://127.0.0.1:8081 --mode headless --cookie "session=abc" --output authed.json
```

- `--cookie name=value` and `--header 'Name: value'` (both repeatable).
- `--cookie-jar` / `--storage-state` for a Netscape jar, JSON cookie list, or
  Playwright storageState.
- `--login-recipe recipe.json` posts a scripted login before crawling and
  re-runs it (exponential backoff, up to `--reauth-max-retries`, default 3) on a
  mid-crawl 401 or login redirect. If every retry fails it emits `session-died`
  and stops that origin. Recipes may include `oauth_pkce` steps and opt-in
  `hook` steps; a `hook` runs an arbitrary shell command, so only use recipes
  you trust.

### Capturing HttpOnly cookies

HttpOnly cookies never appear in `document.cookie`. Launch Chrome with
`--remote-debugging-port=9222`, log in, then:

```bash
shroodler session-export --cdp http://127.0.0.1:9222 --origin https://app.example -o owner.json
```

`session-export` also converts a HAR, proxy JSONL, or Netscape jar into the
Playwright storageState that `--storage-state`, `--owner-cookies-from`, and
`--peer-cookies-from` accept. `--cdp` is loopback-only unless you pass
`--allow-external`.

## 6. When the crawler is blocked: proxy-and-record

Production infra (Cloudflare, Castle.io) blocks automated clients even with a
valid session. The tell is `pages_challenged` far exceeding `pages_crawled`.
Shroodler emits `waf-challenge` / `waf-challenge-sitewide` rather than parsing
the block page as content, and never tries to bypass a challenge.

Instead, record a real browser session through the intercepting proxy; analysis
over captured traffic is passive and never gets WAF-blocked.

```bash
shroodler proxy ca generate
shroodler proxy start --record /tmp/sess.jsonl
# trust the CA, scope your browser proxy to the target only, browse authenticated
```

Then continue from the capture, as crawl seeds or as pages to analyse:

```bash
# ingest captured pages (no re-fetch), live-crawl only the links/API seeds it mentioned
shroodler crawl https://app.example --from-capture /tmp/sess.jsonl --proxy http://127.0.0.1:8888 --allow-external -o out.json

# or turn the capture straight into crawl JSON
shroodler ingest-sessions /tmp/sess.jsonl --target http://127.0.0.1:8081 --output from-proxy.json
```

A Burp/mitmproxy/Caido/DevTools HAR works the same way via `ingest-har` or
`crawl --seed-from`.

> Scope your browser proxy to the target host only. A system-wide proxy routes
> unrelated app and OS traffic (Slack, your password manager) into the
> recording. If a capture is contaminated, delete it rather than filter it
> afterward.

## 7. Access-control testing

### authz-diff

Crawl once as a higher-privileged account, then replay every URL as a
lower-privileged (or anonymous) session. A URL still reachable under the lower
session but denied anonymously is a strong broken-access-control signal.

```bash
shroodler authz-diff admin.json --cookie "session=user" --output authz.json
```

- `--higher-priv-marker STRING` (a value only the privileged account sees)
  upgrades a hit to `confirmed` when it appears in the lower session's response.
- `--no-anon-check` reports every URL the lower session can reach, not just
  those also denied anonymously.
- `--gql-schema` / `--gql-wordlist` replay GraphQL Query fields as the lower
  session.

### peer-write

`authz-diff` is read-only; `peer-write` replays captured writes
(POST/PUT/PATCH/DELETE) against **known** object ids as a second (peer) session.
It is not n+-1 enumeration. Each write is also sent to a nonsense id as a
control: a peer 2xx matching the fake id is dummy success, not a finding;
`{"success": false}` is a write failure; a peer 2xx that differs from the
control is an IDOR lead; an owner re-read that changed is confirmation.

```bash
shroodler peer-write playbook.json --peer-cookies-from peer.json --owner-cookies-from owner.json
shroodler peer-write --from-sessions captured.har --peer-cookies-from peer.json --only-id 10464573 --allow-external
```

CSRF tokens are harvested and attached unless `--no-csrf`; if the captured write
had a CSRF field and harvest fails, the write is skipped (fail closed). With
both jars, owner-reread confirmation is the default; `--allow-unconfirmed` emits
probable leads too.

### --check-idor

For a lighter same-session lead, `crawl --check-idor` replays adjacent numeric
ids (n-1, n+1) using the crawl's own session and flags same-shaped JSON
responses. Opt-in because it makes real extra requests that may read another
user's data, and reported as a medium lead to confirm by hand.

## 8. Importing external data

Shroodler consumes other tools' output so you can analyse traffic its own proxy
never saw. These convert and ingest only; none run the upstream tool or download
a template library.

```bash
shroodler ingest-har captured.har --allow-external -o from-har.json   # Burp/mitmproxy/Caido/DevTools HAR -> crawl JSON
shroodler nuclei-ingest ./nuclei-http.yaml -o from-nuclei.yaml        # Nuclei templates -> payload pack
shroodler slither-ingest slither-report.json -o sc.json              # Slither report -> findings
shroodler report out.json --merge-sarif semgrep.sarif -o out.html    # fold in any SARIF 2.x
shroodler js-routes app.bundle.js -o routes.json                     # mine {id} URL templates from a JS bundle
```

## 9. Safety and guardrails

Active payloads have real consequences, so Shroodler ships explicit brakes:

- **Local-only by default.** `--allow-external` is required for any non-local
  target, on every network command.
- **Consent manifest.** `payload --require-policy` refuses to run unless the
  target publishes `.well-known/scan-policy.json`; `--policy-file` uses a local
  copy.
- **Audit trail.** `--audit-log audit.jsonl` appends a durable record of every
  active request allowed or blocked. Not implied by the policy flags -- pass it
  explicitly.
- **Rate-limit checks are opt-in.** `crawl --check-rate-limit` fires repeated
  bad-credential requests at login forms (lockout/alerting risk);
  `--no-check-rate-limit` forces it off even under `--profile aggressive`.
- **Paced fetch.** `paced-fetch --rate 1` GETs a URL list at a capped rate so an
  agent loop does not trip a program's limit. Does not solve captchas.

## 10. Baselines, diffing, and CI

Snapshot current findings as a baseline in git, then fail CI on anything new:

```bash
shroodler baseline out.json -o expected_findings.json --name my-app
shroodler diff out.json expected_findings.json --gate   # exit non-zero on new findings
```

`diff --gate` ignores resolved findings and honours a `.shroodlerignore` file
(rules are `{id, url}` globs, with an optional `expires` date after which the
rule warns instead of suppressing forever).

```bash
shroodler history record out.json --name my-app
shroodler trend scan-a.json scan-b.json            # introduced vs resolved, severity increases
shroodler ticket file out.json --baseline expected_findings.json   # dry-run; add --apply to call gh
shroodler ask "show critical findings" out.json    # plain-language queries over a scan
```

## 11. Engagement memory and the agent

For a multi-session engagement, keep per-program state at
`~/.shroodler/programs/<slug>/state.json` (endpoints tested, object ids,
findings, sessions):

```bash
shroodler program init etoro-bugcrowd --scope-file scope.txt
shroodler crawl http://127.0.0.1:8081 --program etoro-bugcrowd --output out.json
shroodler program status etoro-bugcrowd    # counts, coverage gaps, stale sessions
```

`crawl`/`authz-diff`/`peer-write --program` all feed the same state.
`program status` shows coverage gaps (endpoints not yet authz-diffed or
peer-write tested) -- your prioritised queue.

The `agent` command loads that state, picks the next highest-value action,
executes it, merges the result, and loops. LLM reasoning is opt-in via
`--llm-agent` / `--llm-triage` and the provider flags; `--dry-run` prints the
plan without making requests.

```bash
shroodler agent --program etoro-bugcrowd --target http://127.0.0.1:8081 --dry-run
```

## 12. MCP server

Drive Shroodler from an MCP client via the stdio server:

```bash
shroodler mcp-server --list-tools    # see the tool surface
shroodler mcp-server                 # stdio JSON-RPC
```

Tools include `scan_route`, `check_idor`, `peer_write`, `program_state`,
`coverage_gaps`, `session_export`, `extract_js_routes`, and `paced_fetch`.
Result-bearing tools return a compact `{leads, confirmed, probable, top,
next_step}` summary by default; pass `summary=false` for full JSON.

## 13. Reference

- `shroodler <command> --help` for the authoritative flag list.
- `man packages/cli/man/shroodler.1` for the full man page.
- `source packages/cli/completions/shroodler.bash` for bash completion.
- [cli-reference.md](cli-reference.md) and the [CHANGELOG](../CHANGELOG.md).
- `docs/bug-bounty-playbook.md` (local, not published) for engagement
  tradecraft.
