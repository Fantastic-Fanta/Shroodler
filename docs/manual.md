# Shroodler usage manual

An end-to-end guide to running Shroodler on a real target, from scoping a
program to filing the findings. For the terse command cheat-sheet see
[cli-reference.md](cli-reference.md); for the per-feature catalogue see
[features.md](features.md); for engagement tradecraft see the local
`docs/bug-bounty-playbook.md`. This document ties those together into the
order you actually run things.

Applies to shroodler 0.2.0.

## 1. The mental model

Shroodler is a pipeline, not a single scanner. Everything revolves around one
artifact: a **crawl JSON** file. Most commands either produce it, enrich it, or
consume it.

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

Three things are worth internalising before you start:

- **Local by default.** Every command that touches the network refuses any
  host outside `127.0.0.1`/`localhost` until you pass `--allow-external`. That
  flag is your assertion that you are authorised to test the target. Nothing
  external happens without it.
- **Findings carry a confidence grade.** `confirmed` (observed directly, e.g.
  a header or TLS fact), `probable` (a strong lead such as an authz or IDOR
  candidate), or `heuristic` (entropy guesses, fingerprints). The report
  Confidence column reflects this. Treat `heuristic` secrets and IDOR
  `probable` leads as things to verify by hand, not as proven bugs.
- **Two engines.** `shroodler` (Python, full feature set) and `shroodler-go`
  (faster, same core subcommands). A few checks are Python-only for now
  (headless crawling, TLS and subresource/SRI checks). Use the Go engine for
  large or repeated crawls; use Python when you need those checks or a SPA.

## 2. Setup

```bash
make bootstrap     # pull the vulnerable local-target submodule (local testing only)
make install-cli   # build shroodler / shroodler-go / shroodler-proxy, symlink into ~/.local/bin
make verify        # lint + unit + integration tests
```

`make up` starts the bundled target apps on `127.0.0.1:8081-8084`; `make down`
stops them. Those apps are intentionally vulnerable, do not "fix" them.

If the binaries are not on your `PATH`, prefix commands with their location:
`.venv/bin/shroodler` for Python, `packages/crawler-go/shroodler-go` and
`packages/proxy-go/shroodler-proxy` for the Go binaries. The rest of this
manual assumes they are on your `PATH`.

LLM features (the `agent` and `--llm-*` flags) read provider settings from
`.env`: `LLM_PROVIDER` (anthropic, deepseek, or ollama), an optional
`LLM_MODEL` override, and the matching API key. They are off unless you ask for
them.

## 3. The core loop: crawl, payload, report

This is the workflow for a target you can hit directly (no WAF in the way).

### Crawl

```bash
shroodler crawl http://127.0.0.1:8081 --output out.json
```

`crawl` walks the site (static HTML parse by default, `--mode headless` for a
real browser against SPAs) and writes pages plus passive findings (missing
headers, exposed secrets, JWT issues, CORS, TLS, mixed content, and more) to
`out.json`.

Shape the crawl with a profile and budgets:

- `--profile safe|balanced|aggressive` sets sane depth/page/time/robots
  defaults. `safe` respects robots.txt, `balanced` ignores it, `aggressive`
  harvests Disallow paths as recon leads. Individual flags still override the
  profile.
- `--depth N` (`-1` unbounded), `--max-pages N` (default 400),
  `--max-time SECONDS` (`0` = no limit).
- `--seed URL` adds an extra same-origin seed; `--exclude-path /markets/`
  skips a section you do not care about.
- `--spec openapi.json` seeds same-origin paths from an OpenAPI/Swagger doc or
  Postman collection; `--gql-schema` / `--gql-wordlist` feed GraphQL field
  names for later replay when introspection is blocked.

### Payload

```bash
shroodler payload out.json --output hits.json
```

`payload` takes the crawl JSON and fires active packs (SQLi, XSS, SSTI, path
traversal, SSRF, open redirect, XXE, OS command injection, CRLF/header
injection, LFI/RFI) at the parameters the crawl found. Useful flags:

- `--pack FILE` adds an extra YAML pack (or a Nuclei-shaped file, auto-detected).
- `--oob-host HOST` enables blind/out-of-band checks via a collaborator server
  you control. Shroodler cannot poll it for you; check its logs for the token
  printed in the output's `oob_probes` list.
- `--adaptive` retries once with a mutated payload on a baseline miss (never
  reports a mutated match as `confirmed`).
- `--require-policy` / `--policy-file` / `--audit-log` are the guardrails in
  section 9.

### Report

```bash
shroodler report hits.json --format html --output out.html
```

Formats: `html`, `md`/`markdown`, `csv`, `json`, `sarif` (GitHub code
scanning), `junit` (CI panels), `pentest`/`pentest-html`, and `submit`. HTML
and Markdown carry an executive risk score (0-100, A-F) weighted by distinct
finding type per severity, so one systemic header issue repeated across 500
pages does not drown five genuinely distinct critical bugs. `--merge-sarif
semgrep.sarif` folds in an external SARIF file alongside Shroodler's own
findings.

## 4. Scope before you crawl

On a broad engagement, do not spend crawl budget on dead or blocked hosts.
`triage` is a fast, low-touch pre-crawl pass (passive Certificate Transparency
expansion, DNS/CNAME classification, one gentle HTTP probe per live host) that
labels redirect aliases, WAF/challenge walls, SSO gates, and live content. It
classifies, it does not crawl or fire payloads.

```bash
shroodler triage hosts.txt --format hosts --hosts-out seeds.txt
shroodler triage --discover example.com --allow-external --header "Bugcrowd: <uuid>"
```

`--format hosts` (or `--hosts-out`) writes a crawl-ready URL list of just the
hosts worth crawling. `cadence` prints the recommended flags for a given slot
(it does not scan):

```bash
shroodler cadence --tier pr        # passive/safe, PR-time
shroodler cadence --tier nightly   # balanced + payload
shroodler cadence --tier weekly    # aggressive + adaptive payload
```

## 5. Authenticated crawling

Simplest case, pass a session the crawler can replay:

```bash
shroodler crawl http://127.0.0.1:8081 --mode headless --cookie "session=abc" --output authed.json
```

Options for supplying a session:

- `--cookie name=value` (repeatable) and `--header 'Name: value'` (repeatable).
- `--cookie-jar` / `--storage-state` for a Netscape jar, JSON cookie list, or
  Playwright storageState.
- `--login-recipe recipe.json` posts a scripted login before crawling and
  re-runs it (exponential backoff, up to `--reauth-max-retries`, default 3) on
  a mid-crawl 401 or login redirect. If every retry fails it emits a
  `session-died` finding and stops that origin instead of crawling with a dead
  session. Recipes may include `oauth_pkce` steps and opt-in `hook` steps.
  A `hook` runs an arbitrary shell command from the recipe file, only use
  recipes you trust.

### Capturing HttpOnly cookies

HttpOnly cookies never appear in `document.cookie`, so export them from a
logged-in browser. Launch Chrome with `--remote-debugging-port=9222`, log in,
then:

```bash
shroodler session-export --cdp http://127.0.0.1:9222 --origin https://app.example -o owner.json
```

`session-export` also converts a HAR, proxy JSONL, or Netscape jar into the
Playwright storageState JSON that `--storage-state`, `--owner-cookies-from`,
and `--peer-cookies-from` all accept. `--cdp` is loopback-only unless you pass
`--allow-external`.

## 6. When the crawler is blocked: proxy-and-record

Real production infra (Cloudflare, Castle.io, and friends) will block an
automated client outright even with a valid session. The tell is
`pages_challenged` far exceeding `pages_crawled`, or every request returning a
challenge page. Shroodler detects this and emits `waf-challenge` /
`waf-challenge-sitewide` findings rather than parsing the block page as real
content. It never tries to solve or bypass a challenge.

When that happens, stop fighting the crawler and record a real browser session
through the intercepting proxy instead. Analysis over captured traffic is
passive and never gets WAF-blocked.

```bash
shroodler proxy ca generate
shroodler proxy start --record /tmp/sess.jsonl
# trust the CA, scope your browser proxy to the target only, browse authenticated
```

Then continue from the capture, either as pages to analyse or as crawl seeds:

```bash
# ingest captured pages (no re-fetch), live-crawl only the links/API seeds it mentioned
shroodler crawl https://app.example --from-capture /tmp/sess.jsonl --proxy http://127.0.0.1:8888 --allow-external -o out.json

# or turn the capture straight into crawl JSON
shroodler ingest-sessions /tmp/sess.jsonl --target http://127.0.0.1:8081 --output from-proxy.json
```

A Burp/mitmproxy/Caido/DevTools HAR works the same way via `ingest-har` or
`crawl --seed-from`.

> Scope your browser proxy to the target host only. A system-wide proxy plus a
> browser-extension proxy will route unrelated app and OS traffic (Slack, your
> password manager, and so on) into the recording. If a capture is
> contaminated that way, delete it rather than trying to filter it afterward.

## 7. Access-control testing

### authz-diff

Crawl once as a higher-privileged account, then replay every URL as a
lower-privileged (or anonymous) session. A URL still reachable under the lower
session, that is also denied anonymously, is a strong broken-access-control
signal.

```bash
shroodler authz-diff admin.json --cookie "session=user" --output authz.json
```

- `--higher-priv-marker STRING` (a value only the privileged account should
  see) upgrades a hit to `confirmed` when it appears in the lower session's
  response.
- `--no-anon-check` reports every URL the lower session can reach, not just the
  ones also denied anonymously.
- `--gql-schema` / `--gql-wordlist` replay GraphQL Query fields as the lower
  session.

### peer-write

`authz-diff` is read-only. `peer-write` replays captured writes
(POST/PUT/PATCH/DELETE) against **known** object ids as a second (peer) session.
It is not n+-1 enumeration, it does not invent adjacent ids. Each write is also
sent to a nonsense id as a control: a peer 2xx that matches the fake id is
dummy success, not a finding; `{"success": false}` is a write failure; a peer
2xx that differs from the control is an IDOR lead, and an owner re-read that
changed is confirmation.

```bash
shroodler peer-write playbook.json --peer-cookies-from peer.json --owner-cookies-from owner.json
shroodler peer-write --from-sessions captured.har --peer-cookies-from peer.json --only-id 10464573 --allow-external
```

CSRF tokens are harvested and attached unless `--no-csrf`; if the captured
write had a CSRF field and harvest fails, the write is skipped (fail closed).
With both owner and peer jars, owner-reread confirmation is the default; pass
`--allow-unconfirmed` to emit probable leads too.

### --check-idor

For a lighter, same-session lead, `crawl --check-idor` replays adjacent numeric
ids (n-1, n+1) using the crawl's own session and flags same-shaped JSON
responses. It is opt-in because it makes real extra requests that may read
another user's data, and it is reported as a medium lead to confirm by hand (a
single session cannot prove the adjacent id belongs to another account).

## 8. Importing external data

Shroodler consumes several other tools' output so you can analyse traffic its
own proxy never saw:

```bash
shroodler ingest-har captured.har --allow-external -o from-har.json   # Burp/mitmproxy/Caido/DevTools HAR -> crawl JSON
shroodler nuclei-ingest ./nuclei-http.yaml -o from-nuclei.yaml        # Nuclei templates -> payload pack
shroodler slither-ingest slither-report.json -o sc.json              # Slither report -> findings
shroodler report out.json --merge-sarif semgrep.sarif -o out.html    # fold in any SARIF 2.x
shroodler js-routes app.bundle.js -o routes.json                     # mine {id} URL templates from a JS bundle
```

These convert and ingest only; none of them run the upstream tool or download a
template library.

## 9. Safety and guardrails

Active payloads can have real consequences, so Shroodler ships explicit
brakes:

- **Local-only by default.** `--allow-external` is required for any non-local
  target, on every command that reaches the network.
- **Consent manifest.** `payload --require-policy` refuses to run unless the
  target publishes `.well-known/scan-policy.json`; `--policy-file` uses a local
  copy instead.
- **Audit trail.** `--audit-log audit.jsonl` appends a durable record of every
  active request the guardrail allowed or blocked. It is not implied by the
  policy flags, pass it explicitly.
- **Rate-limit checks are opt-in.** `crawl --check-rate-limit` fires repeated
  bad-credential requests at login forms (lockout/alerting risk), off unless
  you ask, and `--no-check-rate-limit` forces it off even under
  `--profile aggressive`.
- **Paced fetch.** For a program with a strict request cap,
  `paced-fetch --rate 1` GETs a URL list at a capped rate so an agent loop does
  not trip the limit. It does not solve captchas.

## 10. Baselines, diffing, and CI

Snapshot the current findings as a baseline checked into git, then fail CI on
anything new:

```bash
shroodler baseline out.json -o expected_findings.json --name my-app
shroodler diff out.json expected_findings.json --gate   # exit non-zero on new findings
```

`diff --gate` ignores resolved findings and honours a `.shroodlerignore`
suppression file (rules are `{id, url}` globs, with an optional `expires` date
after which the rule warns instead of silently suppressing forever).

Track change over time and, optionally, auto-file issues:

```bash
shroodler history record out.json --name my-app
shroodler history list
shroodler trend scan-a.json scan-b.json            # introduced vs resolved, severity increases
shroodler ticket file out.json --baseline expected_findings.json   # dry-run; add --apply to call gh
```

Ask questions over a scan in plain language:

```bash
shroodler ask "show critical findings" out.json
shroodler ask "what's new since" out.json --since older.json
```

## 11. Engagement memory and the agent

For a multi-session engagement, keep persistent state per program at
`~/.shroodler/programs/<slug>/state.json` (endpoints tested, object ids seen,
findings, sessions):

```bash
shroodler program init etoro-bugcrowd --scope-file scope.txt
shroodler crawl http://127.0.0.1:8081 --program etoro-bugcrowd --output out.json
shroodler program status etoro-bugcrowd    # counts, coverage gaps, stale sessions
```

`crawl --program`, `authz-diff --program`, and `peer-write --program` all feed
the same state. `program status` shows coverage gaps (endpoints not yet
authz-diffed or peer-write tested), which is your prioritised queue.

The `agent` command loads that state, picks the next highest-value action
(crawl a gap, authz-diff, peer-write, or report), executes it, merges the
result, and loops. LLM reasoning is opt-in via `--llm-agent` / `--llm-triage`
and the provider flags; `--dry-run` prints the plan without making any
requests.

```bash
shroodler agent --program etoro-bugcrowd --target http://127.0.0.1:8081 --dry-run
```

## 12. MCP server

To drive Shroodler from an MCP client (an LLM agent), run the stdio server:

```bash
shroodler mcp-server --list-tools    # see the tool surface
shroodler mcp-server                 # stdio JSON-RPC
```

Tools include `scan_route`, `check_idor`, `peer_write`, `program_state`,
`coverage_gaps`, `session_export`, `extract_js_routes`, and `paced_fetch`.
Result-bearing tools return a compact `{leads, confirmed, probable, top,
next_step}` summary by default; pass `summary=false` for the full JSON.

## 13. Reference

- `shroodler <command> --help` for the authoritative flag list on any
  subcommand.
- `man packages/cli/man/shroodler.1` for the full man page.
- `source packages/cli/completions/shroodler.bash` for bash completion.
- [cli-reference.md](cli-reference.md), [features.md](features.md), and the
  [CHANGELOG](../CHANGELOG.md).
- `docs/bug-bounty-playbook.md` (kept local, not published) for
  engagement tradecraft.
