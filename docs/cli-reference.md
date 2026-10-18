# Commands

What each subcommand does and how to invoke it. For the run-order walkthrough
see [manual.md](manual.md); `shroodler <command> --help` is authoritative for
flags.

## Crawl

- **crawl** — walk a site (static, or `--mode headless` for SPAs) into crawl
  JSON (pages + passive findings). `--profile safe|balanced|aggressive`,
  `--depth`/`--max-pages`/`--max-time`, `--seed`/`--exclude-path`, and `--spec`
  to seed paths from OpenAPI/Swagger/Postman. `--login-recipe` scripts auth and
  re-auths on a mid-crawl 401 up to `--reauth-max-retries` (recipes may include
  `oauth_pkce` and opt-in `hook` steps; a hook runs a shell command, so trust
  the recipe).
- **shroodler-go** — the sole crawl/network engine; `shroodler` drives it.
  Engine-independent analysis (JS, TLS, SRI, deep extractors) runs in Python on
  its output.

```bash
shroodler crawl http://127.0.0.1:8081 --output out.json
shroodler crawl http://127.0.0.1:8082 --mode headless --output spa.json
shroodler crawl http://127.0.0.1:8081 --spec ./openapi.json --output out.json
shroodler crawl http://127.0.0.1:8081 --login-recipe recipe.json --reauth-max-retries 3 --output authed.json
shroodler crawl http://127.0.0.1:8081 --plugin ./my-checks --output out.json
shroodler-go crawl http://127.0.0.1:8081 --output out.json
```

## Passive findings (automatic during a crawl)

- Missing security headers, exposed secrets/keys, JWT issues (`alg: none`,
  missing/long expiry, weak secret), CORS misconfig, GraphQL introspection.
- **Secrets** — known-prefix keys plus an entropy heuristic; ASP.NET ViewState
  and benign URL params excluded from `generic-api-key`.
- **TLS** (Python) — expired/expiring, self-signed, untrusted-chain, handshake
  failures, SAN/CN hostname mismatch, once per `https://` origin.
- **Subresource** — cross-origin `<script>`/`<link>` missing SRI, and HTTPS
  pages loading `http://` subresources (mixed content).
- **Cookie prefix** — `__Secure-`/`__Host-` Set-Cookie violations.
- **Auth-stack fingerprinting** — next-auth/Keycloak/Auth0 from cookie/path
  signatures; runs next-auth's `callbackUrl` probe automatically.
- **WAF/bot-mitigation** — detects Cloudflare/Akamai/PerimeterX/DataDome/CAPTCHA
  challenge pages and emits `waf-challenge` / `waf-challenge-sitewide` instead of
  parsing the block page. Detection only; never bypasses a challenge.
- **Confidence grades** — `confirmed` / `probable` / `heuristic` on every
  finding; verify `heuristic` and `probable` by hand.

## Active payloads

- **payload** — fire SQLi/XSS/SSTI/path-traversal/SSRF/open-redirect/XXE/
  command-injection/CRLF-header-injection/LFI-RFI at the parameters a crawl
  found. `--pack` adds a YAML or Nuclei-shaped pack; `--oob-host` enables
  blind/out-of-band checks via a collaborator you control; `--adaptive` retries
  once with a mutated payload (never reported `confirmed`).
- **Stored XSS** — a reflected POST hit whose marker survives into a later GET
  is `payload-xss-stored`.

```bash
shroodler payload out.json -o hits.json
shroodler payload out.json --pack extra.yaml -o hits.json
shroodler payload out.json --oob-host collab.example.com -o hits.json    # blind checks
shroodler payload out.json --require-policy -o hits.json                 # refuse without a consent manifest
shroodler payload out.json --audit-log audit.jsonl -o hits.json          # record every allow/block decision
```

## Access control

- **authz-diff** — replay a higher-privileged crawl's URLs as a lower-privileged
  (or anonymous) session. `--higher-priv-marker` upgrades a hit to `confirmed`;
  `--no-anon-check` reports every reachable URL; `--gql-schema`/`--gql-wordlist`
  replay GraphQL Query fields.
- **peer-write** (Python) — replay captured writes against *known* object ids as
  a peer session (not n±1 enumeration), with a nonsense-id control and optional
  owner re-read. CSRF tokens harvested unless `--no-csrf`; a captured CSRF field
  that fails to harvest skips the write (fail closed). `--require-confirm` keeps
  only owner-reread confirmations.
- **crawl --check-idor** — same-session adjacent-ID replay (n-1/n+1) against JSON
  APIs. Opt-in; a medium lead to confirm by hand, not a proven vuln.

```bash
shroodler authz-diff admin.json --cookie session=user --output authz.json
shroodler peer-write playbook.json --owner-cookies-from a.json --peer-cookies-from b.json --require-confirm
shroodler peer-write --from-sessions captured.har --peer-cookies-from b.json --only-id 10464573 --allow-external
shroodler crawl http://127.0.0.1:8081 --check-idor --output out.json
```

## Auth / session

- **Auth checks** (during crawl) — missing rate limiting on login forms, session
  fixation, logout not invalidating sessions.
- **OAuth/OIDC** — missing/empty `state`, deprecated implicit flow, and (when
  Keycloak/Auth0 is fingerprinted) an open `redirect_uri` allowlist probe
  (`oauth-redirect-uri-unvalidated`), confirmed only by a 3xx/form_post to
  `https://shroodler.invalid/oauth-callback`.
- **tokens** — password-reset/verification-token predictability from a recorded
  proxy session (sequential-generator or Shannon-entropy test with 2+ samples).

```bash
shroodler tokens /tmp/sess.jsonl -o token-findings.json
```

## JS analysis

- Mines JSON-RPC methods, tRPC procedures, React Query keys, and GraphQL
  operation names from JS; React Query / tRPC URLs are queued as crawl seeds.
- **js-routes** — mine `{userId}`, `{pk}`, `${var}`, `:id`, `<int:pk>` URL
  templates from a bundle (no fetch).

```bash
shroodler js-routes app.bundle.js -o routes.json
shroodler crawl http://127.0.0.1:8081 --gql-schema ./clairvoyance.json --output out.json
```

## Sessions & capture

- **session-export** — dump HttpOnly cookies from a live Chrome `--cdp` URL
  (loopback-only unless `--allow-external`), or convert HAR / proxy JSONL /
  Netscape into Playwright storageState.
- **proxy** — intercepting MITM proxy with its own CA and session recording;
  crawls route through it or seed from a recording.
- **crawl --from-capture** — ingest a capture as pages (no re-fetch) and
  live-crawl only the links/API seeds it mentioned.
- **paced-fetch** — GET/HEAD/OPTIONS a URL list at a capped rate so an agent
  loop doesn't trip a rate limit. Does not solve captchas.

```bash
shroodler session-export --cdp http://127.0.0.1:9222 --origin https://app.example -o owner.json
shroodler proxy ca generate
shroodler proxy start --record /tmp/sess.jsonl
shroodler crawl https://app.example --from-capture /tmp/sess.jsonl --proxy http://127.0.0.1:8888 --allow-external -o out.json
shroodler-go ingest-sessions /tmp/sess.jsonl --target http://127.0.0.1:8081 --output from-proxy.json
shroodler paced-fetch --url http://127.0.0.1:8081/a --url http://127.0.0.1:8081/b --rate 1
```

## Ingest

Convert other tools' output into crawl JSON / findings. None run the upstream
tool or download a template library.

```bash
shroodler ingest-har captured.har --allow-external -o from-har.json   # Burp/mitmproxy/Caido/DevTools HAR
shroodler nuclei-ingest ./nuclei-http.yaml -o from-nuclei.yaml        # Nuclei templates -> payload pack
shroodler slither-ingest slither-report.json -o sc.json              # Slither report -> findings
shroodler report out.json --merge-sarif semgrep.sarif -o out.html    # fold in any SARIF 2.x
```

## Reporting & CI

- **report** — `html`, `md`, `csv`, `json`, `sarif` (GitHub code scanning),
  `junit` (CI), `pentest`/`pentest-html`. HTML/Markdown carry an A-F risk score
  weighted by distinct finding type per severity.
- **baseline** + **diff --gate** — snapshot findings in git, fail CI on anything
  new. `.shroodlerignore` rules are `{id, url}` globs with an optional `expires`.
- **history** / **trend** — record scans and diff any two.
- **ticket** — open/close GitHub issues for findings (dry-run; `--apply` calls `gh`).
- **cadence** — print recommended flags for a pr/nightly/weekly slot (doesn't scan).
- **ask** — plain-language queries over a scan.
- **attack-path** — rank findings by clicks from the start URL (falls back to
  path depth, flagged, when the crawl recorded no edges).

```bash
shroodler report hits.json --format html -o out.html
shroodler baseline out.json -o expected_findings.json --name my-app
shroodler diff out.json expected_findings.json --gate
shroodler history record out.json --name my-app
shroodler trend scan-a.json scan-b.json
shroodler ticket file out.json --baseline expected_findings.json       # add --apply to call gh
shroodler cadence --tier nightly
shroodler ask "show critical findings" out.json
```

## Agent & memory

- **program** — per-engagement state at `~/.shroodler/programs/<slug>/state.json`
  (endpoints tested, object ids, findings, sessions). `crawl`/`authz-diff`/
  `peer-write --program` feed it; `program status` shows coverage gaps.
- **agent** — loads program state, picks the next highest-value action, runs it,
  loops. LLM reasoning opt-in via `--llm-agent`/`--llm-triage`; `--dry-run`
  prints the plan.
- **mcp-server** — stdio server for an MCP client. Tools (`scan_route`,
  `check_idor`, `peer_write`, `program_state`, `coverage_gaps`, ...) return a
  compact `{leads, confirmed, probable, top, next_step}` summary unless
  `summary=false`.

```bash
shroodler program init etoro-bugcrowd --scope-file scope.txt
shroodler program status etoro-bugcrowd
shroodler agent --program etoro-bugcrowd --target http://127.0.0.1:8081 --dry-run
shroodler mcp-server --list-tools
```

## Scope & extensibility

- **triage** — fast pre-crawl pass (CT expansion, DNS/CNAME classification incl.
  dangling-CNAME takeover, one gentle probe per host) labeling redirects, WAF
  walls, SSO gates, and live content. Classifies; does not crawl.
- **Plugins** — extra payload packs, secret rules, and Python page checks from a
  local dir (`--plugin`, or `$SHROODLER_PLUGIN_PATH`).

```bash
shroodler triage hosts.txt --format hosts --hosts-out seeds.txt
shroodler triage --discover example.local --allow-external --no-active
```

## Shell completion, man page, version

```bash
source packages/cli/completions/shroodler.bash
man packages/cli/man/shroodler.1
shroodler version
```
