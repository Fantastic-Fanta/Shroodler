# Shroodler

Web attack-surface mapping toolkit. Crawl a site, throw active payloads at it,
scan for secrets, and report the findings. Target apps live in this repo and
are intentionally vulnerable — do not "fix" them.

By default everything only touches local targets (127.0.0.1/localhost); pass
`--allow-external` to scan a remote host you're authorized to test.

## Quickstart

```bash
make up          # start target apps on 127.0.0.1:8081–8084
make cli         # build/install the CLI and Go binaries, print their paths
make verify      # lint + unit + integration tests
```

## Features

- **Crawl** — static (HTML parse) or headless (real browser, for SPAs)
  crawling with configurable depth/page/time budgets, robots/sitemap
  handling, scripted login, cookie/header/session-state injection, and
  named safe/balanced/aggressive profiles.
- **Passive findings** — missing security headers, exposed secrets/keys,
  JWT issues (`alg: none`, missing/long expiry, weak secret), CORS
  misconfig, GraphQL introspection, and more, discovered while crawling.
- **Active payload testing** — SQLi, XSS, SSTI, path traversal, SSRF,
  open redirect, and XXE (including blind/out-of-band checks via your own
  collaborator host).
- **Auth checks** — missing rate limiting on login/auth forms, session
  fixation, logout not invalidating sessions.
- **Authz diff** — replay a higher-privileged crawl's URLs with a
  lower-privileged session to find broken access control.
- **Intercepting proxy** — MITM proxy with its own CA, session recording,
  and an AutoResponder-style rule system; crawls can route through it or be
  seeded from a recorded session.
- **History & trend** — record scans locally and diff findings between any
  two of them (introduced vs. resolved).
- **Baseline & CI gating** — snapshot current findings as a baseline
  checked into git, then fail CI on anything new (`diff --gate`), with
  optional suppressions.
- **Reports** — render findings as HTML, CSV, SARIF (GitHub code scanning),
  JUnit (CI test panels), or Markdown.
- **Two crawler implementations** — a Python crawler (full feature set) and
  a Go crawler (`shroodler-go`, faster, same core subcommands; a few
  Python-only features are noted in the CLI `--help`).

## Command line

```bash
make bootstrap   # .venv + `shroodler` console script
make bins        # shroodler-go + shroodler-proxy

# Crawl and report
.venv/bin/shroodler crawl http://127.0.0.1:8081 --output out.json
.venv/bin/shroodler crawl http://127.0.0.1:8081 --login-recipe packages/target-apps/app1-server-rendered/login-recipe.json --output authed.json
.venv/bin/shroodler crawl http://127.0.0.1:8082 --mode headless --output spa.json
.venv/bin/shroodler report out.json --format html --output out.html

# Active payloads (SQLi/XSS/SSTI/path-traversal/SSRF/open-redirect/XXE)
.venv/bin/shroodler payload out.json -o hits.json
.venv/bin/shroodler payload out.json --oob-host collab.example.com -o hits.json   # blind checks

# Baseline-in-git for any local app (fail CI on new findings)
.venv/bin/shroodler baseline out.json -o expected_findings.json --name my-app
.venv/bin/shroodler diff out.json expected_findings.json --gate   # plus optional .shroodlerignore
.venv/bin/shroodler report out.json --format sarif -o results.sarif
.venv/bin/shroodler report out.json --format junit -o results.xml

# Authz diff: replay a privileged session's URLs as a lower-priv session
.venv/bin/shroodler authz-diff higher-priv-crawl.json --cookie session=abc123

# History and trend
.venv/bin/shroodler history record out.json --name my-app
.venv/bin/shroodler history list
.venv/bin/shroodler trend <scan-a> <scan-b>

# Go crawler (same subcommands)
packages/crawler-go/shroodler-go crawl http://127.0.0.1:8081 --output out.json

# Intercepting proxy (traffic you route through it)
.venv/bin/shroodler proxy ca generate
.venv/bin/shroodler proxy start --record /tmp/sess.jsonl
curl -x http://127.0.0.1:8888 http://127.0.0.1:8081/
packages/crawler-go/shroodler-go crawl http://127.0.0.1:8081 --proxy http://127.0.0.1:8888 --output out.json
packages/crawler-go/shroodler-go ingest-sessions /tmp/sess.jsonl --target http://127.0.0.1:8081 --output from-proxy.json
packages/crawler-go/shroodler-go crawl http://127.0.0.1:8081 --cookies-from /tmp/sess.jsonl --seed-from /tmp/sess.jsonl

# Put shroodler, shroodler-go, shroodler-proxy on PATH
make install-cli   # symlinks into ~/.local/bin; also prints completion/man-page paths
source packages/cli/completions/shroodler.bash   # bash completion
man packages/cli/man/shroodler.1                 # man page

.venv/bin/shroodler version
```

`make down` stops the target apps. `make cover` runs coverage (Python fails
under 90%; Go prints internal-package percents).

External smoke test (off by default, never part of `make verify`):

```bash
.venv/bin/shroodler crawl https://httpbin.org/get --allow-external --depth 0 --output /tmp/ext.json
```

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
