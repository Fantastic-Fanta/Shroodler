# Command line

```bash
# Scope triage before a crawl (classifies; does not crawl or payload)
shroodler triage hosts.txt --format hosts --hosts-out seeds.txt
shroodler triage --discover example.local --allow-external --no-active
shroodler triage http://127.0.0.1:8081 --header "Bugcrowd: <uuid>" -o triage.json --format json

# Crawl and report
shroodler crawl http://127.0.0.1:8081 --output out.json
shroodler crawl http://127.0.0.1:8081 --user-agent "Mozilla/5.0 (compatible; my-scan/1.0)" --output out.json
shroodler crawl http://127.0.0.1:8081 --login-recipe packages/target-apps/app1-server-rendered/login-recipe.json --output authed.json
shroodler crawl http://127.0.0.1:8082 --mode headless --output spa.json
shroodler report out.json --format html --output out.html

# Active payloads (SQLi/XSS/SSTI/path-traversal/SSRF/open-redirect/XXE/
# command-injection/CRLF-header-injection)
shroodler payload out.json -o hits.json
shroodler payload out.json --oob-host collab.example.com -o hits.json   # blind checks
shroodler payload out.json --require-policy -o hits.json   # refuse without a consent manifest
shroodler payload out.json --audit-log audit.jsonl -o hits.json   # record every allow/block decision

# SRI/mixed-content checks run automatically as part of a normal crawl
# (Python engine only for now -- see docs/features.md)

# Password-reset/verification-token predictability, from a recorded proxy session
shroodler tokens /tmp/sess.jsonl -o token-findings.json

# Baseline-in-git for any local app (fail CI on new findings)
shroodler baseline out.json -o expected_findings.json --name my-app
shroodler diff out.json expected_findings.json --gate   # plus optional .shroodlerignore
shroodler report out.json --format sarif -o results.sarif
shroodler report out.json --format junit -o results.xml

# Authz diff: replay a privileged session's URLs as a lower-priv session
shroodler authz-diff higher-priv-crawl.json --cookie session=abc123

# History and trend
shroodler history record out.json --name my-app
shroodler history list
shroodler trend <scan-a> <scan-b>

# Conversational queries over a scan/report
shroodler ask "show critical findings" out.json
shroodler ask "what's new since" out.json --since older.json

# MCP server (scan_route, check_idor, diff_since_baseline, explain_finding) for agent clients
shroodler mcp-server

# Go crawler (same subcommands, faster)
shroodler-go crawl http://127.0.0.1:8081 --output out.json

# Intercepting proxy (traffic you route through it)
shroodler proxy ca generate
shroodler proxy start --record /tmp/sess.jsonl
curl -x http://127.0.0.1:8888 http://127.0.0.1:8081/
shroodler-go crawl http://127.0.0.1:8081 --proxy http://127.0.0.1:8888 --output out.json
shroodler-go ingest-sessions /tmp/sess.jsonl --target http://127.0.0.1:8081 --output from-proxy.json
shroodler-go crawl http://127.0.0.1:8081 --cookies-from /tmp/sess.jsonl --seed-from /tmp/sess.jsonl

# Shell completion and man page (also printed by `make install-cli`)
source packages/cli/completions/shroodler.bash   # bash completion
man packages/cli/man/shroodler.1                 # man page

shroodler version
```
