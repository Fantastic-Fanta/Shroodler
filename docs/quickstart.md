# Quickstart

`make up`/`make bootstrap` pull in a submodule of intentionally-vulnerable
local test targets — do not "fix" them.

```bash
make up            # start target apps on 127.0.0.1:8081–8084
make install-cli    # build the CLI/Go binaries and put shroodler, shroodler-go, shroodler-proxy on your PATH
make verify         # lint + unit + integration tests
```

The rest of the docs assume `shroodler` is on your `PATH` after
`make install-cli` (symlinked into `~/.local/bin`). No install? Prefix every
command with `.venv/bin/` (Python) or `packages/crawler-go/` /
`packages/proxy-go/` (Go binaries) instead.

Default hunt setup when the target uses HttpOnly cookies (they never appear
in `document.cookie`):

```bash
# Chrome started with --remote-debugging-port=9222, already logged in
shroodler session-export --cdp http://127.0.0.1:9222 --origin https://app.example -o owner.json
# second account in another profile, same origin
shroodler session-export --cdp http://127.0.0.1:9223 --origin https://app.example -o peer.json
shroodler peer-write --from-sessions captured.har --owner-cookies-from owner.json --peer-cookies-from peer.json --allow-external
```

When a WAF blocks the crawler, record a browser session through the
intercepting proxy and continue from the capture:

```bash
shroodler proxy start --record /tmp/sess.jsonl
# browse the app through the proxy, then:
shroodler crawl https://app.example --from-capture /tmp/sess.jsonl --proxy http://127.0.0.1:8888 --allow-external -o out.json
```

`make down` stops the target apps. `make cover` runs coverage (Python fails
under 90%; Go prints internal-package percents).

External smoke test (off by default, never part of `make verify`):

```bash
shroodler crawl https://httpbin.org/get --allow-external --depth 0 --output /tmp/ext.json
```
