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

`make down` stops the target apps. `make cover` runs coverage (Python fails
under 90%; Go prints internal-package percents).

External smoke test (off by default, never part of `make verify`):

```bash
shroodler crawl https://httpbin.org/get --allow-external --depth 0 --output /tmp/ext.json
```
