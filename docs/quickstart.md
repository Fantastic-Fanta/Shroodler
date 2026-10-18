# Quickstart

```bash
make up            # start the vulnerable local test targets on 127.0.0.1:8081-8084
make install-cli   # build + symlink shroodler, shroodler-go, shroodler-proxy into ~/.local/bin
```

Scan one:

```bash
shroodler crawl http://127.0.0.1:8081 -o out.json      # map + passive findings
shroodler payload out.json -o hits.json                # active payloads
shroodler report hits.json --format html -o out.html   # report
```

`make down` stops the targets. Not on `PATH`? Prefix with `.venv/bin/` (Python)
or `packages/crawler-go/` / `packages/proxy-go/` (Go).

Authenticated hunts, WAF-blocked targets, access-control testing, and the rest:
[manual.md](manual.md).
