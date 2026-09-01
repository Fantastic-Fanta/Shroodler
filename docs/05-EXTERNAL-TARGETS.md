# External Targets (optional, opt-in only)

These are real, internet-hosted targets that explicitly permit this kind of scanning —
unlike arbitrary third-party sites, using these is not unauthorized. They're useful for
exposing the crawler to real-world markup, headers, and hosting quirks that hand-built
local fixtures won't fully capture.

**This is entirely optional and off by default.** It's a separate milestone (see below),
not part of the core `make verify` loop, and must never run automatically in CI.

## Known-safe public test targets

| Target | What it's for | Notes |
|---|---|---|
| `scanme.nmap.org` | Nmap's official public test host | Explicitly permits scanning "for testing purposes." Primarily a port-scan target; its web server is minimal, so treat it as a lightweight connectivity/HTTP-behavior test rather than a rich findings source. |
| `testphp.vulnweb.com` | Acunetix's public intentionally-vulnerable PHP app | Explicitly hosted for security-scanner testing. Good source of forms, headers, and real findings. |
| `testasp.vulnweb.com` / `testaspnet.vulnweb.com` | Acunetix's ASP/ASP.NET vulnerable test sites | Same program as above, different stack — useful for heterogeneity. |
| `testhtml5.vulnweb.com` | Acunetix's HTML5/JS-heavy test site | Good for JS-endpoint extraction testing against real minified JS. |
| `demo.testfire.net` | Altoro Mutual — IBM/HCL's intentionally vulnerable banking demo | Long-standing, widely-used public scan target; form-heavy, session/cookie-heavy. |
| `zero.webappsecurity.com` | Micro Focus/OpenText's intentionally vulnerable demo app | Similar purpose to Altoro Mutual, different app structure. |
| `google-gruyere.appspot.com` | Google's intentionally vulnerable training app | Requires a per-instance URL (each session gets its own path) — not a fixed single URL, so it needs a manual step to obtain the instance link before crawling. |
| `httpbin.org` | Not a vulnerable app — just an HTTP behavior echo service | Not useful for findings, but great for verifying header/redirect/method handling against a real server without any security angle at all. |

## Ground rules if you build this milestone

1. **Opt-in flag only** — e.g. `--allow-external` or a config file entry, off by default.
   `make verify` must never touch the network beyond `localhost`.
2. **Respect the target** — these are shared public resources other people use for the
   same purpose. Low request rate, low depth, no aggressive fuzzing, always identify
   a real `User-Agent` string, respect `robots.txt` here even if the local mode allows
   ignoring it.
3. **No new `expected_findings.json` ground truth for these** — they aren't yours, their
   content can change over time, so don't build hard pass/fail assertions against them.
   Treat this purely as a smoke test ("crawl completes, produces valid schema JSON, no
   crashes") not a correctness test.
4. **Never add any other host to this list without checking it explicitly documents
   permission to scan.** A site simply being "vulnerable-looking" or old/abandoned is
   not permission.

## Suggested milestone slot

Add as **Milestone 15 (stretch)**, after Milestone 14, gated behind the same "stretch,
only if time/budget allows" framing — this should be the last thing worked on, never
prioritized over core milestones.
