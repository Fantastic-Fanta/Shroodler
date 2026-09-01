# Test Matrix

This is the checklist of test *dimensions*, not individual test cases — each row should
expand into multiple concrete tests. Add new rows as new features are built; nothing
ships without matrix coverage. Check off cells as both Python and Go implementations
pass them (`[py]` / `[go]`).

## Crawler core

| Dimension | Cases | py | go |
|---|---|---|---|
| Depth limiting | depth 0, 1, 2, 5, 10, unbounded | [x] | [ ] |
| Link scope | same-origin, subdomain, cross-origin (must exclude), path-relative, protocol-relative | [x] | [ ] |
| Link forms | `<a href>`, `<form action>`, `<link>`, `<script src>`, CSS `url()`, meta-refresh | [x] | [ ] |
| Redirects | single 301/302, chain of 5+, redirect loop (must detect & stop) | [x] | [ ] |
| Malformed HTML | unclosed tags, invalid nesting, non-UTF8 bytes | [x] | [ ] |
| Duplicate detection | trailing slash variants, query param order, fragment-only diffs | [x] | [ ] |
| Rate limiting | target returns 429, target throttles via delay | [x] | [ ] |
| Robots.txt | respected in default mode, ignorable via flag (documented, since this is your own app) | [x] | [ ] |
| Pagination traps | infinite "next page" links (app3) | [x] | [ ] |
| Honeypot links | hidden/invisible links only bots would follow (app3) | [x] | [ ] |

## Form extraction

| Dimension | Cases | py | go |
|---|---|---|---|
| Method | GET, POST, missing method (defaults to GET) | [x] | [ ] |
| Encoding | `application/x-www-form-urlencoded`, `multipart/form-data` | [x] | [ ] |
| Field types | text, password, hidden, checkbox, radio, select, textarea, file | [x] | [ ] |
| Field state | disabled fields, readonly fields | [x] | [ ] |
| Structure | nested forms (invalid HTML but happens), multiple forms per page | [x] | [ ] |
| Dynamic | JS-injected form (headless mode only) | [x] | [ ] |

## Header analysis

| Header | States tested | py | go |
|---|---|---|---|
| Content-Security-Policy | present-strict, present-weak (`unsafe-inline`), absent | [x] | [ ] |
| X-Frame-Options | DENY, SAMEORIGIN, absent | [x] | [ ] |
| Strict-Transport-Security | present, absent, present-but-short-max-age | [x] | [ ] |
| X-Content-Type-Options | nosniff, absent | [x] | [ ] |
| Referrer-Policy | present, absent | [x] | [ ] |
| Server / X-Powered-By | present (version leak), absent | [x] | [ ] |

## Cookie analysis

| Secure | HttpOnly | SameSite | py | go |
|---|---|---|---|---|
| true | true | Strict | [x] | [ ] |
| true | true | Lax | [x] | [ ] |
| true | true | None | [x] | [ ] |
| true | false | Strict/Lax/None | [x] | [ ] |
| false | true | Strict/Lax/None | [x] | [ ] |
| false | false | Strict/Lax/None | [x] | [ ] |

(18 combinations total — generate programmatically rather than hand-writing each.)

## Secret detection

| Pattern | Present in body, present in JS, absent (no false positive), high-entropy-but-not-a-secret | py | go |
|---|---|---|---|
| AWS access key | | [x] | [ ] |
| AWS secret key | | [x] | [ ] |
| Generic JWT | | [x] | [ ] |
| Private key block (`BEGIN RSA PRIVATE KEY`) | | [x] | [ ] |
| Slack token | | [x] | [ ] |
| Generic API key (heuristic/entropy-based) | | [x] | [ ] |
| Basic auth in URL | | [x] | [ ] |
| Database connection string | | [x] | [ ] |

Fuzz target: feed the secret scanner random byte strings via `hypothesis`/Go fuzzing —
should never crash, should have a bounded false-positive rate on pure-random input.

## Common-path / exposed-file probing

| Path | Should exist in app1 | Should exist in app3 | py | go |
|---|---|---|---|---|
| `/.git/config` | yes | no | [ ] | [ ] |
| `/.env` | no | yes | [ ] | [ ] |
| `/backup.sql.bak` | yes | no | [ ] | [ ] |
| `/.DS_Store` | no | no | [ ] | [ ] |
| `/wp-config.php.bak` | no | no | [ ] | [ ] |

Assert zero false positives on paths that don't exist in a given app.

## JS endpoint / secret extraction from static assets

| Case | py | go |
|---|---|---|
| Fetch API call with string literal URL | [ ] | [ ] |
| Endpoint built via template literal (best-effort) | [ ] | [ ] |
| Minified JS (single-line, no whitespace) | [ ] | [ ] |
| Source map present (bonus: resolve original file) | [ ] | [ ] |

## Headless mode (Playwright)

| Case | py | go (n/a — parity via py only) |
|---|---|---|
| Content only rendered after `fetch()` resolves | [ ] | n/a |
| Content behind a client-side route (SPA router) | [ ] | n/a |
| Form injected by JS after page load | [ ] | n/a |
| Infinite scroll pagination | [ ] | n/a |

## Report generator

| Case | Test type |
|---|---|
| Empty findings list | snapshot |
| Single finding of each severity | snapshot |
| Findings sorted by severity in output | assertion |
| HTML output is valid HTML (parse-check) | assertion |
| CSV output round-trips (parse back, compare) | assertion |

## Cross-language parity

| Target app | py vs go same findings | py vs go same page set |
|---|---|---|
| app1-server-rendered | [ ] | [ ] |
| app3-crawler-traps | [ ] | [ ] |
| app4-microservices | [ ] | [ ] |

(app2-spa excluded from Go parity since headless mode is Python-only, per architecture doc.)

## Proxy capture core

| Dimension | Cases |
|---|---|
| Protocol | Plain HTTP, HTTPS via CA-signed leaf cert |
| Transfer encoding | Chunked, Content-Length, unknown length (connection-close delimited) |
| Body encoding | gzip, deflate, br, identity — all stored decoded per `07-PROXY-SPEC.md` §1 |
| Connection reuse | Keep-alive with multiple requests on one connection |
| Body size | Small body, large/streamed body |
| Malformed upstream | Truncated response, connection reset mid-response |
| Non-proxy traffic on proxy port | Rejected cleanly, no crash |
| Redirects | Proxy forwards/records as-is, does not follow on the client's behalf |

## Root CA management

| Case | Notes |
|---|---|
| Generate CA | First run, no existing CA present |
| Export CA | Produces a valid PEM |
| Interception attempted with CA not installed/trusted | Clear error surfaced, not a crash or silent passthrough |
| Regenerate CA | Old captures made under the previous CA remain viewable (CA identity isn't embedded in stored sessions) |
| Uninstall | CA removed from wherever it was installed |

## Session inspector / decoding

| Case | py/go n/a — proxy-go only |
|---|---|
| JSON body pretty-print | |
| Form-urlencoded body decode | |
| Multipart body decode | |
| Binary body (fallback to hex/raw) | |
| Header case-insensitive lookup | |
| Cookie parsing consistency with crawler's cookie extractor rules | |
| Secret-pattern scan on a captured body (opt-in), using `secret-patterns` rule-pack | |

## Breakpoints

| Dimension | Cases |
|---|---|
| Stage | Request-stage pause, response-stage pause |
| Resume | Resume unedited, resume with edits |
| Abort | Drop a paused session |
| Concurrency | Multiple sessions paused at once, resolved independently |
| Timeout | Unresumed breakpoint auto-drops after the configured timeout without hanging the proxy |

## AutoResponder

| Dimension | Cases |
|---|---|
| Match | Method + URL pattern match → mocked response returned, real upstream never contacted |
| No match | Passthrough to real upstream |
| Precedence | Multiple matching rules → first rule in file wins |
| Malformed rule file | Fails fast at load with a clear error, doesn't partially load |
| `body_file` resolution | Relative to the rule file's directory, not CWD |

## Replay & composer

| Dimension | Cases |
|---|---|
| Replay unmodified | Outbound request matches the original byte-for-byte where it should |
| Replay with edits | Header, body, method, and URL edits each independently verified |
| Composer (no origin session) | Request built from scratch sends correctly |
| Replay against unreachable target | Clear error via control channel, not a silent no-op |
| Replayed session tagging | New session tagged `replayed_from: <original_id>` |

## Coverage gate

Once the above matrix is fully green, run coverage tooling (`pytest --cov`, `go test
-cover` for both `crawler-go` and `proxy-go`) and treat any uncovered branch as a missing
matrix row — add the row, write the test, repeat until ≥90% across `crawler-py`,
`crawler-go`, and `proxy-go`.
