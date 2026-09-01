# Proxy Spec (Fiddler-parity feature)

`packages/proxy-go/` is a local intercepting HTTP(S) proxy — capture, inspect, replay,
breakpoint, and mock traffic, the same category of tool as Fiddler/Charles/mitmproxy.

**Scope note**: unlike the crawler (which actively probes targets and must stay confined
to local/permitted hosts per `docs/05-EXTERNAL-TARGETS.md`), this proxy passively
intercepts traffic *you* route through it from your own machine — that's a different
capability and isn't subject to the same host allowlist. It still must never be used to
intercept traffic on a shared network or from a device you don't control.

Produces its own binary, `shroodler-proxy`, built the same way as `shroodler-go` (single
static binary), managed by the desktop app as a second sidecar process.

## 1. Session schema (`schema/proxy-session.schema.json`)

```jsonc
{
  "id": "b3f1...",
  "started_at": "2026-09-01T12:00:00Z",
  "finished_at": "2026-09-01T12:00:00.412Z",
  "client_addr": "127.0.0.1:54213",
  "request": {
    "method": "GET",
    "url": "https://app1.local:8443/api/session",
    "http_version": "HTTP/1.1",
    "headers": { "User-Agent": "..." },
    "body": { "encoding": "utf8|base64", "content": "..." }
  },
  "response": {
    "status_code": 200,
    "headers": { "Content-Type": "application/json" },
    "body": { "encoding": "utf8|base64", "content": "..." }
  },
  "tags": ["autoresponded"],
  "notes": null
}
```

Rules:
- `body.encoding` is `"utf8"` when the content-type is text-like and decodes cleanly,
  otherwise `"base64"`. Never guess-decode binary bodies as text.
- Bodies captured with `Content-Encoding: gzip/br/deflate` are stored **decoded**, with
  the original encoding preserved in `response.headers` for accuracy — the point of the
  inspector is readability, not a byte-exact proxy replay artifact (replay reconstructs
  headers correctly regardless of how the body is stored on disk).
- A session that never got a response (upstream unreachable, dropped at a breakpoint) has
  `response: null` and a `tags` entry explaining why (`"dropped"`, `"upstream_error"`).

## 2. Root CA / TLS interception

- On first run, `shroodler-proxy ca generate` creates a local root CA (private key +
  cert), stored under the OS app-data dir (never committed to the repo, add to
  `.gitignore`).
- `shroodler-proxy ca export --output ca.pem` writes the public cert for manual trust
  installation (double-click on macOS to add to Keychain, or trust programmatically from
  the desktop app with the user's explicit confirmation — installing a root CA is a
  significant trust decision and must never happen silently).
- `shroodler-proxy ca uninstall` removes the CA from wherever it was installed. Ground
  rule: the app should make this easy to find and use — a proxy's root CA shouldn't be
  something a user forgets is still trusted on their machine.
- Per-host leaf certificates are generated on the fly, signed by the local CA, cached for
  the lifetime of the process.

## 3. Control channel

`shroodler-proxy` exposes a local WebSocket control channel (default
`ws://127.0.0.1:8890/control`, configurable) separate from the actual proxy listener
(default `127.0.0.1:8888`, what you point a browser/app/`curl -x` at). All messages are
JSON with a `type` field.

**App → proxy:**
```
{ "type": "subscribe" }                                   // start receiving session events
{ "type": "set_autoresponder_rules", "rules": [ ... ] }   // see section 5
{ "type": "resume_breakpoint", "session_id": "...", "edits": { ... } | null }
{ "type": "drop_breakpoint", "session_id": "..." }
{ "type": "replay_session", "session_id": "...", "edits": { ... } | null }
```

**Proxy → app:**
```
{ "type": "session:new", "session": { ...partial, headers only yet... } }
{ "type": "session:complete", "session": { ...full session object... } }
{ "type": "breakpoint:hit", "session_id": "...", "stage": "request" | "response", "session": { ... } }
{ "type": "error", "message": "..." }
```

## 4. Breakpoints

- A breakpoint rule matches on method/URL pattern (same pattern syntax as AutoResponder
  match rules, section 5) and a stage: `request` (pause before forwarding upstream) or
  `response` (pause before returning to the client).
- While paused, the proxy holds the connection open and emits `breakpoint:hit`. The app
  must send `resume_breakpoint` (optionally with `edits` — replace headers/body/method/
  URL for a request-stage breakpoint, or status/headers/body for a response-stage one) or
  `drop_breakpoint` to abort it.
- **Timeout policy**: a paused session that receives no `resume`/`drop` within 5 minutes
  (configurable) is automatically dropped with `tags: ["breakpoint_timeout"]` — an
  unresumed breakpoint must never hang the whole proxy indefinitely.
- Multiple concurrent breakpoints (different sessions paused at once) must be supported
  independently.

## 5. AutoResponder

Rule file format (YAML), same spirit as `secret-patterns` — data, not code:

```yaml
- match:
    method: GET
    url_pattern: 'https://api\.example\.local/v1/.*'
  respond:
    status: 200
    headers:
      Content-Type: application/json
    body_file: mocks/example-response.json
```

Rules:
- Evaluated top-to-bottom, **first match wins** — document this explicitly since rule
  order matters and silently doing something else (e.g. most-specific-match) would be a
  surprising, hard-to-debug behavior.
- A request matching no rule passes through to the real upstream untouched.
- `body_file` paths are relative to the rule file's own directory, not the CWD.
- A malformed rule file must fail fast with a clear error at load time (which line, what's
  wrong) — never partially load rules or silently skip a bad entry.

## 6. Replay & composer

- **Replay**: given a session ID (or an exported session JSON file), resend the same
  request, optionally with `edits` (any subset of method/url/headers/body). The proxy
  performs the actual outbound request itself — this is not a client-side re-fetch in the
  desktop app, so it goes through the same proxy pipeline (and can itself be captured as
  a new session, tagged `"replayed_from": "<original_id>"`).
- **Composer**: build a request from scratch (no originating session) and send it through
  the same replay path with no `edits` base to start from.
- Replaying against an unreachable target must surface a clear error via the control
  channel (`type: "error"`), never a silent no-op.

## 7. CLI contract (scriptable, non-GUI use)

```
shroodler-proxy start [--port 8888] [--control-port 8890] [--record out.sessions.jsonl]
shroodler-proxy ca generate|export [--output path]|uninstall
shroodler-proxy replay <session.json> [--edit-header k=v ...] [--output out.json]
```

`--record` writes each completed session as one JSON line (JSONL) — this is what
`make verify` uses for integration tests: start the proxy, curl a local target app
through it, assert the recorded session file has the right shape without needing the GUI
or the control-channel WebSocket at all.

## 8. Reuse of existing infrastructure

- The session inspector should offer to scan captured bodies with the same
  `secret-patterns` YAML rule-pack the crawler uses (`packages/secret-patterns/`) — same
  data file, no duplicated pattern logic. This is opt-in per session/inspector view, not
  automatic on every captured session (that would be a background scan of everything
  passing through the proxy, which is heavier than what a "scan this one response I'm
  looking at" action should be).
- Cookie parsing in the inspector should follow the same interpretation rules as the
  crawler's cookie extractor (`Secure`/`HttpOnly`/`SameSite`) for consistency, though it's
  a separate implementation local to `proxy-go` — `proxy-go` does not import
  `crawler-go` per the package boundary rules in `01-ARCHITECTURE.md`.
