import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { diffScans } from "../src/lib/diff.js";
import {
  filterFindings,
  parseAutoResponderYaml,
  parseHeaderBlock,
  parseProgress,
  sortFindings,
} from "../src/lib/findings.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

test("diff_scans added and resolved by id+url", () => {
  const base = {
    findings: [
      { id: "missing-csp", url: "http://127.0.0.1/login" },
      { id: "insecure-cookie", url: "http://127.0.0.1/dash" },
    ],
  };
  const compare = {
    findings: [
      { id: "missing-csp", url: "http://127.0.0.1/login" },
      { id: "leaked-secret", url: "http://127.0.0.1/js" },
    ],
  };
  const d = diffScans(base, compare);
  assert.equal(d.added.length, 1);
  assert.equal(d.added[0].id, "leaked-secret");
  assert.equal(d.resolved.length, 1);
  assert.equal(d.resolved[0].id, "insecure-cookie");
});

test("progress line from go sidecar", () => {
  const p = parseProgress("PROGRESS pages=4 current=http://127.0.0.1:8081/login");
  assert.equal(p.pages_crawled, 4);
  assert.equal(p.current_url, "http://127.0.0.1:8081/login");
});

test("filter and sort findings", () => {
  const rows = [
    { id: "b", severity: "low", category: "header" },
    { id: "a", severity: "high", category: "cookie" },
  ];
  assert.equal(filterFindings(rows, { severity: "high" }).length, 1);
  assert.equal(sortFindings(rows, "id")[0].id, "a");
  assert.equal(sortFindings(rows, "severity")[0].severity, "high");
});

test("composer header and autoresponder yaml parse", () => {
  const h = parseHeaderBlock("X-Test: 1\nAccept: */*");
  assert.equal(h["X-Test"], "1");
  const rules = parseAutoResponderYaml(
    "- match:\n    method: GET\n    url_pattern: .*\n  respond:\n    status: 201\n    body: mocked\n",
  );
  assert.equal(rules[0].respond.status, 201);
  assert.equal(rules[0].match.method, "GET");
});

test("dark theme tokens from style guide", () => {
  const css = readFileSync(join(root, "src/app.css"), "utf8");
  for (const hex of ["#211A17", "#8FE6C4", "#EDE8C8", "#9B7FC0"]) {
    assert.ok(css.includes(hex), hex);
  }
});

test("tauri commands exist in rust shell", () => {
  const rs = readFileSync(join(root, "src-tauri/src/lib.rs"), "utf8");
  for (const cmd of [
    "start_scan",
    "stop_scan",
    "list_scans",
    "load_scan",
    "diff_scans",
    "ingest_sessions",
    "start_proxy",
    "stop_proxy",
    "install_ca",
    "uninstall_ca",
  ]) {
    assert.ok(rs.includes(cmd), cmd);
  }
  assert.ok(rs.includes("CA install requires explicit confirmation"));
  assert.ok(!rs.includes("headless mode is Python-only"));
  assert.ok(rs.includes("&mode"));
  assert.ok(rs.includes('"-m".into()') && rs.includes('"shroodler".into()'));
});

test("opt-in secret scan and cookie parser", async () => {
  const { scanSecrets, parseCookieHeader } = await import("../src/lib/secrets.js");
  const hits = scanSecrets("AKIAIOSFODNN7EXAMPLE");
  assert.ok(hits.some((h) => h.id === "aws-access-key"));
  const c = parseCookieHeader("sid=1; Secure; HttpOnly; SameSite=Lax");
  assert.equal(c.secure, true);
  assert.equal(c.httpOnly, true);
  assert.equal(c.sameSite, "Lax");
});

test("ca install never silent", () => {
  const ui = readFileSync(join(root, "src/App.svelte"), "utf8");
  assert.ok(ui.includes("role=\"dialog\""));
  assert.ok(ui.includes("install_ca"));
  assert.ok(ui.includes("confirmed: true"));
  assert.ok(ui.includes("Scan secrets"));
  assert.ok(ui.includes("Cookie jar"));
  assert.ok(ui.includes("Login recipe"));
  assert.ok(ui.includes("cookieJar"));
  assert.ok(ui.includes("Via proxy"));
  assert.ok(ui.includes("Ingest findings"));
});

test("ca trust status is always visible and uninstall stays confirmed", () => {
  const ui = readFileSync(join(root, "src/App.svelte"), "utf8");
  assert.ok(ui.includes("ca_status"));
  assert.ok(ui.includes("refreshCaStatus"));
  assert.ok(ui.includes("CA not trusted"));
  assert.ok(ui.includes("Shroodler root CA is trusted on this machine."));
  assert.ok(ui.includes("ca-banner"));
  assert.ok(ui.includes('openCa("uninstall")'));
  assert.ok(ui.includes("role=\"dialog\""));
  const uninstallCalls = [...ui.matchAll(/invoke\("uninstall_ca"[^)]*\)/g)].map((m) => m[0]);
  assert.equal(uninstallCalls.length, 1);
  assert.ok(uninstallCalls[0].includes("confirmed: true"));
  assert.ok(ui.includes("function confirmCa") || ui.includes("async function confirmCa"));
});

test("session cookie and seed helpers", async () => {
  const { cookieHeaderFromSessions, seedUrlsFromSessions } = await import("../src/lib/sessions.js");
  const sessions = [
    {
      request: { method: "GET", url: "http://127.0.0.1:8081/login", headers: {} },
      response: { status_code: 200, headers: { "Set-Cookie": "sid=one" } },
    },
    {
      request: { method: "GET", url: "http://127.0.0.1:8081/dash", headers: { Cookie: "sid=one" } },
      response: { status_code: 200, headers: { "Set-Cookie": "sid=two" } },
    },
    {
      request: { method: "GET", url: "http://127.0.0.1:8082/x", headers: {} },
      response: { status_code: 200, headers: { "Set-Cookie": "other=x" } },
    },
  ];
  const hdr = cookieHeaderFromSessions(sessions, "http://127.0.0.1:8081/");
  assert.equal(hdr, "sid=two");
  const seeds = seedUrlsFromSessions(sessions, "http://127.0.0.1:8081/");
  assert.equal(seeds.length, 2);
  assert.ok(!seeds.some((u) => u.includes(":8082")));
});

test("site map groups paths and attaches findings", async () => {
  const { buildSiteMap, flattenTree } = await import("../src/lib/sitemap.js");
  const hosts = buildSiteMap(
    [
      { url: "http://127.0.0.1:8081/", status_code: 200, forms: [] },
      { url: "http://127.0.0.1:8081/login", status_code: 200, forms: [{ fields: [{ name: "u" }] }] },
    ],
    [{ id: "missing-csp", url: "http://127.0.0.1:8081/login", severity: "medium" }],
    [{ request: { url: "http://127.0.0.1:8081/api" }, response: { status_code: 204 } }],
  );
  assert.equal(hosts.length, 1);
  const rows = flattenTree(hosts[0].tree);
  assert.ok(rows.some((r) => r.path === "/login" && r.findings[0].id === "missing-csp"));
  assert.ok(rows.some((r) => r.path === "/api" && r.page.source === "proxy"));
});

test("baseline and suppressions and ci exports", async () => {
  const { documentToBaseline, parseSuppressions, isSuppressed } = await import("../src/lib/baseline.js");
  const { renderSarif, renderJunit } = await import("../src/lib/export.js");
  const doc = {
    target: "http://127.0.0.1:8081",
    crawler: { name: "shroodler-go", version: "0.1.0" },
    pages: [
      {
        url: "http://127.0.0.1:8081/login",
        forms: [{ fields: [{ name: "user" }, { name: "pass" }] }],
      },
    ],
    findings: [
      { id: "missing-csp", severity: "medium", category: "header", url: "http://127.0.0.1:8081/login", description: "csp" },
      { id: "server-version-leak", severity: "info", category: "header", url: "http://127.0.0.1:8081/login", description: "svr" },
    ],
  };
  const rules = parseSuppressions("suppressions:\n  - id: server-version-leak\n    url: '*'\n    reason: noise\n");
  assert.equal(rules[0].id, "server-version-leak");
  const base = documentToBaseline(doc, { name: "my-app", suppressions: rules });
  assert.equal(base.target_app, "my-app");
  assert.deepEqual(base.expected_pages, ["/login"]);
  assert.deepEqual(base.expected_forms["/login"], ["pass", "user"]);
  assert.equal(base.expected_findings.length, 1);
  assert.equal(base.expected_findings[0].id, "missing-csp");
  assert.ok(isSuppressed(doc.findings[1], rules));
  const sarif = JSON.parse(renderSarif(doc));
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].results[0].ruleId, "missing-csp");
  assert.ok(renderJunit(doc).includes("failures=\"2\""));
});

test("map and baseline controls exist in the shell", () => {
  const ui = readFileSync(join(root, "src/App.svelte"), "utf8");
  assert.ok(ui.includes('id: "map"'));
  assert.ok(ui.includes("saveBaseline"));
  assert.ok(ui.includes("exportSarif"));
  assert.ok(ui.includes("exportJunit"));
  assert.ok(ui.includes("suppressSelected"));
});

test("proxy session list filters and copy as curl", async () => {
  const { filterSessions, sessionToCurl, shellQuote } = await import("../src/lib/sessions.js");
  const rows = [
    {
      id: "a",
      request: { method: "GET", url: "http://127.0.0.1:8081/login", headers: {} },
      response: { status_code: 200 },
    },
    {
      id: "b",
      request: { method: "POST", url: "http://127.0.0.1:8081/api/session", headers: {} },
      response: { status_code: 404 },
    },
    {
      id: "c",
      request: { method: "GET", url: "http://127.0.0.1:8081/drop", headers: {} },
      response: null,
    },
  ];
  assert.equal(filterSessions(rows, { method: "POST" }).map((s) => s.id).join(), "b");
  assert.equal(filterSessions(rows, { status: "2xx" }).map((s) => s.id).join(), "a");
  assert.equal(filterSessions(rows, { status: "4xx" }).map((s) => s.id).join(), "b");
  assert.equal(filterSessions(rows, { status: "none" }).map((s) => s.id).join(), "c");
  assert.equal(filterSessions(rows, { url: "api/session" }).map((s) => s.id).join(), "b");
  assert.equal(filterSessions(rows, { url: "  LOGIN  " }).map((s) => s.id).join(), "a");

  const curl = sessionToCurl({
    request: {
      method: "POST",
      url: "http://127.0.0.1:8081/api",
      headers: {
        "Content-Type": "application/json",
        Connection: "keep-alive",
        "Keep-Alive": "timeout=5",
        "Proxy-Connection": "keep-alive",
        "Transfer-Encoding": "chunked",
        "Content-Length": "16",
        "Content-Encoding": "gzip",
        ":authority": "127.0.0.1:8081",
      },
      body: { encoding: "utf8", content: `{"ok":true}` },
    },
  });
  assert.match(curl, /^curl -X POST /);
  assert.ok(curl.includes("http://127.0.0.1:8081/api"));
  assert.ok(curl.includes("-H 'Content-Type: application/json'"));
  assert.ok(curl.includes("--data-raw "));
  assert.ok(curl.includes(`{"ok":true}`));
  assert.ok(!/keep-alive/i.test(curl));
  assert.ok(!curl.includes("Transfer-Encoding"));
  assert.ok(!curl.includes("Content-Length"));
  assert.ok(!curl.includes("Content-Encoding"));
  assert.ok(!curl.includes(":authority"));

  const b64 = sessionToCurl({
    request: {
      method: "PUT",
      url: "http://127.0.0.1:8081/bin",
      headers: {},
      body: { encoding: "base64", content: "AQID" },
    },
  });
  assert.ok(b64.includes("-X PUT"));
  assert.ok(b64.includes("--data-binary"));
  assert.ok(b64.includes("\\x01\\x02\\x03"));

  const getCurl = sessionToCurl({
    request: { method: "GET", url: "http://127.0.0.1:8081/", headers: { Host: "127.0.0.1:8081" } },
  });
  assert.match(getCurl, /^curl /);
  assert.ok(!getCurl.includes("-X GET"));
  assert.ok(getCurl.includes("-H 'Host: 127.0.0.1:8081'"));

  assert.equal(shellQuote("plain"), "plain");
  assert.equal(shellQuote("a'b"), `'a'\\''b'`);

  const ui = readFileSync(join(root, "src/App.svelte"), "utf8");
  assert.ok(ui.includes("Copy as curl"));
  assert.ok(ui.includes("filterSessions"));
  assert.ok(ui.includes("HTTP method filter"));
  assert.ok(ui.includes("Status class filter"));
  assert.ok(ui.includes("URL substring filter"));
  assert.ok(ui.includes("copyText"));
});
