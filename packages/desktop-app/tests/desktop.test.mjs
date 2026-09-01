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
    "start_proxy",
    "stop_proxy",
    "install_ca",
    "uninstall_ca",
  ]) {
    assert.ok(rs.includes(cmd), cmd);
  }
  assert.ok(rs.includes("CA install requires explicit confirmation"));
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
});
