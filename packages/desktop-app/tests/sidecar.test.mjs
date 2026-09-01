import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync, spawn } from "node:child_process";
import { parseProgress } from "../src/lib/findings.js";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const goDir = join(repo, "packages", "crawler-go");
const bin = join(goDir, "shroodler-go");

function ensureBin() {
  const r = spawnSync("go", ["build", "-o", "shroodler-go", "./cmd/shroodler"], {
    cwd: goDir,
    encoding: "utf8",
  });
  assert.equal(r.status, 0, r.stderr);
}

test("sidecar crawl writes schema json and progress lines", async () => {
  ensureBin();
  const server = createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<html><body>ok</body></html>");
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  const dir = mkdtempSync(join(tmpdir(), "shroodler-desk-"));
  const out = join(dir, "scan.json");
  const child = spawn(bin, ["crawl", `http://127.0.0.1:${port}/`, "--depth", "0", "--output", out], {
    encoding: "utf8",
  });
  let stdout = "";
  child.stdout.on("data", (d) => {
    stdout += d;
  });
  const code = await new Promise((resolve) => child.on("close", resolve));
  server.close();
  assert.equal(code, 0, stdout);
  const doc = JSON.parse(readFileSync(out, "utf8"));
  assert.ok(Array.isArray(doc.findings));
  assert.ok(Array.isArray(doc.pages));
  assert.ok(stdout.split("\n").some((l) => parseProgress(l)));
});
