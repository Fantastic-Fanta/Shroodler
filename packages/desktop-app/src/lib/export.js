const SARIF_LEVEL = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

function xml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function renderSarif(doc, findings) {
  const rows = findings || doc.findings || [];
  const crawler = doc.crawler || {};
  const rules = [];
  const seen = new Set();
  for (const f of rows) {
    const id = f.id || "finding";
    if (seen.has(id)) continue;
    seen.add(id);
    rules.push({
      id,
      shortDescription: { text: id },
      fullDescription: { text: f.description || id },
    });
  }
  const results = rows.map((f) => ({
    ruleId: f.id || "finding",
    level: SARIF_LEVEL[f.severity] || "note",
    message: { text: f.description || f.id || "" },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: f.url || doc.target || "about:blank" },
        },
      },
    ],
  }));
  return (
    JSON.stringify(
      {
        version: "2.1.0",
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        runs: [
          {
            tool: {
              driver: {
                name: crawler.name || "shroodler",
                version: crawler.version || "0.1.0",
                rules,
              },
            },
            results,
          },
        ],
      },
      null,
      2,
    ) + "\n"
  );
}

export function renderJunit(doc, findings) {
  const rows = findings || doc.findings || [];
  const tests = Math.max(rows.length, 1);
  const fails = rows.length;
  const parts = [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<testsuite name="shroodler" tests="${tests}" failures="${fails}" errors="0">`,
  ];
  if (!rows.length) parts.push(`  <testcase classname="shroodler" name="ok"/>`);
  for (const f of rows) {
    const name = `${f.id || ""} ${f.url || ""}`.trim() || "finding";
    const classname = f.category || "finding";
    const message = f.description || name;
    const evidence = f.evidence || message;
    parts.push(`  <testcase classname="${xml(classname)}" name="${xml(name)}">`);
    parts.push(`    <failure message="${xml(message)}">${xml(evidence)}</failure>`);
    parts.push(`  </testcase>`);
  }
  parts.push(`</testsuite>`);
  return parts.join("\n") + "\n";
}

export function downloadText(filename, text, mime = "application/json") {
  const blob = new Blob([text], { type: mime });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
