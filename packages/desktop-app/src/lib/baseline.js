export function pathOf(url) {
  try {
    return new URL(url).pathname || "/";
  } catch {
    return "/";
  }
}

export function documentToBaseline(doc, { name, suppressions = [] } = {}) {
  const pages = doc.pages || [];
  const findings = (doc.findings || []).filter((f) => !isSuppressed(f, suppressions));
  const expectedPages = [...new Set(pages.map((p) => pathOf(p.url)))].sort();
  const forms = {};
  for (const page of pages) {
    const path = pathOf(page.url);
    const names = new Set(forms[path] || []);
    for (const form of page.forms || []) {
      for (const field of form.fields || []) {
        if (field.name) names.add(field.name);
      }
    }
    if (names.size) forms[path] = [...names].sort();
  }
  const expectedFindings = findings
    .map((f) => ({ id: f.id || "", url: pathOf(f.url) }))
    .sort((a, b) => a.id.localeCompare(b.id) || a.url.localeCompare(b.url));
  const target = doc.target || "";
  return {
    target_app: name || target || "local-app",
    target,
    expected_pages: expectedPages,
    expected_forms: Object.fromEntries(Object.entries(forms).sort(([a], [b]) => a.localeCompare(b))),
    expected_findings: expectedFindings,
    expected_not_found: [],
  };
}

export function globMatch(pattern, value) {
  if (!pattern || pattern === "*") return true;
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`).test(value);
}

export function parseSuppressions(raw) {
  const text = String(raw || "").trim();
  if (!text) return [];
  if (text.startsWith("{") || text.startsWith("[")) {
    try {
      const data = JSON.parse(text);
      const list = Array.isArray(data) ? data : data.suppressions || [];
      return list.map((row) => ({
        id: row.id || "*",
        url: row.url || "*",
        reason: row.reason || "",
      }));
    } catch {
      return [];
    }
  }
  const rows = [];
  const blocks = text.split(/\n\s*-\s+/);
  for (const chunk of blocks) {
    const id = (chunk.match(/(?:^|\n)\s*id:\s*(\S+)/) || [])[1];
    const url = (chunk.match(/(?:^|\n)\s*url:\s*(\S+)/) || [])[1];
    const reasonM = chunk.match(/(?:^|\n)\s*reason:\s*(.*)$/m);
    if (!id && !url) continue;
    rows.push({
      id: (id || "*").replace(/^['"]|['"]$/g, ""),
      url: (url || "*").replace(/^['"]|['"]$/g, ""),
      reason: reasonM ? reasonM[1].trim().replace(/^["']|["']$/g, "") : "",
    });
  }
  return rows;
}

export function isSuppressed(finding, rules) {
  const path = pathOf(finding.url);
  for (const rule of rules || []) {
    if (rule.id !== "*" && rule.id !== finding.id) continue;
    if (globMatch(rule.url, path) || globMatch(rule.url, finding.url || "")) return rule;
  }
  return null;
}

export function suppressionsYaml(rules) {
  const lines = ["suppressions:"];
  for (const r of rules || []) {
    lines.push(`  - id: ${r.id || "*"}`);
    lines.push(`    url: ${r.url || "*"}`);
    if (r.reason) lines.push(`    reason: ${JSON.stringify(r.reason)}`);
  }
  if (!rules?.length) lines.push("  []");
  return lines.join("\n") + "\n";
}
