export function parseProgress(line) {
  const m = String(line).trim().match(/^PROGRESS pages=(\d+) current=(.*)$/);
  if (!m) return null;
  return { pages_crawled: Number(m[1]), current_url: m[2] };
}

export function filterFindings(findings, { severity = "all", category = "all" } = {}) {
  return (findings || []).filter((f) => {
    if (severity !== "all" && f.severity !== severity) return false;
    if (category !== "all" && f.category !== category) return false;
    return true;
  });
}

export function sortFindings(findings, key, dir = "asc") {
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const copy = [...(findings || [])];
  copy.sort((a, b) => {
    let av = a[key];
    let bv = b[key];
    if (key === "severity") {
      av = rank[a.severity] ?? 9;
      bv = rank[b.severity] ?? 9;
    }
    if (av < bv) return dir === "asc" ? -1 : 1;
    if (av > bv) return dir === "asc" ? 1 : -1;
    return 0;
  });
  return copy;
}

export function parseHeaderBlock(text) {
  const headers = {};
  for (const line of String(text || "").split("\n")) {
    const i = line.indexOf(":");
    if (i < 0) continue;
    headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return headers;
}

export function parseAutoResponderYaml(text) {
  const rules = [];
  const chunks = String(text || "")
    .split(/^- /m)
    .map((s) => s.trim())
    .filter(Boolean);
  for (const chunk of chunks) {
    const method = (chunk.match(/method:\s*(\S+)/) || [])[1] || "";
    const url_pattern = (chunk.match(/url_pattern:\s*(\S+)/) || [])[1] || "";
    const status = Number((chunk.match(/status:\s*(\d+)/) || [])[1] || 200);
    const bodyM = chunk.match(/body:\s*(.*)$/m);
    rules.push({
      match: { method, url_pattern },
      respond: { status, headers: {}, body: bodyM ? bodyM[1].trim() : "" },
    });
  }
  return rules;
}
