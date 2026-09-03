const ENTROPY = /\b[A-Za-z0-9_\-/+=]{32,64}\b/g;

export const SECRET_RULES = [
  { id: "aws-access-key", pattern: "AKIA[0-9A-Z]{16}", severity: "high" },
  {
    id: "aws-secret-key",
    pattern: '(?i)(?:aws_?secret_?access_?key|secret_?access_?key)\\s*[:=]\\s*["\']?([A-Za-z0-9/+=]{40})',
    severity: "high",
  },
  { id: "generic-jwt", pattern: "eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+", severity: "medium" },
  { id: "private-key-block", pattern: "-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", severity: "critical" },
  { id: "slack-token", pattern: "xox[baprs]-[0-9A-Za-z-]{10,}", severity: "high" },
  { id: "generic-api-key", pattern: "__ENTROPY__", severity: "medium" },
  { id: "basic-auth-url", pattern: "https?://[^/\\s:'\"]+:[^/\\s@'\"]+@", severity: "high" },
  { id: "database-connection-string", pattern: '(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?|redis|mssql|mariadb)://[^\\s\'"]+', severity: "high" },
];

function shannon(s) {
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  let h = 0;
  for (const n of Object.values(freq)) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function scanSecrets(text, rules = SECRET_RULES) {
  const hits = [];
  for (const rule of rules) {
    if (rule.pattern === "__ENTROPY__") {
      const m = String(text).match(ENTROPY) || [];
      for (const tok of m) {
        if (tok.startsWith("eyJ") || tok.startsWith("AKIA")) continue;
        if (shannon(tok) >= 4.2 && new Set(tok).size >= 16) {
          hits.push({ id: rule.id, evidence: tok.slice(0, 8) + "…" });
        }
      }
      continue;
    }
    let flags = "g";
    let src = rule.pattern;
    if (src.startsWith("(?i)")) {
      flags = "gi";
      src = src.slice(4);
    }
    let re;
    try {
      re = new RegExp(src, flags);
    } catch {
      continue;
    }
    const found = String(text).match(re) || [];
    for (const tok of found) hits.push({ id: rule.id, evidence: tok.slice(0, 24) });
  }
  return hits;
}

export function parseCookieHeader(value) {
  const out = { name: "", secure: false, httpOnly: false, sameSite: null };
  const parts = String(value || "").split(";").map((s) => s.trim());
  if (!parts[0]) return out;
  const nv = parts[0].split("=");
  out.name = nv[0];
  for (const p of parts.slice(1)) {
    const k = p.split("=")[0].toLowerCase();
    if (k === "secure") out.secure = true;
    if (k === "httponly") out.httpOnly = true;
    if (k === "samesite") out.sameSite = (p.split("=")[1] || "").trim();
  }
  return out;
}
