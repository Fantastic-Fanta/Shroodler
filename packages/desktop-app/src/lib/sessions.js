function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
}

function setCookiePairs(headers) {
  const pairs = [];
  for (const [k, v] of headerEntries(headers)) {
    if (String(k).toLowerCase() !== "set-cookie") continue;
    const values = Array.isArray(v) ? v : [v];
    for (const raw of values) {
      const first = String(raw || "").split(";")[0];
      const i = first.indexOf("=");
      if (i < 0) continue;
      const name = first.slice(0, i).trim();
      if (name) pairs.push([name, first.slice(i + 1).trim()]);
    }
  }
  return pairs;
}

function chronological(sessions) {
  const rows = [...(sessions || [])];
  if (rows.length && rows.every((s) => s.started_at)) {
    rows.sort((a, b) => String(a.started_at).localeCompare(String(b.started_at)));
  }
  return rows;
}

export function cookieHeaderFromSessions(sessions, targetUrl) {
  const origin = originOf(targetUrl);
  const jar = new Map();
  for (const s of chronological(sessions)) {
    if (originOf(s.request?.url) !== origin) continue;
    for (const [name, value] of setCookiePairs(s.response?.headers)) {
      jar.set(name, value);
    }
  }
  return [...jar.entries()].map(([n, v]) => `${n}=${v}`).join("; ");
}

export function seedUrlsFromSessions(sessions, targetUrl) {
  const origin = originOf(targetUrl);
  const seen = new Set();
  const urls = [];
  for (const s of chronological(sessions)) {
    const url = s.request?.url;
    if (!url || originOf(url) !== origin || seen.has(url)) continue;
    seen.add(url);
    urls.push(url);
  }
  return urls;
}

const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "trailers",
  "transfer-encoding",
  "upgrade",
]);

const SKIP_HEADERS = new Set([
  ...HOP_BY_HOP,
  "content-length",
  "content-encoding",
]);

export function statusClassBucket(code) {
  const n = Number(code);
  if (!Number.isFinite(n) || n < 100) return "none";
  if (n >= 500) return "5xx";
  if (n >= 400) return "4xx";
  if (n >= 300) return "3xx";
  if (n >= 200) return "2xx";
  return "none";
}

export function filterSessions(sessions, { method = "all", status = "all", url = "" } = {}) {
  const wantMethod = method === "all" || !method ? "" : String(method).toUpperCase();
  const needle = String(url || "").trim().toLowerCase();
  return (sessions || []).filter((s) => {
    if (wantMethod) {
      const m = String(s.request?.method || "").toUpperCase();
      if (m !== wantMethod) return false;
    }
    const code = s.response == null ? null : s.response.status_code;
    const bucket = statusClassBucket(code);
    if (status && status !== "all" && bucket !== status) return false;
    if (needle) {
      const hay = String(s.request?.url || "").toLowerCase();
      if (!hay.includes(needle)) return false;
    }
    return true;
  });
}

export function shellQuote(value) {
  const s = String(value);
  if (s.length === 0) return "''";
  if (!/[^a-zA-Z0-9_@%+=:,./-]/.test(s)) return s;
  const hasCtl = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(s);
  if (!hasCtl) return `'${s.replace(/'/g, `'\\''`)}'`;
  let out = "$'";
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const c = s.charCodeAt(i);
    if (ch === "'") out += "\\'";
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (c < 32 || c === 127) out += "\\x" + c.toString(16).padStart(2, "0");
    else if (c > 255) out += "\\u{" + c.toString(16) + "}";
    else out += ch;
  }
  return out + "'";
}

function headerEntries(headers) {
  if (!headers) return [];
  if (Array.isArray(headers)) {
    return headers
      .map((h) => {
        if (Array.isArray(h)) return [h[0], h[1]];
        if (h && typeof h === "object") return [h.name || h.key, h.value];
        return null;
      })
      .filter(Boolean);
  }
  return Object.entries(headers);
}

function headerValue(v) {
  if (Array.isArray(v)) return v.join(", ");
  return String(v);
}

function shouldSkipHeader(name) {
  const key = String(name || "").toLowerCase();
  if (!key || key.startsWith(":")) return true;
  return SKIP_HEADERS.has(key);
}

function decodeBody(body) {
  if (!body || body.content == null || body.content === "") return null;
  const encoding = String(body.encoding || "utf8").toLowerCase();
  if (encoding === "base64") {
    try {
      if (typeof atob === "function") return { raw: atob(body.content), binary: true };
    } catch {
      /* fall through */
    }
    return { raw: body.content, binary: true, encoded: "base64" };
  }
  return { raw: String(body.content), binary: false };
}

export function sessionToCurl(session) {
  const req = session?.request || {};
  const method = String(req.method || "GET").toUpperCase() || "GET";
  const url = req.url || "";
  const parts = ["curl"];
  if (method !== "GET") parts.push("-X", shellQuote(method));
  parts.push(shellQuote(url));

  for (const [name, value] of headerEntries(req.headers)) {
    if (shouldSkipHeader(name)) continue;
    parts.push("-H", shellQuote(`${name}: ${headerValue(value)}`));
  }

  const decoded = decodeBody(req.body);
  if (decoded) {
    if (decoded.encoded === "base64") {
      parts.push(
        "--data-binary",
        `"$(printf '%s' ${shellQuote(decoded.raw)} | base64 -d)"`,
      );
    } else {
      parts.push(decoded.binary ? "--data-binary" : "--data-raw", shellQuote(decoded.raw));
    }
  }

  return parts.join(" ");
}

export async function copyText(text) {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  if (typeof document === "undefined") {
    throw new Error("clipboard unavailable");
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.left = "-9999px";
  document.body.appendChild(ta);
  ta.select();
  const ok = document.execCommand("copy");
  document.body.removeChild(ta);
  if (!ok) throw new Error("clipboard copy failed");
}
