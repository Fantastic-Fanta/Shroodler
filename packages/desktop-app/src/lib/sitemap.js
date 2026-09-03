export function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
}

export function pathOf(url) {
  try {
    return new URL(url).pathname || "/";
  } catch {
    return "/";
  }
}

function makeNode(segment, path) {
  return { segment, path, page: null, findings: [], children: [] };
}

function childFor(node, segment) {
  let child = node.children.find((c) => c.segment === segment);
  if (!child) {
    const path = node.path === "/" ? `/${segment}` : `${node.path}/${segment}`;
    child = makeNode(segment, path);
    node.children.push(child);
  }
  return child;
}

function insertPath(root, path) {
  const segs = String(path || "/")
    .split("/")
    .filter(Boolean);
  if (segs.length === 0) return root;
  let node = root;
  for (const seg of segs) node = childFor(node, seg);
  return node;
}

function findNode(root, path) {
  if (!path || path === "/") return root;
  const segs = path.split("/").filter(Boolean);
  let node = root;
  for (const seg of segs) {
    node = node.children.find((c) => c.segment === seg);
    if (!node) return null;
  }
  return node;
}

function countPages(node) {
  let n = node.page ? 1 : 0;
  for (const c of node.children) n += countPages(c);
  return n;
}

function sortTree(node) {
  node.children.sort((a, b) => a.segment.localeCompare(b.segment));
  for (const c of node.children) sortTree(c);
}

export function flattenTree(node, depth = 0, out = []) {
  out.push({ ...node, depth });
  for (const c of node.children) flattenTree(c, depth + 1, out);
  return out;
}

export function buildSiteMap(pages = [], findings = [], sessions = []) {
  const seen = new Set((pages || []).map((p) => p.url));
  const extra = [];
  for (const s of sessions || []) {
    const url = s.request?.url;
    if (!url || seen.has(url)) continue;
    seen.add(url);
    extra.push({
      url,
      status_code: s.response?.status_code ?? 0,
      forms: [],
      params: [],
      cookies: [],
      headers: { present: [], missing: [] },
      js_files: [],
      source: "proxy",
    });
  }
  const allPages = [...(pages || []), ...extra];
  const origins = new Map();
  for (const page of allPages) {
    const origin = originOf(page.url) || "unknown";
    if (!origins.has(origin)) origins.set(origin, { origin, root: makeNode("", "/") });
    const host = origins.get(origin);
    const node = insertPath(host.root, pathOf(page.url));
    node.page = page;
  }
  for (const f of findings || []) {
    const origin = originOf(f.url);
    const host = origins.get(origin);
    if (!host) continue;
    const node = findNode(host.root, pathOf(f.url)) || host.root;
    node.findings.push(f);
  }
  const hosts = [...origins.values()].map((h) => {
    sortTree(h.root);
    return { origin: h.origin, tree: h.root, count: countPages(h.root) };
  });
  hosts.sort((a, b) => a.origin.localeCompare(b.origin));
  return hosts;
}

export function pageLabel(node) {
  if (!node.segment) return "/";
  return node.segment;
}
