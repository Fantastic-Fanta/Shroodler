export function findingKey(f) {
  return `${f.id}|${f.url}`;
}

export function diffScans(base, compare) {
  const baseSet = new Map((base.findings || []).map((f) => [findingKey(f), f]));
  const compareSet = new Map((compare.findings || []).map((f) => [findingKey(f), f]));
  const added = [];
  const resolved = [];
  for (const [k, f] of compareSet) {
    if (!baseSet.has(k)) added.push(f);
  }
  for (const [k, f] of baseSet) {
    if (!compareSet.has(k)) resolved.push(f);
  }
  return { added, resolved };
}
