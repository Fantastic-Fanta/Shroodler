#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PIDDIR="$ROOT/.local-run"
if [ ! -d "$PIDDIR" ]; then
  exit 0
fi
for f in "$PIDDIR"/*.pid; do
  [ -f "$f" ] || continue
  pid="$(cat "$f")"
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    echo "stopped $(basename "$f" .pid) pid $pid"
  fi
  rm -f "$f"
done
