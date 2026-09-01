#!/usr/bin/env bash
# Start target apps as local processes when Docker is unavailable.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PIDDIR="$ROOT/.local-run"
VENV="$ROOT/.venv"
mkdir -p "$PIDDIR"

if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install -q -r "$ROOT/packages/target-apps/app1-server-rendered/requirements.txt"

start_if_needed() {
  local name="$1" port="$2" cmd="$3"
  if curl -sf "http://127.0.0.1:${port}/" >/dev/null 2>&1; then
    echo "$name already up on :$port"
    return
  fi
  eval "$cmd" >"$PIDDIR/${name}.log" 2>&1 &
  echo $! >"$PIDDIR/${name}.pid"
  echo "started $name pid $! :$port"
}

ensure_app2() {
  local dir="$ROOT/packages/target-apps/app2-spa"
  if [ ! -f "$dir/dist/index.html" ]; then
    (cd "$dir" && npm install && npm run build)
  fi
}

start_if_needed app1 8081 "\"$VENV/bin/python\" \"$ROOT/packages/target-apps/app1-server-rendered/app.py\""
ensure_app2
start_if_needed app2 8082 "node \"$ROOT/packages/target-apps/app2-spa/server.mjs\""
start_if_needed app3 8083 "node \"$ROOT/packages/target-apps/app3-crawler-traps/server.mjs\""

wait_port() {
  local name="$1" port="$2"
  for _ in $(seq 1 40); do
    if curl -sf "http://127.0.0.1:${port}/" >/dev/null 2>&1; then
      echo "$name ready"
      return 0
    fi
    sleep 0.25
  done
  echo "$name failed to become ready" >&2
  cat "$PIDDIR/${name}.log" >&2 || true
  return 1
}

wait_port app1 8081
wait_port app2 8082
wait_port app3 8083
