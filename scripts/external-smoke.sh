#!/usr/bin/env bash
# Opt-in external smoke. Never invoked by make verify.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export SHROODLER_ALLOW_EXTERNAL=1
"$ROOT/.venv/bin/shroodler" crawl https://httpbin.org/get --allow-external --depth 0 --output /tmp/shroodler-ext.json
"$ROOT/.venv/bin/python" -c "import json,jsonschema,pathlib; jsonschema.validate(json.load(open('/tmp/shroodler-ext.json')), json.load(open('$ROOT/schema/finding.schema.json')))"
echo "external smoke ok"
