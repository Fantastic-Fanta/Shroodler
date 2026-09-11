# LLM agent evaluation harness

Measures whether the LLM agent actually finds the real bugs (recall) without
crying wolf (precision), and at what cost — so "smarter" is a number, not a
vibe. Scoring lives in `shroodler/eval_harness.py`; this directory holds the
ground truth and the runner.

## Concept

1. Curate an **expected-findings** file per target: the finding ids and URLs a
   correct run should surface (the ground truth). Format:

   ```json
   {"findings": [
     {"id": "sqli-error", "url": "http://127.0.0.1:8081/api/items?id=1"},
     {"id": "xss-reflected", "url": "http://127.0.0.1:8081/search?q=x"}
   ]}
   ```

   Matching is by `(id, url-path)` — the same key `shroodler diff --gate` uses,
   so the query string does not have to match exactly.

2. Run the agent against the target and score its findings:

   ```bash
   shroodler eval <scan-or-state.json> eval/expected/app1.json --label app1
   ```

   `<scan-or-state.json>` can be the saved program-state JSON (it contains a
   `findings` list) or any scan JSON. If the JSON carries `cost_usd` /
   `iterations` (the agent's stdout does), they appear on the scorecard.

3. A/B the LLM tools **on vs off** to attribute the difference:

   ```bash
   shroodler eval on.json  eval/expected/app1.json --baseline off.json
   ```

   prints Δ recall, Δ precision, Δ false-positives, and what was newly found.

## Running against the local target apps

The four apps in `docker-compose.yml` (private `target-apps` submodule) serve
on ports 8081–8084. Bring them up, run the agent with and without the LLM
tools, and score:

```bash
docker compose up -d
# tools ON (default)
shroodler agent --program eval-app1 --target http://127.0.0.1:8081/ \
  --allow-external --llm-agent > on.json
# tools OFF (deterministic loop only) for the A/B baseline
shroodler agent --program eval-app1-base --target http://127.0.0.1:8081/ \
  --allow-external > off.json
# score (findings live in the saved state each run prints as state_path)
shroodler eval "$(jq -r .state_path on.json)"  eval/expected/app1.json \
  --baseline "$(jq -r .state_path off.json)"
```

`make eval-agent` wraps this for all four apps once you have curated expected
files and `DEEPSEEK_API_KEY` set.

## Curating ground truth

There is no shortcut: run the agent (and a manual pass) against each app once,
inspect the findings, and record the true bugs — id and URL — into
`expected/appN.json`. `expected/app1.example.json` shows the shape. Re-score on
every prompt or model change to catch regressions.
