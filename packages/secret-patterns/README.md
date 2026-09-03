# Secret-pattern rule-pack

YAML patterns and path wordlists consumed by both crawlers as data. Never hardcode
patterns or probe paths in crawler source.

- `rules/*.yaml` — regex (or `__ENTROPY__`) secret rules
- `wordlists/*.txt` — one path per line; `#` comments allowed

Adding a rule or a path is a data change plus an `expected_findings.json` row on a
target-app fixture.
