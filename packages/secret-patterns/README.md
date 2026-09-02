# Secret-pattern rule-pack

YAML patterns and path wordlists consumed by both crawlers as data. Never hardcode
patterns or probe paths in crawler source.

- `rules/*.yaml` — regex (or `__ENTROPY__`) secret rules
- `wordlists/*.txt` — one path per line; `#` comments allowed
  - `common-paths.txt` — exposed-file probe paths
  - `source-control.txt`, `well-known.txt` — additional probe path groups
  - `backup-suffixes.txt` — suffixes appended to discovered interesting paths
  - `backup-interesting.txt` — last-segment names that qualify a crawled page for
    backup-name mutation (e.g. `config` → `config.bak`)

Adding a rule or a path is a data change plus an `expected_findings.json` /
`expected_not_found` row on the target-app fixture that should or should not serve it.
404 is not a finding.
