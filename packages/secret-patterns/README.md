# Secret-pattern rule-pack

YAML patterns, path wordlists, and keyword lists consumed by both crawlers as data.
Never hardcode patterns, probe paths, or keywords in crawler source.

- `rules/*.yaml` — regex (or `__ENTROPY__`) secret rules
- `wordlists/*.txt` — one path per line; `#` comments allowed
  - `common-paths.txt` — exposed-file probe paths
  - `source-control.txt`, `well-known.txt` — additional probe path groups
  - `backup-suffixes.txt` — suffixes appended to discovered interesting paths
  - `backup-interesting.txt` — last-segment names that qualify a crawled page for
    backup-name mutation (e.g. `config` → `config.bak`)
- `keywords/html-comments.txt` — leftover HTML comment markers (`TODO`, `FIXME`,
  credential-like words)

Adding a rule, path, or keyword is a data change plus an `expected_findings.json` /
`expected_not_found` row on the target-app fixture that should or should not serve it.
404 is not a finding.
