# Payload-tester packs

YAML payload packs consumed by the Python tester (and the Go engine) as data. Never
hardcode payload strings in tester source.

- `id` — pack entry id
- `finding_id` — optional finding id (defaults to `id`)
- `payload` — string submitted into each form field
- `severity` / `description`
- `match.any` / `match.all` — `status_gte`, `body_contains` (sql-error style), `reflected`

`sqli.yaml` and `xss.yaml` are the default set that matches the original hardcoded
payloads. Extra files in this directory load automatically; `--pack PATH` merges more.
