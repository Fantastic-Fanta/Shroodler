# Changelog

## 0.2.0 — 2026-09-01

Cloud/SaaS pack (`rules/cloud.yaml`): GitHub PAT, npm, Stripe, Google API, SendGrid,
OpenAI project keys, Slack webhooks. Wordlists split into `common-paths.txt`,
`source-control.txt`, and `well-known.txt`; both crawlers load every `wordlists/*.txt`.

## 0.1.1 — 2026-09-02

Backup-name mutation wordlists: `wordlists/backup-suffixes.txt` (`.bak`, `.old`,
`.orig`, `~`, `.swp`, `.copy`) and `wordlists/backup-interesting.txt`. Both crawlers
load these as data; 404 is not a finding.

## 0.1.0 — 2026-09-01

Initial rule-pack: AWS keys, JWT, private key block, Slack token, entropy heuristic,
basic-auth URLs, database connection strings.
