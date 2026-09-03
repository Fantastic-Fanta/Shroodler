# Changelog

## 0.2.0 — 2026-09-01

Cloud/SaaS pack (`rules/cloud.yaml`): GitHub PAT (`ghp_`) and fine-grained PAT
(`github_pat_`), npm access tokens (`npm_`), Stripe secret keys (`sk_live_` / `sk_test_`;
publishable `pk_` is not a secret-key match), Google API keys (`AIza`), SendGrid, OpenAI
project keys, Slack webhooks, and Azure storage account keys (`AccountKey=` /
`SharedAccessKey=` with an 88-character key). Wordlists split into `common-paths.txt`,
`source-control.txt`, and `well-known.txt`; both crawlers load every `wordlists/*.txt`.

## 0.1.1 — 2026-09-02

Backup-name mutation wordlists: `wordlists/backup-suffixes.txt` (`.bak`, `.old`,
`.orig`, `~`, `.swp`, `.copy`) and `wordlists/backup-interesting.txt`. Both crawlers
load these as data; 404 is not a finding.

## 0.1.0 — 2026-09-01

Initial rule-pack: AWS keys, JWT, private key block, Slack token, entropy heuristic,
basic-auth URLs, database connection strings.
