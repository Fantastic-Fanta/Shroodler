#!/usr/bin/env bash
# eToro bug bounty scan commands — Bugcrowd engagement: etoro-mbb-og
# Scope: *.etoro.com (wildcard). Credentials stored in login-recipe.json.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# --- PR pass: authenticated surface only, skip /markets/ breadth ---
shroodler crawl https://www.etoro.com/ \
  --profile safe \
  --login-recipe "$DIR/login-recipe.json" \
  --seed https://www.etoro.com/portfolio \
  --seed https://www.etoro.com/watchlists \
  --seed https://www.etoro.com/feed \
  --seed https://www.etoro.com/copytrader \
  --exclude-path /markets/ \
  --allow-external \
  --user-agent "$UA" \
  -o "$DIR/www-crawl-safe.json"

# --- Nightly pass: balanced + IDOR, exclude /markets/ to focus budget on auth surfaces ---
shroodler crawl https://www.etoro.com/ \
  --profile balanced \
  --login-recipe "$DIR/login-recipe.json" \
  --seed https://www.etoro.com/portfolio \
  --seed https://www.etoro.com/watchlists \
  --seed https://www.etoro.com/feed \
  --seed https://www.etoro.com/copytrader \
  --seed https://www.etoro.com/social-trading/club \
  --seed https://www.etoro.com/discover/people \
  --exclude-path /markets/ \
  --allow-external \
  --check-idor \
  --user-agent "$UA" \
  -o "$DIR/www-crawl-nightly.json"

# --- Markets pass: separate budget, public surface only ---
shroodler crawl https://www.etoro.com/markets/ \
  --profile safe \
  --allow-external \
  --user-agent "$UA" \
  -o "$DIR/markets-crawl.json"

# --- Payload pass (against nightly crawl output) ---
shroodler payload "$DIR/www-crawl-nightly.json" \
  -o "$DIR/www-payload-hits.json"

# --- API subdomain (separate crawl, no login required for unauth surface) ---
shroodler crawl https://api.etoro.com/ \
  --profile balanced \
  --allow-external \
  --user-agent "$UA" \
  -o "$DIR/api-crawl.json"
