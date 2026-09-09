"""CI workflow templates for GitHub Actions, GitLab CI, and Bitbucket Pipelines."""

from __future__ import annotations

GITHUB_TEMPLATE = """\
name: shroodler

on:
  pull_request:
  schedule:
    - cron: "0 4 * * *"

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - name: Cache venv
        uses: actions/cache@v4
        with:
          path: .venv
          key: ${{{{ runner.os }}}}-shroodler-venv-${{{{ hashFiles('packages/crawler-py/pyproject.toml') }}}}
      - name: Install shroodler
        run: |
          python -m venv .venv
          .venv/bin/pip install -e packages/crawler-py
      - name: Crawl
        env:
          SHROODLER_SESSION_COOKIE: ${{{{ secrets.SHROODLER_SESSION_COOKIE }}}}
          ANTHROPIC_API_KEY: ${{{{ secrets.ANTHROPIC_API_KEY }}}}
        run: |
          .venv/bin/shroodler crawl "{target}" --program {program} --max-pages 50 -o scan.json
      - name: Diff against baseline
        run: |
          .venv/bin/shroodler diff scan.json expected_findings.json --gate --format github-annotations
      - name: Upload scan artifact
        uses: actions/upload-artifact@v4
        with:
          name: shroodler-scan
          path: scan.json
"""

GITLAB_TEMPLATE = """\
stages:
  - scan

shroodler:
  stage: scan
  image: python:3.12
  cache:
    key: shroodler-venv
    paths:
      - .venv/
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_PIPELINE_SOURCE == "schedule"
  script:
    - python -m venv .venv
    - .venv/bin/pip install -e packages/crawler-py
    - .venv/bin/shroodler crawl "{target}" --program {program} --max-pages 50 -o scan.json
    - .venv/bin/shroodler diff scan.json expected_findings.json --gate --format github-annotations
  artifacts:
    paths:
      - scan.json
    expire_in: 7 days
  variables:
    SHROODLER_SESSION_COOKIE: $SHROODLER_SESSION_COOKIE
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
"""

BITBUCKET_TEMPLATE = """\
image: python:3.12

definitions:
  caches:
    shroodler-venv: .venv

pipelines:
  pull-requests:
    '**':
      - step: &shroodler-scan
          name: shroodler
          caches:
            - shroodler-venv
          script:
            - python -m venv .venv
            - .venv/bin/pip install -e packages/crawler-py
            - .venv/bin/shroodler crawl "{target}" --program {program} --max-pages 50 -o scan.json
            - .venv/bin/shroodler diff scan.json expected_findings.json --gate --format github-annotations
          artifacts:
            - scan.json
  custom:
    nightly:
      - step: *shroodler-scan
"""

PLATFORMS = {
    "github": GITHUB_TEMPLATE,
    "gitlab": GITLAB_TEMPLATE,
    "bitbucket": BITBUCKET_TEMPLATE,
}


def render_ci_template(
    platform: str,
    *,
    program: str = "",
    target: str = "",
) -> str:
    key = (platform or "").strip().lower()
    if key not in PLATFORMS:
        raise ValueError(f"unknown CI platform {platform!r}; use github, gitlab, or bitbucket")
    slug = (program or "").strip() or "$PROGRAM"
    url = (target or "").strip() or "$TARGET"
    return PLATFORMS[key].format(program=slug, target=url)
