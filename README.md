# Shroodler

Self-contained web attack-surface mapping toolkit. All target apps live in this repo
and are intended for local use only.

See `docs/` for architecture, spec, test matrix, and milestones.

```
make up       # start target apps
make down     # stop target apps
make verify   # lint + tests + integration (grows with each milestone)
```
