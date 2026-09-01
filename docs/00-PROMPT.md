# Project Kickoff Prompt

Paste this into Cursor's chat/agent mode as your first message. It references the other
files in this folder — make sure they're all in the repo root (or a `/docs` folder) before
you start, since the prompt tells Cursor to read them.

---

## Prompt

You are building **Shroodler**, a self-contained web attack-surface mapping toolkit,
entirely for use against local, self-hosted target applications that are part of this
same repo. Nothing in this project touches third-party systems.

Before writing any code, read these files in full:
- `docs/01-ARCHITECTURE.md` — repo layout, tech stack, package boundaries
- `docs/02-SPEC.md` — data contracts (finding schema, expected_findings format, CLI/API shape)
- `docs/03-TEST-MATRIX.md` — the exhaustive test matrix every feature must satisfy
- `docs/04-MILESTONES.md` — the ordered build plan with checkboxes
- `docs/05-EXTERNAL-TARGETS.md` — the only internet hosts you're ever allowed to point
  the crawler at, and only for the optional Milestone 24 (see ground rule 10)
- `docs/06-UI-STYLE.md` — colors, typography, layout, and motion rules for the desktop
  app (Milestones 16, 17, 18, 19, 20). Treat it as the single source of truth for design
  decisions, the same way `02-SPEC.md` is for the JSON schema — don't improvise a
  different look.
- `docs/07-PROXY-SPEC.md` — the full contract for the Fiddler-style intercepting proxy
  (Milestones 12–15 for the engine, 19–20 for its GUI)

**Ground rules:**
1. Follow the milestone order in `04-MILESTONES.md`. Don't skip ahead to later milestones
   before earlier ones are green (all their tests passing).
2. Every feature you build must have a corresponding row in the test matrix implemented
   as an actual automated test before you consider it done. If a feature doesn't have a
   matrix row yet, add one to `03-TEST-MATRIX.md` and then implement the test.
3. After finishing each milestone, run the full verification loop (`make verify` — set
   this up in Milestone 0). I will not be watching this run in real time, so don't wait
   for me to review output or say "continue" — if it passes, move straight to the next
   milestone yourself. If it fails, try to fix it yourself first; only stop and leave a
   note (per rule 12) if you're genuinely stuck after real effort.
4. Keep the JSON finding schema in `02-SPEC.md` as the single source of truth. If you need
   to change it, update the doc first, then propagate the change to all packages.
5. All target apps live under `packages/target-apps/` and are intentionally vulnerable —
   this is expected and correct, do not "fix" their vulnerabilities. Only fix bugs in the
   *tooling* (crawler, extractors, report generator).
6. When a milestone involves both the Python and Go implementations, treat "passes cross-
   language parity test" as part of the definition of done, not optional polish.
7. Work milestone-by-milestone. At the start of each one, restate which milestone you're
   on and what "done" looks like for it (pull directly from `04-MILESTONES.md`).
8. Commit as you go: after each major change (a new extractor, a passing matrix section,
   a milestone going green) make a git commit with a clear message. Don't batch multiple
   milestones into one commit — small, frequent commits so nothing is lost if a run is
   interrupted.
9. Commits must be attributed to me alone. Do not add "Co-Authored-By", "Generated with
   Cursor", tool banners/links, or any other self-attribution to commit messages, code
   comments, file headers, or the README — no trace of the tool used to build this should
   appear anywhere in the repo.
10. This project never touches the real internet except for the specific hosts listed in
    `docs/05-EXTERNAL-TARGETS.md`, and only inside Milestone 24, and only behind an
    opt-in flag that is off by default. Never scan, crawl, or send requests to any other
    external domain for any reason (including "just checking," debugging, or fetching a
    dependency's docs) — everything else must stay against `localhost` targets. This rule
    is specifically about the crawler *actively probing* hosts; it does not apply to the
    proxy (rule 11), which is a different kind of capability.
11. The proxy (`proxy-go`, Milestones 12–15 and 19–20) intercepts traffic that's actively
    routed through it — it doesn't probe anything on its own — so it isn't restricted to
    `docs/05-EXTERNAL-TARGETS.md`. Even so: root CA installation must never happen
    silently — always require an explicit confirmation step (in the CLI, print exactly
    what's being installed and require a flag/prompt; in the GUI, a real confirmation
    dialog) — and never write CA private keys or captured session files into the repo
    (add proxy CA/data directories to `.gitignore` in Milestone 12).
12. **I am leaving this running unattended and will not be reachable at all until it's
    fully done.** Do not ask me anything — not a clarifying question, not a "does this
    look right?", not a yes/no confirmation, not "should I proceed?" — at any point before
    every milestone through Milestone 24 is complete. Asking and then sitting idle waiting
    for a reply is the single worst thing you can do here, because no reply is coming and
    you'll just stall for however long you wait. You do not need my nod for anything:
    - Ambiguous spec details: make the most reasonable, conservative call yourself (favor
      whatever's simplest to change later, never anything destructive/irreversible), log
      the assumption and why in `docs/DECISIONS.md` (create it if it doesn't exist), and
      keep going immediately — don't pause after logging it.
    - A milestone you can't get `make verify` green on after real, sustained effort: log
      exactly what's failing and what you tried in `docs/DECISIONS.md`, commit what you
      have, and move on to the next milestone rather than looping or stopping.
    - Anything else that would normally feel worth flagging: log it in `docs/DECISIONS.md`
      and continue. A written note I'll read later is always the right move, a question
      that blocks on my reply is never the right move, for anything in this project.
    The only genuine exception — where stopping outright (not asking, just halting) is
    correct — is something that strictly requires me as a person and can't be logged and
    deferred: needing real credentials/an account/a purchase, or a step that's destructive
    or irreversible and outside what these docs already authorize. That should not come up
    anywhere in this plan, but if it somehow does, stop and clearly explain why in
    `docs/DECISIONS.md` rather than asking in chat, since I won't see chat until I'm back.
    Otherwise: work straight through every milestone in `04-MILESTONES.md`, in order, all
    the way to Milestone 24, start to finish, with zero questions and zero pauses.

**Start now with Milestone 0**: scaffold the monorepo structure exactly as described in
`01-ARCHITECTURE.md`, set up Docker Compose, and get an empty `make verify` pipeline
running (even if it just runs `echo "no tests yet"` for now — the point is the loop exists
before there's anything to test). Then continue straight through every remaining
milestone in order, per rule 12, until Milestone 24 or you hit something in that rule's
stop conditions.
