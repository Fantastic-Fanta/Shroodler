# UI Style Guide (Desktop App)

This is the single source of truth for the desktop app's visual design and motion, the
same way `02-SPEC.md` is for the JSON schema. Read this in full before writing any UI
code (Milestone 12+). If a design decision isn't covered here, favor restraint and
consistency with what's already defined over inventing something new.

## 1. Color palette

Extracted from a reference image: a dark, warm-neutral body with one glowing cool-mint
focal point, a calm slate-gray secondary, and one small, rare accent color. The app
should feel grounded and a little nocturnal, with a single point of light — not a
generic dark-mode dev tool.

| Token | Hex (approx) | Role |
|---|---|---|
| `bg-base` | `#211A17` | App background (warm charcoal-brown, not pure black) |
| `bg-raised` | `#2A2320` | Panels, cards, sidebar — one step lighter than base |
| `bg-hover` | `#332A26` | Hover/pressed state on raised surfaces |
| `border` | `#4A4038` | Default borders/dividers, warm-toned not gray |
| `accent` | `#8FE6C4` | Primary buttons, active nav item, links, progress indicator — the app's "glow" |
| `accent-dim` | `#5FA98A` | Accent at rest / secondary emphasis (e.g. inactive but selected) |
| `secondary` | `#6E8494` | Secondary buttons, muted chrome, inactive icons |
| `text-primary` | `#EDE8C8` | Primary body text on dark backgrounds (warm cream, not stark white) |
| `text-muted` | `#B3AD94` | Secondary/help text |
| `accent-rare` | `#9B7FC0` | Reserved for exactly one purpose at a time — see below |

**`accent-rare` (purple) usage rule**: in the reference image this color appears once, on
the beak tip — a small, deliberate accent, not a workhorse color. In the app it must be
used for exactly one recurring purpose, chosen once and applied consistently — e.g. the
"critical" severity tag, or the focus ring on inputs. Do not let it spread into general
UI decoration; if you're reaching for it a second time for something unrelated, use
`accent` or `secondary` instead.

**Severity colors** stay semantically conventional (this is a security-tool usability
convention users already rely on — don't force the brand palette onto these), but tune
saturation/warmth so they sit comfortably against the warm-brown background instead of
reading as generic Bootstrap colors:

| Severity | Hex (approx) |
|---|---|
| critical | `#E5484D` |
| high | `#F0883E` |
| medium | `#E8B339` |
| low | `#5B9BD1` |
| info | `#8B8A85` |

## 2. Typography

- **UI chrome, labels, body text**: system sans font stack (SF Pro on macOS), fallback
  `Inter`. No separate display/heading font — restraint over decoration.
- **Technical data** (URLs, headers, cookies, JSON, secret evidence, findings detail):
  monospace — `SF Mono` on macOS, fallback `JetBrains Mono`. Anything that's literally
  data from a scan should render in monospace so it reads as data, not prose.
- Headings use the same sans stack, distinguished by weight, not a different typeface.

## 3. Layout

- **Sidebar** (`bg-raised`): scan history, target list, settings. Active item highlighted
  with `accent`, not a full background fill — a left border or subtle tint is enough.
- **Main pane**: findings table with a detail drawer that opens on row selection (slides
  in from the side, doesn't navigate away from the table).
- **Top bar**: target input, start/stop scan control, live progress indicator using
  `accent`.
- **Cards** (scan summaries, target tiles): `bg-raised`, 1px `border`, small radius, no
  heavy drop shadows — flat and native-feeling rather than skeuomorphic. A subtle
  translucent/frosted material (native macOS vibrancy, if Tauri exposes it easily) is a
  reasonable option for the sidebar or top bar if it doesn't cost meaningful extra effort
  — optional polish, not a requirement.

## 4. Motion

The app should feel calm and purposeful, not decorative — this is a security tool people
use to make judgment calls, not a marketing site. Apply these rules to every animation
decision instead of inventing motion case-by-case:

1. **Restraint first.** Only animate to communicate a state change (loading, success,
   error, focus) or a spatial relationship (where a panel came from or is going). Never
   animate purely for decoration.
2. **Justify before you style.** Before picking a duration or easing curve, be able to
   say what the animation is communicating. If you can't, don't add it.
3. **Springs for interruptible motion, short easing for feedback.** Use spring-based
   motion for anything the user can interrupt mid-animation by acting again — opening/
   closing the finding detail drawer, resizing panels. Use short fixed-duration ease-out
   curves (roughly 100–200ms) for small, atomic feedback like a button press or hover
   state.
4. **Respect interruption.** If a user re-triggers an action while its animation is still
   running (e.g. re-opens a drawer that's mid-close), the new animation must continue
   from the current visual state, not reset and restart.
5. **Keep it short.** 100–200ms for micro-feedback (hover, press, toggle), 200–350ms for
   panel/drawer/modal transitions. The one exception is the scan-progress indicator
   itself, which reflects a real ongoing process, not a UI transition, so it runs for as
   long as the scan does.
6. **Never block on motion.** The user should never have to wait for an animation to
   finish before they can act again — don't disable input during a drawer's open
   transition, for example.
7. **Always provide a reduced-motion fallback.** Check the OS-level "reduce motion"
   setting and swap springs/slides for instant or opacity-only transitions when it's on.
8. **Where motion is actually used in this app** — resist adding it anywhere else:
   - Scan running: a subtle pulse on the `accent`-colored progress indicator.
   - A new finding arriving during a live scan: a calm fade + slight slide into the
     findings list — not bouncy, not attention-grabbing beyond that.
   - Opening/closing the finding detail drawer: spring-based slide.
   - Severity filter toggling: animate rows leaving/entering the filtered list rather
     than snapping, so users don't lose their place.
   - Baseline/diff view (Milestone 14): this is the one place a more noticeable
     treatment is justified, since the view's entire purpose is to draw attention to
     what changed — new findings get a brief `accent`-tinted background fade that
     settles to normal, resolved findings fade out.
   - Everything else (switching sidebar sections, scrolling tables, static content):
     little to no motion — snappy, not performative.
