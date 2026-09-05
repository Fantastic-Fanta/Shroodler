"""Guards against the hand-maintained shell completion scripts silently
drifting out of sync with the real argparse flags in shroodler/cli.py.

This only checks that every real long-option flag for each subcommand
appears somewhere in the completion scripts -- it can't prove there's
nothing *extra* or that the logic is right, but it catches the common and
dangerous case: someone adds a new flag and forgets the completion script.
"""

from __future__ import annotations

from pathlib import Path

from shroodler.cli import build_parser

COMPLETIONS_DIR = Path(__file__).resolve().parents[3] / "cli" / "completions"
BASH_SCRIPT = COMPLETIONS_DIR / "shroodler.bash"
ZSH_SCRIPT = COMPLETIONS_DIR / "_shroodler"

# proxy forwards raw args to shroodler-proxy and has no argparse flags of
# its own to check.
SKIP_SUBCOMMANDS = {"proxy"}


def _subparsers():
    parser = build_parser()
    for action in parser._actions:
        if hasattr(action, "choices") and isinstance(action.choices, dict):
            return action.choices
    raise AssertionError("no subparsers found")


def _long_flags(sub) -> set[str]:
    flags: set[str] = set()
    for action in sub._actions:
        for opt in action.option_strings:
            if opt.startswith("--") and opt != "--help":
                flags.add(opt)
    return flags


def test_bash_completion_has_every_long_flag():
    assert BASH_SCRIPT.is_file()
    text = BASH_SCRIPT.read_text(encoding="utf-8")
    missing: dict[str, set[str]] = {}
    for name, sub in _subparsers().items():
        if name in SKIP_SUBCOMMANDS or name in {"expected"}:
            continue
        gap = {f for f in _long_flags(sub) if f not in text}
        if gap:
            missing[name] = gap
    assert not missing, f"bash completion missing flags: {missing}"


def test_zsh_completion_has_every_long_flag():
    assert ZSH_SCRIPT.is_file()
    text = ZSH_SCRIPT.read_text(encoding="utf-8")
    missing: dict[str, set[str]] = {}
    for name, sub in _subparsers().items():
        if name in SKIP_SUBCOMMANDS or name in {"expected"}:
            continue
        gap = {f for f in _long_flags(sub) if f not in text}
        if gap:
            missing[name] = gap
    assert not missing, f"zsh completion missing flags: {missing}"


def test_man_page_exists_and_mentions_every_top_level_command():
    man_path = COMPLETIONS_DIR.parent / "man" / "shroodler.1"
    assert man_path.is_file()
    # Normalize troff's escaped hyphens (\-) back to plain "-" so a name
    # like "ingest-sessions" is found even though the source escapes each
    # hyphen for correct dash rendering.
    text = man_path.read_text(encoding="utf-8").replace("\\-", "-")
    for name in _subparsers():
        if name == "expected":
            continue  # documented as an alias of baseline in prose, not its own heading
        assert name in text, f"man page does not mention {name!r}"
