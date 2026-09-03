"""Command-line entry. Delegates to the crawler-py CLI, which covers the full spec."""

from __future__ import annotations

from shroodler.cli import main as _crawler_main


def main(argv: list[str] | None = None) -> None:
    _crawler_main(argv)


if __name__ == "__main__":
    main()
