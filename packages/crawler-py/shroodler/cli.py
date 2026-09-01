from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from shroodler.crawler import crawl_url
from shroodler.diffcmd import diff_documents, load_json
from shroodler.validate import validate_crawl


def _progress(pages: int, current: str) -> None:
    print(f"PROGRESS pages={pages} current={current}", flush=True)


def cmd_crawl(args: argparse.Namespace) -> int:
    depth = None if args.depth < 0 else args.depth
    result = crawl_url(
        args.url,
        mode=args.mode,
        depth=depth,
        ignore_robots=args.ignore_robots,
        allow_external=args.allow_external,
        progress=_progress,
    )
    doc = result.to_dict()
    validate_crawl(doc)
    text = json.dumps(doc, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    actual = load_json(args.findings)
    expected = load_json(args.expected)
    errors = diff_documents(actual, expected, pages_only=args.pages_only)
    if errors:
        for err in errors:
            print(err, file=sys.stderr)
        return 1
    print("diff ok")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    print("shroodler report is not implemented yet", file=sys.stderr)
    return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="shroodler")
    sub = p.add_subparsers(dest="command", required=True)

    crawl = sub.add_parser("crawl", help="Crawl a target URL")
    crawl.add_argument("url")
    crawl.add_argument("--mode", choices=["static", "headless"], default="static")
    crawl.add_argument("--depth", type=int, default=5, help="Max depth; -1 for unbounded")
    crawl.add_argument("--output", "-o")
    crawl.add_argument("--ignore-robots", action="store_true")
    crawl.add_argument(
        "--allow-external",
        action="store_true",
        help="Permit crawling listed public fixtures (off by default)",
    )
    crawl.set_defaults(func=cmd_crawl)

    diff = sub.add_parser("diff", help="Compare crawl JSON to expected_findings.json")
    diff.add_argument("findings")
    diff.add_argument("expected")
    diff.add_argument("--pages-only", action="store_true")
    diff.set_defaults(func=cmd_diff)

    report = sub.add_parser("report", help="Render findings JSON as HTML or CSV")
    report.add_argument("findings")
    report.add_argument("--format", choices=["html", "csv"], default="html")
    report.add_argument("--output", "-o")
    report.set_defaults(func=cmd_report)

    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        code = args.func(args)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
    raise SystemExit(code)


if __name__ == "__main__":
    main()
