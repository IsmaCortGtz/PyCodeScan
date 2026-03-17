#!/usr/bin/env python3
"""PyCodeScan — command-line entry point."""
from __future__ import annotations

import argparse
import sys

from pycodescan.analyzer import Analyzer
from pycodescan.reporter import print_report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pycodescan",
        description=(
            "Analyze Python source files for common security vulnerabilities "
            "using AST — no external dependencies required."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  pycodescan script.py\n"
            "  pycodescan app.py utils.py --no-color\n"
            "  pycodescan examples/insecure_web_app.py\n"
        ),
    )
    parser.add_argument(
        "files",
        nargs="+",
        metavar="FILE",
        help="Python file(s) to analyze.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI color output.",
    )
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    analyzer = Analyzer()
    use_color = not args.no_color
    exit_code = 0

    for filepath in args.files:
        try:
            vulns = analyzer.analyze_file(filepath)
            print_report(filepath, vulns, use_color=use_color)
            if vulns:
                exit_code = max(exit_code, 1)
        except FileNotFoundError as exc:
            print(f"[error] {exc}", file=sys.stderr)
            exit_code = 2
        except (SyntaxError, ValueError) as exc:
            print(f"[error] {exc}", file=sys.stderr)
            exit_code = 2
        except Exception as exc:  # noqa: BLE001
            print(f"[error] Unexpected failure on {filepath}: {exc}", file=sys.stderr)
            exit_code = 2

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
