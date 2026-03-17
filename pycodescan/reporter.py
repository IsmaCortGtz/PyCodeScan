"""Terminal output formatting for PyCodeScan reports."""
from __future__ import annotations

import sys
from typing import List

from .detectors.base import Vulnerability

# ANSI escape codes
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
GREEN  = "\033[92m"

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",   # bright red
    "HIGH":     "\033[31m",   # red
    "MEDIUM":   "\033[33m",   # yellow
    "LOW":      "\033[34m",   # blue
}

SEVERITY_LABEL = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH    ",
    "MEDIUM":   "MEDIUM  ",
    "LOW":      "LOW     ",
}

_USE_COLOR = sys.stdout.isatty()


def _c(text: str, *codes: str, use_color: bool = True) -> str:
    if not use_color:
        return text
    return "".join(codes) + text + RESET


def _wrap(text: str, width: int = 66, indent: str = "         ") -> str:
    words = text.split()
    lines: List[str] = []
    current = ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return f"\n{indent}".join(lines)


def print_report(
    filepath: str,
    vulns: List[Vulnerability],
    use_color: bool = True,
) -> None:
    uc = use_color

    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns:
        counts[v.severity] = counts.get(v.severity, 0) + 1

    total = len(vulns)
    bar = "=" * 72

    print()
    print(_c(bar, BOLD, use_color=uc))
    print(_c("  PyCodeScan — Security Analysis", BOLD, use_color=uc))
    print(_c(bar, BOLD, use_color=uc))
    print(f"  File  : {filepath}")
    print(f"  Found : {total} issue{'s' if total != 1 else ''}")
    print(_c("-" * 72, DIM, use_color=uc))

    if total == 0:
        print(_c("  No vulnerabilities detected. Good job!", GREEN, use_color=uc))
        print(_c(bar, BOLD, use_color=uc))
        print()
        return

    for idx, vuln in enumerate(vulns, 1):
        color   = SEVERITY_COLOR.get(vuln.severity, "")
        label   = SEVERITY_LABEL.get(vuln.severity, vuln.severity)
        header  = f"  [{idx:>2}]  {label}  {vuln.name}"

        print()
        print(_c(header, BOLD, color, use_color=uc))
        print(f"         Location    : line {vuln.line}, col {vuln.col}")
        print(f"         Description :")
        print(f"           {_wrap(vuln.description, width=64, indent='           ')}")
        print()
        print(f"         Recommendation:")
        print(f"           {_wrap(vuln.recommendation, width=64, indent='           ')}")
        print(_c("  " + "-" * 70, DIM, use_color=uc))

    print()
    print(_c("  Summary:", BOLD, use_color=uc))
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = counts[sev]
        if n:
            color = SEVERITY_COLOR[sev]
            print(f"    {_c(sev, color, use_color=uc)}: {n}")
    print(_c(bar, BOLD, use_color=uc))
    print()
