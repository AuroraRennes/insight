"""The insight command.

insight check <elf>    check the HBNG annotations of an executable
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

from insight.annotations.check import check_elf

DEFAULT_MAX_ISSUES = 50


def arguments() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="insight", description="CoreSight decoding and HBNG annotation checks"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser(
        "check", help="check every annotated block: framing, send lines and the pairing of values with sends"
    )
    check.add_argument("elf", type=Path, help="an executable built with the HBNG compiler")
    check.add_argument(
        "--max-issues",
        type=int,
        default=DEFAULT_MAX_ISSUES,
        help=f"issues to print, all being counted (default {DEFAULT_MAX_ISSUES})",
    )
    return parser


def check(path: Path, max_issues: int) -> int:
    with path.open("rb") as file:
        report = check_elf(ELFFile(file))
    out = sys.stdout
    for issue in report.issues[:max_issues]:
        out.write(f"{issue}\n")
    if len(report.issues) > max_issues:
        out.write(f"... {len(report.issues) - max_issues} more\n")
    if report.old_format:
        out.write(f"{path}: old annotation format, not checked\n")
    else:
        out.write(
            f"{path}: {report.blocks} blocks, {report.groups} instructions, {report.sends} sends, "
            f"{len(report.issues)} issues\n"
        )
    return 0 if report.ok else 1


def main(argv: list[str] | None = None) -> int:
    args = arguments().parse_args(argv)
    if args.command == "check":
        return check(args.elf, args.max_issues)
    return 2
