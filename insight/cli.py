"""The insight command.

insight check <elf>              check the HBNG annotations of an executable
insight check --against-r <elf>  also compare each instruction's annotation with R
insight forms <elf>... -o <json> --origin <text>  add AArch64 executables to a corpus of forms
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile

from insight.annotations.check import check_elf
from insight.flips.forms import Corpus, add_file, load_corpus, save_corpus

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
    check.add_argument(
        "--against-r",
        action="store_true",
        help="also compare each instruction's annotation with R, the reference semantics",
    )
    forms = commands.add_parser("forms", help="add the instruction forms of AArch64 executables to a corpus")
    forms.add_argument("elfs", type=Path, nargs="+", help="AArch64 ELF files")
    forms.add_argument(
        "-o", "--output", type=Path, required=True, help="the corpus (JSON), extended if it exists"
    )
    forms.add_argument(
        "--origin", required=True, help="where the files come from, recorded with each file's sha256"
    )
    return parser


def check(path: Path, max_issues: int, *, against_r: bool) -> int:
    with path.open("rb") as file:
        report = check_elf(ELFFile(file), against_r=against_r)
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
    if against_r:
        unsupported = sum(report.unsupported.values())
        out.write(f"R: {unsupported} instructions without a rule\n")
        for reason, count in sorted(report.unsupported.items(), key=lambda item: -item[1])[:max_issues]:
            out.write(f"  {count:7}  {reason}\n")
    return 0 if report.ok else 1


def forms(paths: list[Path], output: Path, origin: str) -> int:
    corpus = load_corpus(output) if output.exists() else Corpus()
    for path in paths:
        add_file(corpus, path, origin)
    save_corpus(corpus, output)
    sys.stdout.write(f"{output}: {len(corpus.forms)} forms from {len(corpus.sources)} files\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = arguments().parse_args(argv)
    if args.command == "check":
        return check(args.elf, args.max_issues, against_r=args.against_r)
    if args.command == "forms":
        return forms(args.elfs, args.output, args.origin)
    return 2
