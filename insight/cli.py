"""The insight command.

insight check <elf>              check the HBNG annotations of an executable
insight check --against-r <elf>  also compare each instruction's annotation with R
insight forms <elf>... -o <json> --origin <text>  add AArch64 executables to a corpus of forms
insight fliptest <json>          flip tests of R over a corpus
"""

from __future__ import annotations

import argparse
import re
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
    fliptest = commands.add_parser("fliptest", help="flip tests of R over a corpus of forms")
    fliptest.add_argument("corpus", type=Path, help="a corpus written by 'insight forms'")
    fliptest.add_argument("--form", help="only the forms matching this regular expression")
    fliptest.add_argument("--instances", type=int, default=2, help="encodings per form (default 2)")
    fliptest.add_argument("--jobs", type=int, default=1, help="parallel workers (default 1)")
    fliptest.add_argument("--verbose", action="store_true", help="also print precision reports and notes")
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
        out.write(f"R: {report.jump_table_loads} jump-table loads taken as constant (read-only tables)\n")
    return 0 if report.ok else 1


def forms(paths: list[Path], output: Path, origin: str) -> int:
    corpus = load_corpus(output) if output.exists() else Corpus()
    for path in paths:
        add_file(corpus, path, origin)
    save_corpus(corpus, output)
    sys.stdout.write(f"{output}: {len(corpus.forms)} forms from {len(corpus.sources)} files\n")
    return 0


def fliptest(path: Path, form: str | None, instances: int, jobs: int, *, verbose: bool) -> int:
    from insight.flips.corpus_run import Summary, run_corpus, select  # noqa: PLC0415 (unicorn is slow to load)

    encodings = select(load_corpus(path).forms, form, instances)
    summary = Summary()
    out = sys.stdout
    for report in run_corpus(encodings, jobs):
        summary.reports.append(report)
        if report.failures:
            out.write(f"FAIL {report.text}  [{report.form}]\n")
            for message in report.failures[:8]:
                out.write(f"       {message}\n")
            if len(report.failures) > 8:
                out.write(f"       ... {len(report.failures) - 8} more\n")
        if verbose:
            for message in report.precision + report.untestable + report.notes:
                out.write(f"  --  {report.text}: {message}\n")
    skipped: dict[str, int] = {}
    for report in summary.skipped:
        reason = re.sub(r"operand \S+ is not a general register", "FP/SIMD operands", report.skipped or "")
        skipped[reason] = skipped.get(reason, 0) + 1
    for reason, count in sorted(skipped.items(), key=lambda item: -item[1]):
        out.write(f"skipped {count:5}  {reason}\n")
    precise = [r for r in summary.passed if r.precision]
    out.write(
        f"{len(summary.reports)} instructions, {len(summary.forms(summary.reports))} forms: "
        f"{len(summary.passed)} passed ({len(precise)} with precision reports), "
        f"{len(summary.failed)} failed ({len(summary.forms(summary.failed))} forms), "
        f"{len(summary.skipped)} skipped; "
        f"{sum(r.runs for r in summary.reports)} runs, against unicorn, not the A53\n"
    )
    return 0 if not summary.failed else 1


def main(argv: list[str] | None = None) -> int:
    args = arguments().parse_args(argv)
    if args.command == "check":
        return check(args.elf, args.max_issues, against_r=args.against_r)
    if args.command == "forms":
        return forms(args.elfs, args.output, args.origin)
    if args.command == "fliptest":
        return fliptest(args.corpus, args.form, args.instances, args.jobs, verbose=args.verbose)
    return 2
