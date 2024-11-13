import argparse
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from onsight.parsers.parser import Parser
from onsight.verifiers.direct_jump_verifier import DirectJumpVerifier
from onsight.verifiers.shadow_stack_verifier import ShadowStackVerifier
from onsight.verifiers.verifier import Verifier

if TYPE_CHECKING:
    from onsight.execution_trace import ExecutionTrace

logger = logging.getLogger("onsight")

VERIFIERS: dict[str, type[Verifier]] = {
    "shadow-stack": ShadowStackVerifier,
    "direct-jump": DirectJumpVerifier,
}


class ArgParser(argparse.ArgumentParser):
    def __init__(self) -> None:
        super().__init__(description="Onsight, perf/CoreSight parser and verifier")
        self.add_parse_arguments()

    def add_parse_arguments(self) -> None:
        # Required input file argument
        self.add_argument(
            "-i",
            "--input_file",
            type=str,
            help="Path to the input trace file to be processed."
            "Its extension is used to determine the fitting parser"
            "supported: .perf.dump (from perf report), .perf.disasm.log (from perf script)",
        )

        # Optional verifiers argument, allowing multiple choices with combinable syntax
        self.add_argument(
            "-v",
            "--verifiers",
            type=str,
            help="List of verifiers to apply on the parsed trace."
            "Use ',' to combine verifiers (e.g., shadow-stack,direct-jumps).",
        )

    def parse(self, args: list[str]) -> argparse.Namespace:
        return self.parse_args(args)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    arg_parser: ArgParser = ArgParser()
    args: argparse.Namespace = arg_parser.parse(argv)

    if not argv:
        arg_parser.print_help()
        return 0

    logger.debug("Finding parser.")
    input_file_path: Path = Path(args.input_file)
    extension: str = "".join(input_file_path.suffixes)

    try:
        method_name: str = f"for{extension.replace(".", "_")}"
        parser: Parser = getattr(Parser, method_name)()
    except AttributeError:
        logger.exception(
            f"Parser not defined for extension '{extension}'" "(or not propagated in the 'Parser' class)"
        )

    logger.debug(f"Parsing input file {args.input_file}.")
    execution_trace: ExecutionTrace = parser.parse(args.input_file)

    verifiers: list[str] = args.verifiers.split(",")
    for verifier_name in verifiers:
        try:
            verifier: Verifier = VERIFIERS[verifier_name]()
            verifier.verify_trace(execution_trace)
        except KeyError:
            logger.exception(f"Verifier '{verifier_name}' not defined.")

    return 0
