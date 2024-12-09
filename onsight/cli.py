import argparse
import logging
import sys
from pathlib import Path

from onsight.constants import DATA_TESSLA
from onsight.exceptions import VerifierError
from onsight.execution_trace import ExecutionTrace
from onsight.parsers.parser import Parser
from onsight.serializer import Serializer
from onsight.verifiers.direct_jump_verifier import DirectJumpVerifier
from onsight.verifiers.shadow_stack_verifier import ShadowStackVerifier
from onsight.verifiers.verifier import Verifier

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
            "Its extension is used to determine the fitting parser."
            "The current perf resulting files are supported: *.perf.report, *.perf.script",
        )

        # Optional verifiers argument, allowing multiple choices with combinable syntax
        self.add_argument(
            "-v",
            "--verifiers",
            type=str,
            help="List of verifiers to apply on the parsed trace."
            "Use ',' to combine verifiers (e.g., shadow-stack,direct-jumps).",
        )

        self.add_argument(
            "-d",
            "--dump-file",
            type=str,
            help="Path to the disassembled traced program, obtained with: " "objdump -d -z <binary>.",
        )

        self.add_argument(
            "-t",
            "--to-tessla",
            type=str,
            help="Output a TeSSLa file from the extracted execution trace (default, tessla.input).",
        )

        self.add_argument(
            "-o",
            "--output",
            type=str,
            help="Serialize execution trace and output to a json file.",
        )

    def parse(self, args: list[str]) -> argparse.Namespace:
        return self.parse_args(args)

    def check_dump_file(self, extension: str, dump_file: None | str) -> None:
        if extension == ".perf.report" and not dump_file:
            logger.info(
                "[-] To recover the complete execution trace, the dump file"
                " of the traced program should be passed using -d."
            )
            sys.exit(1)

    def get_parser_from_extension(self, extension: str) -> Parser:
        try:
            method_name: str = f"for{extension.replace(".", "_")}"
            parser: Parser = getattr(Parser, method_name)()
        except AttributeError:
            logger.exception(
                f"Parser not defined for extension '{extension}'" "(or not propagated in the 'Parser' class)"
            )
            sys.exit(1)
        return parser

    def deserialize_execution_trace(self, input_file: str) -> ExecutionTrace:
        execution_trace: ExecutionTrace = Serializer.load_execution_trace(json_file_name=input_file)
        return execution_trace

    def verify_trace(self, verifiers: list[str], trace: ExecutionTrace) -> None:
        # Run all verifications sequentially
        for verifier_name in verifiers:
            try:
                # Instanciate verifier
                verifier: Verifier = VERIFIERS[verifier_name]()
                # Launch verification
                if verifier.verify_trace(trace):
                    logger.info(f"[+] {verifier.message()}")
            except KeyError:
                logger.exception(f"Verifier '{verifier_name}' not defined.")
            except VerifierError as err:
                logger.info(f"[-] \tOriginal exception: {err}")

    def output_to_tessla_file(self, output_file: str, trace: ExecutionTrace) -> None:
        try:
            with (Path(DATA_TESSLA) / output_file).open(mode="w") as file:
                file.write(trace.to_tessla_trace())
        except OSError:
            logger.exception("[-] Failed to output TeSSLa trace.")
            raise


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    arg_parser: ArgParser = ArgParser()
    args: argparse.Namespace = arg_parser.parse(argv)

    if not argv:
        arg_parser.print_help()
        return 0

    logger.info("[+] Finding parser.")
    input_file_path: Path = Path(args.input_file)
    extension: str = "".join(input_file_path.suffixes)

    # Check for the dump file presence if needed
    arg_parser.check_dump_file(extension=extension, dump_file=args.dump_file)

    # Check if the input file is a serialized execution trace
    if extension == ".json":
        logger.info("[+] Deserializing json file.")
        execution_trace: ExecutionTrace = arg_parser.deserialize_execution_trace(input_file=args.input_file)
    else:
        # Get parser from extension
        parser: Parser = arg_parser.get_parser_from_extension(extension=extension)
        logger.info(f"[+] Parsing input file {args.input_file}.")
        execution_trace = parser.parse(file_name=args.input_file, dump_file_name=args.dump_file)

    # Apply verifications
    verifiers: list[str] = args.verifiers.split(",")
    arg_parser.verify_trace(verifiers=verifiers, trace=execution_trace)

    # Output trace to tessla file
    output_tessla_file: str = args.to_tessla
    if output_tessla_file:
        arg_parser.output_to_tessla_file(output_file=output_tessla_file, trace=execution_trace)

    return 0
