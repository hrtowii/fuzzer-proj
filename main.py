#!/usr/bin/env python3
import argparse
import sys
import os
import signal
from pathlib import Path
from typing import List, Tuple

from fuzzer import Fuzzer
from models import FuzzerConfig, InputFormat


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simple fuzzer for 6447 - Black-box vulnerability discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fuzz a single binary
  %(prog)s --binary /path/to/target --input /path/to/sample.csv

  # Fuzz multiple binaries
  %(prog)s --binary-dir /path/to/binaries --input-dir /path/to/inputs

  # Custom configuration
  %(prog)s --binary target --input sample.json --mutations 5000 --timeout 10

  # Enable verbose output and save crashes
  %(prog)s --binary target --input sample.jpg --verbose --save-crashes ./crashes
        """,
    )

    binary_group = parser.add_mutually_exclusive_group(required=True)
    binary_group.add_argument(
        "--binary", "-b", type=str, help="Path to the target binary to fuzz"
    )
    binary_group.add_argument(
        "--binary-dir",
        "-B",
        type=str,
        help="Directory containing binaries to fuzz (all executables will be fuzzed)",
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--input", "-i", type=str, help="Path to sample input file for the binary"
    )
    input_group.add_argument(
        "--input-dir", "-I", type=str, help="Directory containing sample input files"
    )

    parser.add_argument(
        "--mutations",
        "-m",
        type=int,
        default=1000,
        help="Maximum number of mutations per binary (default: 1000)",
    )
    parser.add_argument(
        "--timeout",
        "-t",
        type=int,
        default=5,
        help="Timeout in seconds for each execution (default: 5)",
    )
    parser.add_argument(
        "--processes",
        "-p",
        type=int,
        default=1,
        help="Number of parallel processes (default: 1)",
    )
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=1024 * 1024,
        help="Maximum input file size in bytes (default: 1MB)",
    )

    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="./fuzzer_output",
        help="Output directory for results (default: ./fuzzer_output)",
    )
    parser.add_argument(
        "--save-crashes",
        type=str,
        metavar="DIR",
        help="Save crashing inputs to specified directory",
    )
    parser.add_argument(
        "--report", type=str, help="Save fuzzing report to specified file"
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress non-error output"
    )
    parser.add_argument(
        "--preserve-files",
        action="store_true",
        help="Preserve temporary files (for debugging)",
    )

    parser.add_argument(
        "--format",
        choices=[f.value for f in InputFormat],
        help="Force input format detection (auto-detected if not specified)",
    )

    return parser.parse_args()


def validate_arguments(args: argparse.Namespace) -> bool:
    """Validate command line arguments."""
    if args.binary and not os.path.isfile(args.binary):
        print(f"Error: Binary file not found: {args.binary}")
        return False

    if args.binary and not os.access(args.binary, os.X_OK):
        print(f"Error: Binary file is not executable: {args.binary}")
        return False

    if args.binary_dir and not os.path.isdir(args.binary_dir):
        print(f"Error: Binary directory not found: {args.binary_dir}")
        return False

    if args.input and not os.path.isfile(args.input):
        print(f"Error: Input file not found: {args.input}")
        return False

    if args.input_dir and not os.path.isdir(args.input_dir):
        print(f"Error: Input directory not found: {args.input_dir}")
        return False

    if args.mutations <= 0:
        print("Error: Number of mutations must be positive")
        return False

    if args.timeout <= 0:
        print("Error: Timeout must be positive")
        return False

    if args.processes <= 0:
        print("Error: Number of processes must be positive")
        return False

    if args.max_file_size <= 0:
        print("Error: Maximum file size must be positive")
        return False

    return True


def find_binaries(binary_dir: str) -> List[str]:
    """Find all executable files in the specified directory."""
    binaries = []
    binary_path = Path(binary_dir)

    for file_path in binary_path.iterdir():
        if file_path.is_file() and os.access(file_path, os.X_OK):
            if not any(
                skip in file_path.name.lower() for skip in [".so", ".dll", ".dylib"]
            ):
                binaries.append(str(file_path))

    return sorted(binaries)


def find_input_files(input_dir: str) -> List[str]:
    """Find all input files in the specified directory."""
    input_files = []
    input_path = Path(input_dir)

    for file_path in input_path.rglob("*"):
        if file_path.is_file():
            # Skip very large files
            if file_path.stat().st_size <= 10 * 1024 * 1024:  # 10MB limit
                input_files.append(str(file_path))

    return sorted(input_files)


def match_binaries_to_inputs(
    binaries: List[str], inputs: List[str]
) -> List[Tuple[str, str]]:
    """Match binaries with appropriate input files."""
    if not binaries or not inputs:
        return []

    matches = []

    for binary in binaries:
        for input_file in inputs:
            matches.append((binary, input_file))

    return matches


def setup_signal_handlers(fuzzer: Fuzzer):
    """Setup signal handlers for graceful shutdown."""

    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}. Shutting down gracefully...")
        fuzzer.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def main():
    """Main entry point."""
    args = parse_arguments()

    if not validate_arguments(args):
        sys.exit(1)

    verbose = args.verbose and not args.quiet
    quiet = args.quiet

    config = FuzzerConfig(
        max_mutations_per_file=args.mutations,
        timeout_per_execution=args.timeout,
        parallel_processes=args.processes,
        max_file_size=args.max_file_size,
        output_directory=args.output,
        verbose=verbose,
        preserve_working_files=args.preserve_files,
    )

    fuzzer = Fuzzer(config)
    setup_signal_handlers(fuzzer)

    try:
        if args.binary:
            if not args.input:
                print("Error: --input is required when using --binary")
                sys.exit(1)

            print(f"Starting fuzzer for binary: {args.binary}")
            print(f"Using input file: {args.input}")
            print(f"Configuration: {args.mutations} mutations, {args.timeout}s timeout")

            session = fuzzer.fuzz_binary(args.binary, args.input)
            sessions = {args.binary: session}

        else:
            binaries = find_binaries(args.binary_dir)
            inputs = find_input_files(args.input_dir)

            if not binaries:
                print(f"No executables found in {args.binary_dir}")
                sys.exit(1)

            if not inputs:
                print(f"No input files found in {args.input_dir}")
                sys.exit(1)

            print(f"Found {len(binaries)} binaries and {len(inputs)} input files")

            binary_input_pairs = match_binaries_to_inputs(binaries, inputs)
            print(f"Created {len(binary_input_pairs)} binary-input pairs to fuzz")

            sessions = fuzzer.fuzz_multiple_binaries(binary_input_pairs)

        if not quiet:
            report = fuzzer.generate_report(sessions)
            print("\n" + report)

            if args.report:
                try:
                    with open(args.report, "w") as f:
                        f.write(report)
                    print(f"Report saved to: {args.report}")
                except Exception as e:
                    print(f"Error saving report: {e}")

            if args.save_crashes:
                fuzzer.save_crashing_inputs(sessions, args.save_crashes)

        total_crashes = sum(
            session.stats.crashes_found for session in sessions.values()
        )
        if total_crashes > 0:
            print(f"\n🚨 Found {total_crashes} crashes! Vulnerabilities detected.")
            sys.exit(1)  # Exit with error code to indicate crashes found
        else:
            print(
                f"\n✅ No crashes found. Binaries appear robust against tested mutations."
            )
            sys.exit(0)

    except KeyboardInterrupt:
        print("\nFuzzing interrupted by user.")
        sys.exit(130)  # Standard exit code for SIGINT
    except Exception as e:
        print(f"Error during fuzzing: {e}")
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
