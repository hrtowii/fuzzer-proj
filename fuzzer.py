import os
import uuid
import time
import signal
from pathlib import Path
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import queue

from models import (
    InputFormat,
    FuzzerConfig,
    FuzzerSession,
    FuzzResult,
    ExecutionResult,
    MutationStats,
    CrashType,
)
from detector import InputDetector
from harness import Harness
from mutate.base import BaseMutator
from mutate.csv_mutator import CSVMutator
from mutate.json_mutator import JSONMutator
from mutate.binary_mutator import BinaryMutator
from strategies import (
    BitFlipStrategy,
    ArithmeticStrategy,
    ValueReplacementStrategy,
    StructureModificationStrategy,
    DictionaryStrategy,
    InterestingValuesStrategy,
)


class Fuzzer:
    """
    Main fuzzer orchestrator that coordinates all components.
    """

    def __init__(self, config: FuzzerConfig):
        """
        Initialize the fuzzer with configuration.

        Args:
            config: Fuzzer configuration
        """
        self.config = config
        self.session = None
        self.detector = InputDetector()
        self.strategy_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.crash_signatures = set()
        self.shutdown_event = threading.Event()

        self.strategies = [
            BitFlipStrategy(flip_probability=0.01),
            ArithmeticStrategy(),
            ValueReplacementStrategy(),
            StructureModificationStrategy(),
            DictionaryStrategy(),
            InterestingValuesStrategy(),
        ]

    def fuzz_binary(self, binary_path: str, sample_input_path: str) -> FuzzerSession:
        """
        Fuzz a single binary with a sample input.

        Args:
            binary_path: Path to the target binary
            sample_input_path: Path to the sample input file

        Returns:
            FuzzerSession with results
        """
        session_id = str(uuid.uuid4())
        self.session = FuzzerSession(
            session_id=session_id,
            binary_path=binary_path,
            sample_input_path=sample_input_path,
            detected_format=InputFormat.PLAINTEXT,  # Will be updated
            config=self.config,
        )

        try:
            if not self._setup_fuzzing(binary_path, sample_input_path):
                self.session.finish_session()
                return self.session

            self._execute_fuzzing()

        except Exception as e:
            print(f"Error during fuzzing: {e}")
        finally:
            self.session.finish_session()

        return self.session

    def _setup_fuzzing(self, binary_path: str, sample_input_path: str) -> bool:
        """
        Setup phase: detect format, validate binary, etc.

        Args:
            binary_path: Path to target binary
            sample_input_path: Path to sample input

        Returns:
            True if setup successful, False otherwise
        """
        print(f"[{self.session.session_id}] Starting setup phase...")

        if not os.path.exists(binary_path):
            print(f"Error: Binary does not exist: {binary_path}")
            return False

        if not os.path.exists(sample_input_path):
            print(f"Error: Sample input does not exist: {sample_input_path}")
            return False

        try:
            with open(sample_input_path, "rb") as f:
                sample_data = f.read()
        except Exception as e:
            print(f"Error reading sample input: {e}")
            return False

        try:
            detected_format = self.detector.detect_format(sample_input_path)
            self.session.detected_format = detected_format
            print(
                f"[{self.session.session_id}] Detected format: {detected_format.value}"
            )
        except Exception as e:
            print(f"Error detecting input format: {e}")
            return False

        if not self.detector.validate_format(sample_data, detected_format):
            print(f"Warning: Sample input may not be valid {detected_format.value}")

        try:
            harness = Harness(binary_path, self.config.timeout_per_execution)
            is_valid, message = harness.check_binary_requirements()
            if not is_valid:
                print(f"Warning: {message}")
            else:
                print(f"[{self.session.session_id}] Binary validation passed")

            # Perform dry run
            is_valid, message = harness.dry_run(sample_data)
            if not is_valid:
                print(f"Warning: Dry run failed: {message}")
            else:
                print(f"[{self.session.session_id}] Dry run successful")

        except Exception as e:
            print(f"Error validating binary: {e}")
            return False

        print(f"[{self.session.session_id}] Setup completed successfully")
        return True

    def _execute_fuzzing(self) -> None:
        """
        Execute the main fuzzing loop.
        """
        print(f"[{self.session.session_id}] Starting fuzzing phase...")

        with open(self.session.sample_input_path, "rb") as f:
            sample_data = f.read()

        mutator = self._create_mutator(sample_data, self.session.detected_format)

        harness = Harness(self.session.binary_path, self.config.timeout_per_execution)

        start_time = time.time()
        max_execution_time = 60  # 60 seconds per binary as per requirements

        mutation_count = 0
        crash_count = 0
        unique_crash_count = 0

        print(
            f"[{self.session.session_id}] Generating up to {self.config.max_mutations_per_file} mutations..."
        )

        while (
            mutation_count < self.config.max_mutations_per_file
            and not self.shutdown_event.is_set()
            and (time.time() - start_time) < max_execution_time
        ):
            try:
                mutated_data = mutator.mutate()
                mutation_count += 1
            except Exception as e:
                print(f"Error generating mutation {mutation_count}: {e}")
                continue

            try:
                execution_result = harness.execute(mutated_data)

                fuzz_result = FuzzResult(
                    input_data=mutated_data,
                    execution_result=execution_result,
                    mutation_description=mutator.generate_mutation_description(),
                    input_size=len(mutated_data),
                    is_crash=execution_result.crashed,
                    is_unique_crash=False,
                )

                if execution_result.crashed:
                    crash_count += 1
                    crash_signature = self._generate_crash_signature(execution_result)

                    if crash_signature not in self.crash_signatures:
                        self.crash_signatures.add(crash_signature)
                        unique_crash_count += 1
                        fuzz_result.is_unique_crash = True

                        print(f"[{self.session.session_id}] 🚨 UNIQUE CRASH FOUND!")
                        print(f"    Mutation: {fuzz_result.mutation_description}")
                        print(f"    Crash type: {execution_result.crash_type}")
                        print(f"    Return code: {execution_result.return_code}")
                        if self.config.verbose:
                            print(
                                f"    Stderr: {execution_result.stderr.decode('utf-8', errors='ignore')[:200]}"
                            )
                    else:
                        print(f"[{self.session.session_id}] 💥 Crash found (duplicate)")

                self.session.add_result(fuzz_result)

                if mutation_count % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = mutation_count / elapsed if elapsed > 0 else 0
                    print(
                        f"[{self.session.session_id}] Progress: {mutation_count} mutations, "
                        f"{crash_count} crashes, {unique_crash_count} unique, "
                        f"{rate:.1f} mutations/sec"
                    )

            except Exception as e:
                print(f"Error executing mutation {mutation_count}: {e}")
                continue

        # Final statistics
        elapsed = time.time() - start_time
        final_rate = mutation_count / elapsed if elapsed > 0 else 0

        print(f"[{self.session.session_id}] Fuzzing completed!")
        print(f"    Total mutations: {mutation_count}")
        print(f"    Total crashes: {crash_count}")
        print(f"    Unique crashes: {unique_crash_count}")
        print(f"    Execution time: {elapsed:.2f} seconds")
        print(f"    Average rate: {final_rate:.1f} mutations/sec")

    def _create_mutator(
        self, sample_data: bytes, input_format: InputFormat
    ) -> BaseMutator:
        """
        Create appropriate mutator for the detected input format.

        Args:
            sample_data: Sample input data
            input_format: Detected input format

        Returns:
            Appropriate mutator instance
        """
        if input_format == InputFormat.CSV:
            return CSVMutator(sample_data)
        elif input_format == InputFormat.JSON:
            return JSONMutator(sample_data)
        elif input_format in [InputFormat.JPEG, InputFormat.ELF, InputFormat.PDF]:
            return BinaryMutator(sample_data, input_format)
        else:
            # Default to binary mutator for other formats
            return BinaryMutator(sample_data, input_format)

    def _generate_crash_signature(self, execution_result: ExecutionResult) -> str:
        """
        Generate a unique signature for a crash to identify duplicates.

        Args:
            execution_result: Execution result containing crash information

        Returns:
            Crash signature string
        """
        if not execution_result.crashed:
            return "no_crash"

        # Create signature from crash type and signal
        signature_parts = []

        if execution_result.crash_type:
            signature_parts.append(execution_result.crash_type.value)

        if execution_result.signal:
            signature_parts.append(f"signal_{execution_result.signal}")

        # Add first few lines of stderr for additional uniqueness
        stderr_lines = execution_result.stderr.decode("utf-8", errors="ignore").split(
            "\n"
        )
        for line in stderr_lines[:3]:  # First 3 lines
            if line.strip():
                # Extract key information from the line
                if "segfault" in line.lower():
                    signature_parts.append("segfault")
                elif "abort" in line.lower():
                    signature_parts.append("abort")
                elif "assert" in line.lower():
                    signature_parts.append("assert")
                elif "buffer" in line.lower() and "overflow" in line.lower():
                    signature_parts.append("buffer_overflow")
                elif "stack" in line.lower():
                    signature_parts.append("stack_error")

        return "|".join(signature_parts) if signature_parts else "unknown_crash"

    def fuzz_multiple_binaries(
        self, binary_list: List[str]
    ) -> Dict[str, FuzzerSession]:
        """
        Fuzz multiple binaries.

        Args:
            binary_list: List of (binary_path, sample_input_path) tuples

        Returns:
            Dictionary mapping binary paths to their sessions
        """
        results = {}

        for i, (binary_path, sample_input_path) in enumerate(binary_list):
            print(f"\n{'=' * 60}")
            print(f"Fuzzing binary {i + 1}/{len(binary_list)}: {binary_path}")
            print(f"{'=' * 60}")

            try:
                session = self.fuzz_binary(binary_path, sample_input_path)
                results[binary_path] = session

                # Print summary for this binary
                print(f"\nSummary for {binary_path}:")
                print(f"  Mutations: {session.stats.total_mutations}")
                print(f"  Crashes: {session.stats.crashes_found}")
                print(f"  Unique crashes: {session.stats.unique_crashes}")
                print(f"  Execution time: {session.stats.execution_time_total:.2f}s")

            except Exception as e:
                print(f"Error fuzzing {binary_path}: {e}")
                continue

        return results

    def generate_report(self, sessions: Dict[str, FuzzerSession]) -> str:
        """
        Generate a comprehensive fuzzing report.

        Args:
            sessions: Dictionary of fuzzing sessions

        Returns:
            Report string
        """
        report = []
        report.append("=" * 80)
        report.append("FUZZING REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total binaries fuzzed: {len(sessions)}")
        report.append("")

        # Overall statistics
        total_mutations = sum(
            session.stats.total_mutations for session in sessions.values()
        )
        total_crashes = sum(
            session.stats.crashes_found for session in sessions.values()
        )
        total_unique_crashes = sum(
            session.stats.unique_crashes for session in sessions.values()
        )
        total_time = sum(
            session.stats.execution_time_total for session in sessions.values()
        )

        report.append("OVERALL STATISTICS:")
        report.append(f"  Total mutations: {total_mutations:,}")
        report.append(f"  Total crashes: {total_crashes:,}")
        report.append(f"  Total unique crashes: {total_unique_crashes:,}")
        report.append(f"  Total execution time: {total_time:.2f} seconds")
        report.append(
            f"  Average mutations/sec: {total_mutations / total_time:.1f}"
            if total_time > 0
            else "  Average mutations/sec: N/A"
        )
        report.append("")

        # Per-binary details
        for binary_path, session in sessions.items():
            report.append(f"BINARY: {binary_path}")
            report.append(f"  Format: {session.detected_format.value}")
            report.append(f"  Mutations: {session.stats.total_mutations:,}")
            report.append(f"  Crashes: {session.stats.crashes_found:,}")
            report.append(f"  Unique crashes: {session.stats.unique_crashes:,}")
            report.append(
                f"  Execution time: {session.stats.execution_time_total:.2f}s"
            )
            report.append(
                f"  Average mutation time: {session.stats.average_execution_time * 1000:.2f}ms"
            )

            # Show crash details if any
            if session.stats.unique_crashes > 0:
                report.append("  Crash details:")
                crash_results = [r for r in session.results if r.is_unique_crash]
                for i, crash in enumerate(crash_results[:5]):  # Show first 5 crashes
                    report.append(
                        f"    {i + 1}. {crash.execution_result.crash_type.value} - "
                        f"{crash.mutation_description}"
                    )

                if len(crash_results) > 5:
                    report.append(f"    ... and {len(crash_results) - 5} more crashes")

            report.append("")

        # Recommendations
        report.append("RECOMMENDATIONS:")
        if total_unique_crashes == 0:
            report.append(
                "  ✅ No crashes found - binaries appear robust against tested mutations"
            )
            report.append(
                "  💡 Consider increasing mutation count or trying different strategies"
            )
        else:
            report.append(
                f"  🚨 {total_unique_crashes} unique crashes found - immediate attention required"
            )
            report.append(
                "  📋 Prioritize fixing crashes by severity and reproducibility"
            )
            report.append("  🔧 Consider implementing additional input validation")

        report.append("")
        report.append("END OF REPORT")
        report.append("=" * 80)

        return "\n".join(report)

    def save_crashing_inputs(
        self, sessions: Dict[str, FuzzerSession], output_dir: str
    ) -> None:
        """
        Save inputs that caused crashes to files.

        Args:
            sessions: Dictionary of fuzzing sessions
            output_dir: Directory to save crashing inputs
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        for binary_path, session in sessions.items():
            binary_name = Path(binary_path).name
            binary_dir = output_path / binary_name
            binary_dir.mkdir(exist_ok=True)

            crash_results = [r for r in session.results if r.is_crash]
            print(f"Saving {len(crash_results)} crashing inputs for {binary_name}...")

            for i, crash in enumerate(crash_results):
                # Create filename with crash type and index
                crash_type = (
                    crash.execution_result.crash_type.value
                    if crash.execution_result.crash_type
                    else "unknown"
                )
                filename = f"crash_{i + 1:03d}_{crash_type}.bin"
                filepath = binary_dir / filename

                try:
                    with open(filepath, "wb") as f:
                        f.write(crash.input_data)

                    # Also save a metadata file
                    metadata_file = filepath.with_suffix(".meta")
                    with open(metadata_file, "w") as f:
                        f.write(f"Binary: {binary_path}\n")
                        f.write(f"Mutation: {crash.mutation_description}\n")
                        f.write(f"Crash type: {crash_type}\n")
                        f.write(f"Return code: {crash.execution_result.return_code}\n")
                        f.write(f"Signal: {crash.execution_result.signal}\n")
                        f.write(f"Unique: {crash.is_unique_crash}\n")
                        if crash.execution_result.stderr:
                            f.write(
                                f"Stderr: {crash.execution_result.stderr.decode('utf-8', errors='ignore')}\n"
                            )

                except Exception as e:
                    print(f"Error saving crash file {filepath}: {e}")

        print(f"Crashing inputs saved to: {output_path}")

    def shutdown(self) -> None:
        """Shutdown the fuzzer gracefully."""
        print("Shutting down fuzzer...")
        self.shutdown_event.set()

