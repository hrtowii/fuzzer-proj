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


def execute_mutation_worker(
    binary_path: str,
    mutation_data: bytes,
    timeout_per_execution: int,
    mutation_description: str,
) -> Dict[str, Any]:
    """
    Worker function that executes a single mutation in a separate process.

    Args:
        binary_path: Path to the binary to execute
        mutation_data: The mutated input data
        timeout_per_execution: Timeout for each execution
        mutation_description: Description of the mutation

    Returns:
        Dictionary containing execution results
    """
    from harness import Harness

    try:
        # Debug: Print first 20 bytes of received mutation data (only for first few calls)
        if hasattr(execute_mutation_worker, "call_count"):
            execute_mutation_worker.call_count += 1
        else:
            execute_mutation_worker.call_count = 1

        if execute_mutation_worker.call_count <= 3:
            print(
                f"[DEBUG] Worker {execute_mutation_worker.call_count}: {mutation_data[:20]}... (len={len(mutation_data)})"
            )

        harness = Harness(binary_path, timeout_per_execution)
        execution_result = harness.execute(mutation_data)

        return {
            "success": True,
            "input_data": mutation_data,
            "execution_result": execution_result,
            "mutation_description": mutation_description,
            "input_size": len(mutation_data),
            "is_crash": execution_result.crashed,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "mutation_description": mutation_description,
            "input_size": len(mutation_data) if mutation_data else 0,
        }


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
        Execute the main fuzzing loop using ProcessPoolExecutor for parallel execution.
        """
        print(f"[{self.session.session_id}] Starting parallel fuzzing phase...")

        with open(self.session.sample_input_path, "rb") as f:
            sample_data = f.read()

        mutator = self._create_mutator(sample_data, self.session.detected_format)

        start_time = time.time()
        max_execution_time = 60  # 60 seconds per binary as per requirements

        mutation_count = 0
        crash_count = 0
        unique_crash_count = 0

        # Thread-safe counters and result collection
        mutation_counter = {"value": 0}
        crash_counter = {"value": 0}
        unique_crash_counter = {"value": 0}
        result_lock = threading.Lock()

        print(
            f"[{self.session.session_id}] Running parallel fuzzing for {max_execution_time} seconds..."
        )

        # Determine optimal number of worker threads for no-GIL Python 3.14
        # Use 2x CPU cores for maximum parallelism with no-GIL
        max_workers = min(
            self.config.parallel_threads, 16
        )  # Cap at 16 threads per binary for 8-core system

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            last_progress_time = start_time

            while (
                not self.shutdown_event.is_set()
                and (time.time() - start_time) < max_execution_time
                and unique_crash_count < 1
            ):
                # Generate mutations and submit to workers
                try:
                    # Submit larger mutation batches for no-GIL threading (more efficient than processes)
                    batch_size = (
                        max_workers * 4
                    )  # Larger batches for better thread utilization

                    for _ in range(batch_size):
                        if (time.time() - start_time) >= max_execution_time:
                            break

                        try:
                            mutated_data = mutator.mutate()
                            mutation_description = (
                                mutator.generate_mutation_description()
                            )

                            future = executor.submit(
                                execute_mutation_worker,
                                self.session.binary_path,
                                mutated_data,
                                self.config.timeout_per_execution,
                                mutation_description,
                            )
                            futures.append(future)

                        except Exception as e:
                            print(f"Error generating mutation: {e}")
                            continue

                    # Process completed futures
                    completed_futures = []
                    for future in futures:
                        if future.done():
                            completed_futures.append(future)

                    for future in completed_futures:
                        try:
                            result = future.result()

                            with result_lock:
                                mutation_counter["value"] += 1
                                mutation_count = mutation_counter["value"]

                            if result["success"]:
                                execution_result = result["execution_result"]

                                fuzz_result = FuzzResult(
                                    input_data=result["input_data"],
                                    execution_result=execution_result,
                                    mutation_description=result["mutation_description"],
                                    input_size=result["input_size"],
                                    is_crash=result["is_crash"],
                                    is_unique_crash=False,
                                )

                                if execution_result.crashed:
                                    with result_lock:
                                        crash_counter["value"] += 1
                                        crash_count = crash_counter["value"]

                                    crash_signature = self._generate_crash_signature(
                                        execution_result
                                    )

                                    if crash_signature not in self.crash_signatures:
                                        with result_lock:
                                            self.crash_signatures.add(crash_signature)
                                            unique_crash_counter["value"] += 1
                                            unique_crash_count = unique_crash_counter[
                                                "value"
                                            ]
                                            fuzz_result.is_unique_crash = True

                                        print(
                                            f"[{self.session.session_id}] 🚨 UNIQUE CRASH FOUND!"
                                        )
                                        print(
                                            f"    Mutation: {fuzz_result.mutation_description}"
                                        )
                                        print(
                                            f"    Crash type: {execution_result.crash_type}"
                                        )
                                        print(
                                            f"    Return code: {execution_result.return_code}"
                                        )
                                        print(
                                            f"[{self.session.session_id}] Stopping fuzzing after finding 1 unique crash"
                                        )
                                        break
                                    else:
                                        if (
                                            mutation_count % 10 == 0
                                        ):  # Reduce duplicate crash spam
                                            print(
                                                f"[{self.session.session_id}] 💥 Crash found (duplicate)"
                                            )

                                self.session.add_result(fuzz_result)
                            else:
                                print(
                                    f"Error in worker process: {result.get('error', 'Unknown error')}"
                                )

                        except Exception as e:
                            print(f"Error processing future result: {e}")

                    # Remove completed futures from list
                    futures = [f for f in futures if f not in completed_futures]

                    # Progress reporting every 5 seconds
                    current_time = time.time()
                    if current_time - last_progress_time >= 5.0:
                        elapsed = current_time - start_time
                        rate = mutation_count / elapsed if elapsed > 0 else 0
                        remaining = max_execution_time - elapsed
                        print(
                            f"[{self.session.session_id}] Progress: {mutation_count} mutations, "
                            f"{crash_count} crashes, {unique_crash_count} unique, "
                            f"{rate:.1f} mutations/sec, {remaining:.1f}s remaining"
                        )
                        last_progress_time = current_time

                    # No delay needed with threading - no-GIL architecture handles CPU-bound work efficiently

                except Exception as e:
                    print(f"Error in main fuzzing loop: {e}")
                    continue

            # Wait for any remaining futures to complete
            for future in futures:
                try:
                    result = future.result(
                        timeout=self.config.timeout_per_execution + 5
                    )

                    if result["success"]:
                        with result_lock:
                            mutation_counter["value"] += 1
                            mutation_count = mutation_counter["value"]

                        execution_result = result["execution_result"]

                        fuzz_result = FuzzResult(
                            input_data=result["input_data"],
                            execution_result=execution_result,
                            mutation_description=result["mutation_description"],
                            input_size=result["input_size"],
                            is_crash=result["is_crash"],
                            is_unique_crash=False,
                        )

                        if execution_result.crashed:
                            with result_lock:
                                crash_counter["value"] += 1
                                crash_count = crash_counter["value"]

                            crash_signature = self._generate_crash_signature(
                                execution_result
                            )

                            if crash_signature not in self.crash_signatures:
                                with result_lock:
                                    self.crash_signatures.add(crash_signature)
                                    unique_crash_counter["value"] += 1
                                    unique_crash_count = unique_crash_counter["value"]
                                    fuzz_result.is_unique_crash = True

                        self.session.add_result(fuzz_result)
                except Exception as e:
                    print(f"Error processing final future: {e}")

        # Final statistics
        elapsed = time.time() - start_time
        final_rate = mutation_count / elapsed if elapsed > 0 else 0

        print(f"[{self.session.session_id}] Parallel fuzzing completed!")
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

    def fuzz_single_binary(self, binary_input_pair: tuple) -> tuple:
        """
        Fuzz a single binary (used for parallel execution).

        Args:
            binary_input_pair: Tuple of (binary_path, sample_input_path)

        Returns:
            Tuple of (binary_path, session or error_message)
        """
        binary_path, sample_input_path = binary_input_pair

        try:
            session = self.fuzz_binary(binary_path, sample_input_path)
            return (binary_path, session, None)
        except Exception as e:
            return (binary_path, None, str(e))

    def fuzz_multiple_binaries(
        self, binary_list: List[str]
    ) -> Dict[str, FuzzerSession]:
        """
        Fuzz multiple binaries in parallel using ThreadPoolExecutor.

        Args:
            binary_list: List of (binary_path, sample_input_path) tuples

        Returns:
            Dictionary mapping binary paths to their sessions
        """
        print(f"\n{'=' * 80}")
        print(f"Starting parallel fuzzing of {len(binary_list)} binaries")
        print(f"{'=' * 80}")

        results = {}

        # Determine optimal number of parallel binaries for no-GIL Python 3.14
        # Use more concurrent binaries with threading (no process overhead)
        max_concurrent_binaries = min(
            len(binary_list), 8
        )  # Up to 8 binaries on 8-core system

        with ThreadPoolExecutor(max_workers=max_concurrent_binaries) as executor:
            # Submit all binary fuzzing tasks
            future_to_binary = {
                executor.submit(self.fuzz_single_binary, binary_pair): binary_pair
                for binary_pair in binary_list
            }

            # Process results as they complete
            completed_count = 0
            for future in as_completed(future_to_binary):
                binary_path, session, error = future.result()
                completed_count += 1

                print(f"\n{'=' * 60}")
                print(
                    f"Completed binary {completed_count}/{len(binary_list)}: {binary_path}"
                )
                print(f"{'=' * 60}")

                if session:
                    results[binary_path] = session

                    # Print summary for this binary
                    print(f"\nSummary for {binary_path}:")
                    print(f"  Mutations: {session.stats.total_mutations}")
                    print(f"  Crashes: {session.stats.crashes_found}")
                    print(f"  Unique crashes: {session.stats.unique_crashes}")
                    print(
                        f"  Execution time: {session.stats.execution_time_total:.2f}s"
                    )
                    print(
                        f"  Average mutation rate: {session.stats.mutations_per_second:.1f} mutations/sec"
                    )
                else:
                    print(f"Error fuzzing {binary_path}: {error}")

        print(f"\n{'=' * 80}")
        print(f"All binaries fuzzed in parallel!")
        print(f"Successfully fuzzed: {len(results)}/{len(binary_list)} binaries")
        print(f"{'=' * 80}")

        return results

    def save_crashing_inputs(
        self, sessions: Dict[str, FuzzerSession], output_dir: str
    ) -> None:
        """
        Save inputs that caused crashes to files.

        Args:
            sessions: Dictionary of fuzzing sessions
            output_dir: Directory to save crashing inputs
        """
        # Create fuzzeroutput directory
        fuzzeroutput_path = Path("fuzzeroutput")
        fuzzeroutput_path.mkdir(parents=True, exist_ok=True)

        for binary_path, session in sessions.items():
            binary_name = Path(
                binary_path
            ).stem  # Get just the filename without extension
            crash_results = [r for r in session.results if r.is_crash]
            unique_crash_results = [r for r in crash_results if r.is_unique_crash]

            # Only save unique crashes to avoid duplicates
            crashes_to_save = (
                unique_crash_results if unique_crash_results else crash_results
            )
            print(f"Saving {len(crashes_to_save)} crashing inputs for {binary_name}...")

            for i, crash in enumerate(crashes_to_save):
                # Create filename as bad{binary_name}.txt or bad{binary_name}_001.txt for multiple crashes
                if len(crashes_to_save) == 1:
                    filename = f"bad{binary_name}.txt"
                else:
                    filename = f"bad{binary_name}_{i + 1:03d}.txt"
                filepath = fuzzeroutput_path / filename

                try:
                    # Debug: Print first 20 bytes of crash data being saved
                    print(
                        f"[DEBUG] Saving crash {i + 1}: {crash.input_data[:20]}... (len={len(crash.input_data)})"
                    )

                    # Write crash input data as text (not binary)
                    with open(filepath, "wb") as f:
                        f.write(crash.input_data)

                except Exception as e:
                    print(f"Error saving crash file {filepath}: {e}")

        print(f"Crashing inputs saved to: {fuzzeroutput_path}")

    def shutdown(self) -> None:
        """Shutdown the fuzzer gracefully."""
        print("Shutting down fuzzer...")
        self.shutdown_event.set()
