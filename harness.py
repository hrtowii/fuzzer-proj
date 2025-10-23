import subprocess
import signal
import os
import time
import tempfile
from pathlib import Path
from typing import Optional, Tuple

from models import ExecutionResult, CrashInfo, CrashType


class Harness:
    """
    Execution harness for safely running target binaries and detecting crashes.
    """

    def __init__(self, binary_path: str, timeout: int = 5):
        """
        Initialize the execution harness.

        Args:
            binary_path: Path to the target binary
            timeout: Timeout in seconds for each execution
        """
        self.binary_path = Path(binary_path)
        self.timeout = timeout

        if not self.binary_path.exists():
            raise ValueError(f"Binary does not exist: {binary_path}")

        if not os.access(self.binary_path, os.X_OK):
            raise ValueError(f"Binary is not executable: {binary_path}")

    def execute(self, input_data: bytes) -> ExecutionResult:
        """
        Execute the binary with the given input data.

        Args:
            input_data: Input data to provide to the binary via stdin

        Returns:
            ExecutionResult with details about the execution
        """
        start_time = time.time()

        try:
            # Create temporary file for input if needed for debugging
            with tempfile.NamedTemporaryFile(delete=False) as temp_input:
                temp_input.write(input_data)
                temp_input_path = temp_input.name

            # Execute the binary
            process = subprocess.Popen(
                [str(self.binary_path)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,  # Create new process group
            )

            try:
                stdout, stderr = process.communicate(
                    input=input_data, timeout=self.timeout
                )
                # print(stdout)
                execution_time = time.time() - start_time
                return_code = process.returncode

                # Determine if this was a crash
                crash_info = self._analyze_crash(return_code, stderr, execution_time)

                return ExecutionResult(
                    return_code=return_code,
                    stdout=stdout,
                    stderr=stderr,
                    execution_time=execution_time,
                    crashed=crash_info is not None,
                    crash_type=crash_info.crash_type if crash_info else None,
                    signal=self._extract_signal_from_stderr(stderr),
                    fault_address=None,  # Would need additional tools to extract
                )

            except subprocess.TimeoutExpired:
                # Kill the entire process group
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                process.wait()
                execution_time = time.time() - start_time

                return ExecutionResult(
                    return_code=-1,
                    stdout=b"",
                    stderr=b"Timeout exceeded",
                    execution_time=execution_time,
                    crashed=False,
                    crash_type=None,
                    signal=None,
                    fault_address=None,
                )

        except Exception as e:
            execution_time = time.time() - start_time
            return ExecutionResult(
                return_code=-1,
                stdout=b"",
                stderr=str(e).encode(),
                execution_time=execution_time,
                crashed=False,
                crash_type=None,
                signal=None,
                fault_address=None,
            )

        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_input_path)
            except:
                pass

    def _analyze_crash(
        self, return_code: int, stderr: bytes, execution_time: float
    ) -> Optional[CrashInfo]:
        """
        Analyze execution results to determine if a crash occurred.

        Args:
            return_code: Process return code
            stderr: Standard error output
            execution_time: Time taken to execute

        Returns:
            CrashInfo if a crash is detected, None otherwise
        """
        # Check for obvious crash indicators
        if return_code < 0:
            # Killed by signal
            signal_num = abs(return_code)
            crash_type = self._signal_to_crash_type(signal_num)
            if crash_type:
                return CrashInfo(
                    signal=signal_num,
                    crash_type=crash_type,
                )

        # Check stderr for crash patterns
        stderr_str = stderr.decode("utf-8", errors="ignore").lower()

        crash_patterns = {
            "segmentation fault": CrashType.SEGFAULT,
            "segfault": CrashType.SEGFAULT,
            "abort": CrashType.ABORT,
            "assertion": CrashType.ABORT,
            "buffer overflow": CrashType.BUFFER_OVERFLOW,
            "stack overflow": CrashType.BUFFER_OVERFLOW,
            "heap overflow": CrashType.BUFFER_OVERFLOW,
            "use after free": CrashType.USE_AFTER_FREE,
            "double free": CrashType.DOUBLE_FREE,
            "invalid read": CrashType.INVALID_READ,
            "invalid write": CrashType.INVALID_WRITE,
        }

        for pattern, crash_type in crash_patterns.items():
            if pattern in stderr_str:
                return CrashInfo(
                    signal=0,
                    crash_type=crash_type,
                )

        # Check for common crash signals in output
        if any(
            signal_name in stderr_str
            for signal_name in ["sigsegv", "sigabrt", "sigbus", "sigfpe"]
        ):
            return CrashInfo(
                signal=0,
                crash_type=CrashType.UNKNOWN,
            )

        return None

    def _signal_to_crash_type(self, signal_num: int) -> Optional[CrashType]:
        """Convert signal number to crash type."""
        signal_map = {
            signal.SIGSEGV: CrashType.SEGFAULT,
            signal.SIGABRT: CrashType.ABORT,
            signal.SIGBUS: CrashType.INVALID_READ,  # Can be various memory errors
            signal.SIGFPE: CrashType.INVALID_READ,  # Floating point exception
        }

        return signal_map.get(signal_num)

    def _extract_signal_from_stderr(self, stderr: bytes) -> Optional[int]:
        """Try to extract signal number from stderr output."""
        stderr_str = stderr.decode("utf-8", errors="ignore")

        # Look for patterns like "terminated by signal SIGSEGV (11)"
        import re

        signal_match = re.search(r"signal \w+ \((\d+)\)", stderr_str)
        if signal_match:
            return int(signal_match.group(1))

        return None

    def check_binary_requirements(self) -> Tuple[bool, str]:
        """
        Check if the binary meets basic requirements for fuzzing.

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Check if binary exists and is executable
            if not self.binary_path.exists():
                return False, f"Binary does not exist: {self.binary_path}"

            if not os.access(self.binary_path, os.X_OK):
                return False, f"Binary is not executable: {self.binary_path}"

            # Try to run binary with empty input to see if it crashes immediately
            result = self.execute(b"")
            if result.crashed and result.crash_type == CrashType.SEGFAULT:
                return (
                    False,
                    "Binary crashes immediately with empty input - may not be suitable for fuzzing",
                )

            return True, "Binary appears suitable for fuzzing"

        except Exception as e:
            return False, f"Error checking binary: {e}"

    def dry_run(self, sample_input: bytes) -> Tuple[bool, str]:
        """
        Perform a dry run with the sample input to ensure it works normally.

        Args:
            sample_input: Sample input data

        Returns:
            Tuple of (success, message)
        """
        try:
            result = self.execute(sample_input)

            if result.crashed:
                return False, f"Sample input causes crash: {result.crash_type}"

            if result.return_code != 0:
                return (
                    False,
                    f"Sample input returns non-zero exit code: {result.return_code}",
                )

            if (
                result.execution_time > self.timeout * 0.8
            ):  # Use 80% of timeout as threshold
                return (
                    False,
                    f"Sample input takes too long to execute: {result.execution_time:.2f}s",
                )

            return True, "Dry run successful - binary processes sample input normally"

        except Exception as e:
            return False, f"Dry run failed: {e}"
