from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class InputFormat(str, Enum):
    """Supported input formats for the fuzzer."""
    PLAINTEXT = "plaintext"
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    JPEG = "jpeg"
    ELF = "elf"
    PDF = "pdf"


class CrashType(str, Enum):
    """Types of crashes that can be detected."""
    SEGFAULT = "segfault"
    ABORT = "abort"
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    INVALID_READ = "invalid_read"
    INVALID_WRITE = "invalid_write"
    UNKNOWN = "unknown"


class ExecutionResult(BaseModel):
    """Result of executing a binary with given input."""
    return_code: int
    stdout: bytes
    stderr: bytes
    execution_time: float
    crashed: bool = False
    crash_type: Optional[CrashType] = None
    signal: Optional[int] = None
    fault_address: Optional[int] = None


class FuzzResult(BaseModel):
    """Result of a single fuzzing attempt."""
    input_data: bytes
    execution_result: ExecutionResult
    mutation_description: str
    timestamp: datetime = Field(default_factory=datetime.now)
    input_size: int = Field(description="Size of the input in bytes")
    is_crash: bool = Field(default=False, description="Whether this input caused a crash")
    is_unique_crash: bool = Field(default=False, description="Whether this is a unique crash")


class CrashInfo(BaseModel):
    """Detailed information about a crash."""
    signal: int
    crash_type: CrashType
    backtrace: List[str] = Field(default_factory=list)
    fault_address: Optional[int] = None
    registers: Dict[str, int] = Field(default_factory=dict)
    memory_map: Optional[str] = None


class FuzzerConfig(BaseModel):
    """Configuration for the fuzzer."""
    max_mutations_per_file: int = Field(default=1000, ge=1)
    timeout_per_execution: int = Field(default=5, ge=1)
    parallel_threads: int = Field(default=16, ge=1)
    enable_coverage: bool = Field(default=False)
    max_file_size: int = Field(default=1024 * 1024, ge=1)  # 1MB default
    min_file_size: int = Field(default=0, ge=0)
    preserve_working_files: bool = Field(default=False)
    output_directory: str = Field(default="./fuzzer_output")
    sequential_binary_fuzzing: bool = Field(default=False, description="Whether to fuzz binaries sequentially (True) or in parallel (False)")
    parallel_batch_size: int = Field(default=2, description="Number of binaries to run in parallel in batch mode")


class MutationStats(BaseModel):
    """Statistics for mutation operations."""
    total_mutations: int = 0
    successful_mutations: int = 0
    crashes_found: int = 0
    unique_crashes: int = 0
    execution_time_total: float = 0.0
    individual_execution_time_total: float = 0.0  # Sum of individual execution times
    average_execution_time: float = 0.0
    mutations_per_second: float = 0.0


class FuzzerSession(BaseModel):
    """A complete fuzzing session."""
    session_id: str
    binary_path: str
    sample_input_path: str
    detected_format: InputFormat
    config: FuzzerConfig
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    results: List[FuzzResult] = Field(default_factory=list)
    stats: MutationStats = Field(default_factory=MutationStats)

    def add_result(self, result: FuzzResult) -> None:
        """Add a fuzz result to the session."""
        self.results.append(result)
        self.stats.total_mutations += 1

        if result.execution_result.crashed:
            self.stats.crashes_found += 1
            if result.is_unique_crash:
                self.stats.unique_crashes += 1

        # Track individual execution times for calculating average execution time
        self.stats.individual_execution_time_total += result.execution_result.execution_time
        if self.stats.total_mutations > 0:
            self.stats.average_execution_time = (
                self.stats.individual_execution_time_total / self.stats.total_mutations
            )

    def finish_session(self) -> None:
        """Mark the session as finished."""
        self.end_time = datetime.now()

        # Calculate total wall-clock time for the session
        if self.end_time and self.start_time:
            total_session_time = (self.end_time - self.start_time).total_seconds()
        else:
            total_session_time = 0.0

        # Update execution_time_total to be the wall-clock time, not sum of individual execution times
        self.stats.execution_time_total = total_session_time

        # Calculate mutations per second using wall-clock time
        if total_session_time > 0:
            self.stats.mutations_per_second = (
                self.stats.total_mutations / total_session_time
            )