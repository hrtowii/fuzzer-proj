from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
import random
import struct

from models import InputFormat


class BaseMutator(ABC):
    """
    Abstract base class for all mutators.
    Provides common functionality and interface for format-specific mutators.
    """

    def __init__(self, sample_data: bytes, input_format: InputFormat):
        """
        Initialize the mutator with sample data.

        Args:
            sample_data: Original sample input data
            input_format: Detected format of the input
        """
        self.original_data = sample_data
        self.current_data = sample_data
        self.input_format = input_format
        self.mutation_count = 0
        self.max_mutation_depth = 10
        self.random = random.Random()

    @abstractmethod
    def mutate(self) -> bytes:
        """
        Generate a mutated version of the input.

        Returns:
            Mutated input data
        """
        pass

    @abstractmethod
    def reset(self) -> None:
        """Reset the mutator to its original state."""
        pass

    @abstractmethod
    def _validate_structure(self, data: bytes) -> bool:
        """
        Validate that the data maintains the expected structure.

        Args:
            data: Data to validate

        Returns:
            True if data is valid for the format
        """
        pass

    def get_mutation_count(self) -> int:
        """Get the number of mutations performed so far."""
        return self.mutation_count

    def set_seed(self, seed: int) -> None:
        """Set the random seed for reproducible mutations."""
        self.random.seed(seed)

    def _bit_flip(self, data: bytes, probability: float = 0.01) -> bytes:
        """
        Flip random bits in the data.

        Args:
            data: Original data
            probability: Probability of flipping each bit

        Returns:
            Data with random bits flipped
        """
        if not data:
            return data

        result = bytearray(data)
        for i in range(len(result)):
            for bit in range(8):
                if self.random.random() < probability:
                    result[i] ^= 1 << bit

        return bytes(result)

    def _byte_substitution(self, data: bytes, probability: float = 0.01) -> bytes:
        """
        Substitute random bytes in the data.

        Args:
            data: Original data
            probability: Probability of substituting each byte

        Returns:
            Data with random bytes substituted
        """
        if not data:
            return data

        result = bytearray(data)
        for i in range(len(result)):
            if self.random.random() < probability:
                result[i] = self.random.randint(0, 255)

        return bytes(result)

    def _byte_insertion(self, data: bytes, max_insertions: int = 5) -> bytes:
        """
        Insert random bytes into the data.

        Args:
            data: Original data
            max_insertions: Maximum number of bytes to insert

        Returns:
            Data with random bytes inserted
        """
        if not data:
            return data

        result = bytearray(data)
        num_insertions = self.random.randint(1, max_insertions)

        for _ in range(num_insertions):
            position = self.random.randint(0, len(result))
            byte_value = self.random.randint(0, 255)
            result.insert(position, byte_value)

        return bytes(result)

    def _byte_deletion(self, data: bytes, max_deletions: int = 5) -> bytes:
        """
        Delete random bytes from the data.

        Args:
            data: Original data
            max_deletions: Maximum number of bytes to delete

        Returns:
            Data with random bytes deleted
        """
        if not data or len(data) <= 1:
            return data

        result = bytearray(data)
        num_deletions = min(self.random.randint(1, max_deletions), len(result) - 1)

        for _ in range(num_deletions):
            if len(result) > 1:
                position = self.random.randint(0, len(result) - 1)
                del result[position]

        return bytes(result)

    def _arithmetic_mutations(self, data: bytes) -> bytes:
        """
        Apply arithmetic mutations to numeric data.

        Args:
            data: Original data

        Returns:
            Data with arithmetic mutations applied
        """
        if len(data) < 4:
            return data

        result = bytearray(data)

        for i in range(0, len(result) - 3, 4):
            if self.random.random() < 0.1:  # 10% chance to mutate each integer
                try:
                    original = struct.unpack("<I", result[i : i + 4])[0]

                    operations = [
                        lambda x: x + 1,
                        lambda x: x - 1,
                        lambda x: x * 2,
                        lambda x: x // 2,
                        lambda x: x ^ 0xFFFFFFFF,
                        lambda x: 0,
                        lambda x: 0xFFFFFFFF,
                    ]

                    mutated = self.random.choice(operations)(original)
                    result[i : i + 4] = struct.pack("<I", mutated & 0xFFFFFFFF)
                except:
                    pass

        return bytes(result)

    def _known_interesting_values(self) -> List[bytes]:
        """
        Get a list of known interesting values for mutation.

        Returns:
            List of interesting byte sequences
        """
        return [
            b"",  # Empty input
            b"\x00",  # Null byte
            b"\x00" * 16,  # Multiple nulls
            b"\xff" * 16,  # All bits set
            b"\x7f" * 16,  # High bit set
            b"\x80" * 16,  # Sign bit set
            struct.pack("<I", 0),  # 32-bit zero
            struct.pack("<I", 1),  # 32-bit one
            struct.pack("<I", 0xFFFFFFFF),  # 32-bit max
            struct.pack("<i", -1),  # 32-bit -1
            struct.pack("<Q", 0),  # 64-bit zero
            struct.pack("<Q", 0xFFFFFFFFFFFFFFFF),  # 64-bit max
            b"A" * 16,  # Repeated character
            b"%n%n%n%n",  # Format string
            b"../../../../etc/passwd",  # Path traversal
            b"' OR '1'='1",  # SQL injection
            b"<script>alert('xss')</script>",  # XSS
            b"\x41\x41\x41\x41\x41\x41\x41\x41",  # Buffer overflow pattern
        ]

    def _replace_with_interesting_value(self, data: bytes) -> bytes:
        """
        Replace a portion of data with an interesting value.

        Args:
            data: Original data

        Returns:
            Data with interesting value substituted
        """
        if not data:
            return self.random.choice(self._known_interesting_values())

        interesting_values = self._known_interesting_values()
        replacement = self.random.choice(interesting_values)

        if len(data) <= len(replacement):
            return replacement

        start = self.random.randint(0, len(data) - len(replacement))
        result = bytearray(data)
        result[start : start + len(replacement)] = replacement

        return bytes(result)

    def _boundary_mutations(self, data: bytes) -> bytes:
        """
        Apply mutations at boundaries and structure points.

        Args:
            data: Original data

        Returns:
            Data with boundary mutations applied
        """
        if not data:
            return data

        mutations = []

        for truncation_point in [1, len(data) // 4, len(data) // 2, len(data) - 1]:
            if truncation_point < len(data):
                mutations.append(data[:truncation_point])

        if len(data) > 4:
            for repeat_count in [2, 4, 8]:
                portion = data[: len(data) // 4]
                mutations.append(portion * repeat_count)

        mutations.extend(
            [
                data + b"\x00",
                data + b"\xff",
                data + b"A" * 100,
                data + self.random.choice(self._known_interesting_values()),
            ]
        )

        return self.random.choice(mutations + [data])

    def generate_mutation_description(self) -> str:
        """
        Generate a human-readable description of the last mutation.

        Returns:
            Description of the mutation applied
        """
        return f"Mutation #{self.mutation_count} on {self.input_format.value} input"

    def _increment_mutation_count(self) -> None:
        """Increment the mutation counter."""
        self.mutation_count += 1

