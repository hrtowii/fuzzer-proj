import random
from typing import List

from .base import MutationStrategy


class BitFlipStrategy(MutationStrategy):
    """
    Bit flip mutation strategy that randomly flips bits in the input data.
    This is one of the most basic and effective fuzzing strategies.
    """

    def __init__(self, flip_probability: float = 0.01, max_bit_flips: int = None):
        """
        Initialize the bit flip strategy.

        Args:
            flip_probability: Probability of flipping each bit (0.0 to 1.0)
            max_bit_flips: Maximum number of bits to flip per mutation (None for no limit)
        """
        super().__init__("Bit Flip")
        self.flip_probability = flip_probability
        self.max_bit_flips = max_bit_flips

    def apply(self, data: bytes) -> bytes:
        """
        Apply bit flip mutations to the input data.

        Args:
            data: Original input data

        Returns:
            Data with random bits flipped
        """
        if not data:
            return data

        result = bytearray(data)
        bits_flipped = 0

        for byte_index in range(len(result)):
            for bit_index in range(8):
                if (self.max_bit_flips is None or bits_flipped < self.max_bit_flips) and \
                   random.random() < self.flip_probability:
                    # Flip the bit
                    result[byte_index] ^= (1 << bit_index)
                    bits_flipped += 1

        self._increment_mutation_count()
        return bytes(result)

    def get_description(self) -> str:
        """Get a description of the bit flip strategy."""
        return f"Randomly flips bits with probability {self.flip_probability}"

    def can_handle(self, data: bytes) -> bool:
        """Check if this strategy can handle the data."""
        return super().can_handle(data) and len(data) > 0

    def get_effectiveness_score(self) -> float:
        """Bit flipping is highly effective for finding memory corruption bugs."""
        return 0.8

    def get_complexity_score(self) -> float:
        """Bit flipping is computationally simple."""
        return 0.1


class SingleBitFlipStrategy(MutationStrategy):
    """
    Strategy that flips exactly one bit per mutation.
    This provides more systematic coverage than random bit flipping.
    """

    def __init__(self):
        """Initialize the single bit flip strategy."""
        super().__init__("Single Bit Flip")
        self.current_bit = 0

    def apply(self, data: bytes) -> bytes:
        """
        Apply single bit flip mutation.

        Args:
            data: Original input data

        Returns:
            Data with one bit flipped
        """
        if not data:
            return data

        total_bits = len(data) * 8
        if total_bits == 0:
            return data

        # Calculate which bit to flip
        bit_to_flip = self.current_bit % total_bits
        self.current_bit += 1

        byte_index = bit_to_flip // 8
        bit_index = bit_to_flip % 8

        result = bytearray(data)
        result[byte_index] ^= (1 << bit_index)

        self._increment_mutation_count()
        return bytes(result)

    def get_description(self) -> str:
        """Get a description of the single bit flip strategy."""
        return "Systematically flips one bit at a time for thorough coverage"

    def can_handle(self, data: bytes) -> bool:
        """Check if this strategy can handle the data."""
        return super().can_handle(data) and len(data) > 0

    def get_effectiveness_score(self) -> float:
        """Single bit flipping provides excellent systematic coverage."""
        return 0.9

    def get_complexity_score(self) -> float:
        """Still computationally simple."""
        return 0.1


class WalkingBitFlipStrategy(MutationStrategy):
    """
    Strategy that flips consecutive bits in a walking pattern.
    Useful for finding buffer boundaries and field limits.
    """

    def __init__(self, walk_length: int = 4):
        """
        Initialize the walking bit flip strategy.

        Args:
            walk_length: Number of consecutive bits to flip
        """
        super().__init__("Walking Bit Flip")
        self.walk_length = walk_length
        self.current_position = 0

    def apply(self, data: bytes) -> bytes:
        """
        Apply walking bit flip mutation.

        Args:
            data: Original input data

        Returns:
            Data with consecutive bits flipped
        """
        if not data:
            return data

        total_bits = len(data) * 8
        if total_bits == 0:
            return data

        result = bytearray(data)

        # Flip consecutive bits starting from current position
        for i in range(self.walk_length):
            bit_position = (self.current_position + i) % total_bits
            byte_index = bit_position // 8
            bit_index = bit_position % 8
            result[byte_index] ^= (1 << bit_index)

        # Advance position
        self.current_position += 1

        self._increment_mutation_count()
        return bytes(result)

    def get_description(self) -> str:
        """Get a description of the walking bit flip strategy."""
        return f"Flips {self.walk_length} consecutive bits in a walking pattern"

    def can_handle(self, data: bytes) -> bool:
        """Check if this strategy can handle the data."""
        return super().can_handle(data) and len(data) * 8 >= self.walk_length

    def get_effectiveness_score(self) -> float:
        """Good for finding buffer boundaries."""
        return 0.7

    def get_complexity_score(self) -> float:
        """Still simple computation."""
        return 0.2


class BoundaryBitFlipStrategy(MutationStrategy):
    """
    Strategy that focuses on flipping bits at boundaries and structure points.
    This targets areas like headers, length fields, and separators.
    """

    def __init__(self, boundary_positions: List[int] = None):
        """
        Initialize the boundary bit flip strategy.

        Args:
            boundary_positions: Specific byte positions to focus on (None for auto-detection)
        """
        super().__init__("Boundary Bit Flip")
        self.boundary_positions = boundary_positions

    def apply(self, data: bytes) -> bytes:
        """
        Apply boundary-focused bit flip mutations.

        Args:
            data: Original input data

        Returns:
            Data with boundary bits flipped
        """
        if not data:
            return data

        result = bytearray(data)

        # Determine boundary positions
        if self.boundary_positions is None:
            boundary_positions = self._detect_boundaries(data)
        else:
            boundary_positions = [pos for pos in self.boundary_positions if pos < len(data)]

        if not boundary_positions:
            # Fallback to first and last bytes
            boundary_positions = [0, len(data) - 1] if len(data) > 1 else [0]

        # Choose a random boundary position and flip a random bit
        byte_position = random.choice(boundary_positions)
        bit_position = random.randint(0, 7)
        result[byte_position] ^= (1 << bit_position)

        self._increment_mutation_count()
        return bytes(result)

    def _detect_boundaries(self, data: bytes) -> List[int]:
        """
        Detect likely boundary positions in the data.

        Args:
            data: Input data

        Returns:
            List of boundary byte positions
        """
        boundaries = []

        # Add common boundaries
        if len(data) > 0:
            boundaries.extend([0, len(data) - 1])

        # Look for null bytes (often string terminators)
        for i, byte in enumerate(data):
            if byte == 0:
                boundaries.extend([max(0, i - 1), i, min(len(data) - 1, i + 1)])

        # Look for common delimiter bytes
        delimiters = [ord(c) for c in ['\n', '\r', '\t', ',', ';', ':', '|', ' ']]
        for i, byte in enumerate(data):
            if byte in delimiters:
                boundaries.extend([max(0, i - 1), i, min(len(data) - 1, i + 1)])

        # Look for patterns that might indicate length fields
        if len(data) >= 4:
            for i in range(len(data) - 3):
                # Small values that might be lengths
                if data[i] < 32:  # Likely not printable ASCII, could be length
                    boundaries.append(i)

        # Remove duplicates and sort
        boundaries = list(set(boundaries))
        boundaries.sort()

        return boundaries

    def get_description(self) -> str:
        """Get a description of the boundary bit flip strategy."""
        return "Focuses on flipping bits at boundaries and structure points"

    def get_effectiveness_score(self) -> float:
        """Very effective for structured format parsing bugs."""
        return 0.85

    def get_complexity_score(self) -> float:
        """Slightly more complex due to boundary detection."""
        return 0.3