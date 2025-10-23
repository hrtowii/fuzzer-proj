import random
import struct
from typing import List, Union, Tuple

from .base import MutationStrategy


class ArithmeticStrategy(MutationStrategy):
    """
    Arithmetic mutation strategy that performs arithmetic operations on numeric values
    found in the input data. This is particularly effective for binary formats.
    """

    def __init__(self, operation_probabilities: dict = None):
        """
        Initialize the arithmetic strategy.

        Args:
            operation_probabilities: Dictionary mapping operations to probabilities
        """
        super().__init__("Arithmetic")

        # Default operation probabilities
        if operation_probabilities is None:
            operation_probabilities = {
                'add': 0.2,
                'subtract': 0.2,
                'multiply': 0.15,
                'divide': 0.15,
                'negate': 0.1,
                'zero': 0.1,
                'max': 0.05,
                'min': 0.05
            }

        self.operation_probabilities = operation_probabilities
        self.operations = list(operation_probabilities.keys())

    def apply(self, data: bytes) -> bytes:
        """
        Apply arithmetic mutations to numeric values in the data.

        Args:
            data: Original input data

        Returns:
            Data with arithmetic mutations applied
        """
        if not data or len(data) < 2:
            return data

        result = bytearray(data)

        # Find potential numeric values to mutate
        numeric_positions = self._find_numeric_values(data)

        if numeric_positions:
            # Choose a random numeric value to mutate
            pos, size, signed = random.choice(numeric_positions)
            self._apply_arithmetic_operation(result, pos, size, signed)

        self._increment_mutation_count()
        return bytes(result)

    def _find_numeric_values(self, data: bytes) -> List[Tuple[int, int, bool]]:
        """
        Find potential numeric values in the data.

        Args:
            data: Input data

        Returns:
            List of tuples (position, size, signed) for numeric values
        """
        numeric_values = []
        data_len = len(data)

        # Look for different integer sizes
        sizes = [1, 2, 4]  # Try 8-bit, 16-bit, and 32-bit values

        for size in sizes:
            if size <= data_len:
                for i in range(0, data_len - size + 1):
                    # Consider both signed and unsigned interpretations
                    numeric_values.append((i, size, False))  # unsigned
                    numeric_values.append((i, size, True))   # signed

        # Remove positions that would overlap and randomly sample
        if len(numeric_values) > 20:
            numeric_values = random.sample(numeric_values, 20)

        return numeric_values

    def _apply_arithmetic_operation(self, data: bytearray, pos: int, size: int, signed: bool) -> None:
        """
        Apply a random arithmetic operation to a numeric value.

        Args:
            data: Data array to modify
            pos: Position of the numeric value
            size: Size of the numeric value in bytes
            signed: Whether to interpret as signed or unsigned
        """
        # Extract the current value
        if size == 1:
            if signed:
                current = struct.unpack('<b', data[pos:pos+1])[0]
            else:
                current = struct.unpack('<B', data[pos:pos+1])[0]
        elif size == 2:
            if signed:
                current = struct.unpack('<h', data[pos:pos+2])[0]
            else:
                current = struct.unpack('<H', data[pos:pos+2])[0]
        elif size == 4:
            if signed:
                current = struct.unpack('<i', data[pos:pos+4])[0]
            else:
                current = struct.unpack('<I', data[pos:pos+4])[0]
        else:
            return  # Unsupported size

        # Choose an operation based on probabilities
        operation = random.choices(
            self.operations,
            weights=[self.operation_probabilities[op] for op in self.operations]
        )[0]

        # Apply the operation
        new_value = self._perform_operation(current, operation, signed)

        # Pack the new value back into the data
        if size == 1:
            if signed:
                data[pos:pos+1] = struct.pack('<b', new_value)
            else:
                data[pos:pos+1] = struct.pack('<B', new_value)
        elif size == 2:
            if signed:
                data[pos:pos+2] = struct.pack('<h', new_value)
            else:
                data[pos:pos+2] = struct.pack('<H', new_value)
        elif size == 4:
            if signed:
                data[pos:pos+4] = struct.pack('<i', new_value)
            else:
                data[pos:pos+4] = struct.pack('<I', new_value)

    def _perform_operation(self, value: int, operation: str, signed: bool) -> int:
        """
        Perform the specified arithmetic operation.

        Args:
            value: Current value
            operation: Operation to perform
            signed: Whether value is signed

        Returns:
            New value after operation
        """
        if operation == 'add':
            return value + random.choice([1, -1, 2, -2, 10, -10, 100, -100])
        elif operation == 'subtract':
            return value - random.choice([1, 2, 5, 10, 100])
        elif operation == 'multiply':
            multiplier = random.choice([2, 3, 5, 10, 100])
            return value * multiplier
        elif operation == 'divide':
            if value != 0:
                divisor = random.choice([2, 3, 5, 10])
                return value // divisor
            return value
        elif operation == 'negate':
            return -value
        elif operation == 'zero':
            return 0
        elif operation == 'max':
            if signed:
                return (2 ** (8 * 1)) // 2 - 1 if value < 256 else \
                       (2 ** (8 * 2)) // 2 - 1 if value < 65536 else \
                       (2 ** (8 * 4)) // 2 - 1
            else:
                return (2 ** (8 * 1)) - 1 if value < 256 else \
                       (2 ** (8 * 2)) - 1 if value < 65536 else \
                       (2 ** (8 * 4)) - 1
        elif operation == 'min':
            if signed:
                return -(2 ** (8 * 1)) // 2 if value < 256 else \
                       -(2 ** (8 * 2)) // 2 if value < 65536 else \
                       -(2 ** (8 * 4)) // 2
            else:
                return 0
        else:
            return value

    def get_description(self) -> str:
        """Get a description of the arithmetic strategy."""
        return "Applies arithmetic operations to numeric values in the input"

    def get_effectiveness_score(self) -> float:
        """Very effective for binary formats with numeric fields."""
        return 0.75

    def get_complexity_score(self) -> float:
        """Moderately complex due to value parsing."""
        return 0.4


class IntegerBoundaryStrategy(MutationStrategy):
    """
    Strategy that targets integer boundaries and overflow conditions.
    """

    def __init__(self):
        """Initialize the integer boundary strategy."""
        super().__init__("Integer Boundary")

        # Common boundary values for different integer sizes
        self.boundaries = {
            1: {  # 8-bit
                'signed_max': 127,
                'signed_min': -128,
                'unsigned_max': 255,
                'unsigned_min': 0,
            },
            2: {  # 16-bit
                'signed_max': 32767,
                'signed_min': -32768,
                'unsigned_max': 65535,
                'unsigned_min': 0,
            },
            4: {  # 32-bit
                'signed_max': 2147483647,
                'signed_min': -2147483648,
                'unsigned_max': 4294967295,
                'unsigned_min': 0,
            }
        }

    def apply(self, data: bytes) -> bytes:
        """
        Apply integer boundary mutations.

        Args:
            data: Original input data

        Returns:
            Data with boundary mutations applied
        """
        if not data or len(data) < 2:
            return data

        result = bytearray(data)

        # Find integer values to mutate
        positions = self._find_integers(data)
        if positions:
            pos, size, signed = random.choice(positions)
            self._apply_boundary_value(result, pos, size, signed)

        self._increment_mutation_count()
        return bytes(result)

    def _find_integers(self, data: bytes) -> List[Tuple[int, int, bool]]:
        """Find integer values in the data."""
        integers = []
        sizes = [1, 2, 4]

        for size in sizes:
            if size <= len(data):
                for i in range(0, len(data) - size + 1):
                    integers.append((i, size, False))  # unsigned
                    integers.append((i, size, True))   # signed

        # Sample to avoid too many positions
        if len(integers) > 15:
            integers = random.sample(integers, 15)

        return integers

    def _apply_boundary_value(self, data: bytearray, pos: int, size: int, signed: bool) -> None:
        """Apply a boundary value to an integer field."""
        bounds = self.boundaries.get(size, {})
        if not bounds:
            return

        if signed:
            boundary_values = [
                bounds['signed_max'],
                bounds['signed_min'],
                bounds['signed_max'] + 1,  # Overflow
                bounds['signed_min'] - 1,  # Underflow
                0, 1, -1  # Common edge cases
            ]
        else:
            boundary_values = [
                bounds['unsigned_max'],
                bounds['unsigned_min'],
                bounds['unsigned_max'] + 1,  # Overflow
                0, 1  # Common edge cases
            ]

        new_value = random.choice(boundary_values)

        # Pack the value
        if size == 1:
            if signed:
                data[pos:pos+1] = struct.pack('<b', new_value & 0xFF)
            else:
                data[pos:pos+1] = struct.pack('<B', new_value & 0xFF)
        elif size == 2:
            if signed:
                data[pos:pos+2] = struct.pack('<h', new_value & 0xFFFF)
            else:
                data[pos:pos+2] = struct.pack('<H', new_value & 0xFFFF)
        elif size == 4:
            if signed:
                data[pos:pos+4] = struct.pack('<i', new_value & 0xFFFFFFFF)
            else:
                data[pos:pos+4] = struct.pack('<I', new_value & 0xFFFFFFFF)

    def get_description(self) -> str:
        """Get a description of the integer boundary strategy."""
        return "Targets integer overflow and underflow conditions"

    def get_effectiveness_score(self) -> float:
        """Excellent for finding integer overflow vulnerabilities."""
        return 0.9

    def get_complexity_score(self) -> float:
        """Moderate complexity."""
        return 0.3


class FloatingPointStrategy(MutationStrategy):
    """
    Strategy that mutates floating-point values with special cases.
    """

    def __init__(self):
        """Initialize the floating point strategy."""
        super().__init__("Floating Point")

        # Special floating-point values
        self.special_values = [
            0.0, -0.0, 1.0, -1.0,
            float('inf'), float('-inf'), float('nan'),
            3.14159265359, 2.71828182846,  # Pi and e
            1e10, 1e-10, -1e10, -1e-10,  # Very large/small
            1.7976931348623157e+308,  # Max double
            -1.7976931348623157e+308,
            2.2250738585072014e-308,  # Min positive normal double
        ]

    def apply(self, data: bytes) -> bytes:
        """
        Apply floating-point mutations.

        Args:
            data: Original input data

        Returns:
            Data with floating-point mutations applied
        """
        if not data or len(data) < 4:
            return data

        result = bytearray(data)

        # Look for 32-bit and 64-bit floating-point patterns
        positions = []

        if len(data) >= 4:
            for i in range(0, len(data) - 3):
                positions.append((i, 4))  # 32-bit float

        if len(data) >= 8:
            for i in range(0, len(data) - 7):
                positions.append((i, 8))  # 64-bit double

        if positions:
            pos, size = random.choice(positions)
            self._apply_floating_value(result, pos, size)

        self._increment_mutation_count()
        return bytes(result)

    def _apply_floating_value(self, data: bytearray, pos: int, size: int) -> None:
        """Apply a special floating-point value."""
        new_value = random.choice(self.special_values)

        try:
            if size == 4:
                data[pos:pos+4] = struct.pack('<f', new_value)
            elif size == 8:
                data[pos:pos+8] = struct.pack('<d', new_value)
        except (struct.error, OverflowError):
            # Handle overflow gracefully
            if size == 4:
                data[pos:pos+4] = struct.pack('<f', 0.0)
            elif size == 8:
                data[pos:pos+8] = struct.pack('<d', 0.0)

    def get_description(self) -> str:
        """Get a description of the floating point strategy."""
        return "Mutates floating-point values with special cases"

    def get_effectiveness_score(self) -> float:
        """Good for numerical processing code."""
        return 0.6

    def get_complexity_score(self) -> float:
        """Low to moderate complexity."""
        return 0.2