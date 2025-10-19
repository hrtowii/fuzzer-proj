"""
Mutation package for the fuzzer.

This package contains format-specific mutators for different input types.
"""

from .base import BaseMutator
from .csv_mutator import CSVMutator
from .json_mutator import JSONMutator
from .binary_mutator import BinaryMutator

__all__ = [
    'BaseMutator',
    'CSVMutator',
    'JSONMutator',
    'BinaryMutator',
]
