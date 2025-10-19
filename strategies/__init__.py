"""
Mutation strategies for the fuzzer.

This module provides various mutation strategies that can be applied to input data
to find vulnerabilities in target binaries.
"""

from .base import MutationStrategy
from .bit_flip import BitFlipStrategy
from .arithmetic import ArithmeticStrategy
from .value_replacement import ValueReplacementStrategy
from .structure_modification import StructureModificationStrategy
from .dictionary import DictionaryStrategy
from .interesting_values import InterestingValuesStrategy

__all__ = [
    'MutationStrategy',
    'BitFlipStrategy',
    'ArithmeticStrategy',
    'ValueReplacementStrategy',
    'StructureModificationStrategy',
    'DictionaryStrategy',
    'InterestingValuesStrategy',
]