from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any


class MutationStrategy(ABC):
    """
    Abstract base class for mutation strategies.

    Mutation strategies define specific approaches to modifying input data
    to potentially trigger vulnerabilities in target binaries.
    """

    def __init__(self, name: str):
        """
        Initialize the mutation strategy.

        Args:
            name: Human-readable name for the strategy
        """
        self.name = name
        self.mutation_count = 0

    @abstractmethod
    def apply(self, data: bytes) -> bytes:
        """
        Apply the mutation strategy to input data.

        Args:
            data: Original input data

        Returns:
            Mutated input data
        """
        pass

    @abstractmethod
    def get_description(self) -> str:
        """
        Get a description of what this mutation strategy does.

        Returns:
            Human-readable description
        """
        pass

    def get_mutation_count(self) -> int:
        """Get the number of mutations performed by this strategy."""
        return self.mutation_count

    def reset(self) -> None:
        """Reset the mutation counter."""
        self.mutation_count = 0

    def _increment_mutation_count(self) -> None:
        """Increment the internal mutation counter."""
        self.mutation_count += 1

    def can_handle(self, data: bytes) -> bool:
        """
        Check if this strategy can handle the given data.

        Args:
            data: Input data to check

        Returns:
            True if the strategy can handle this data
        """
        return len(data) > 0

    def get_effectiveness_score(self) -> float:
        """
        Get an effectiveness score for this strategy (0.0 to 1.0).
        This can be used to prioritize more effective strategies.

        Returns:
            Effectiveness score
        """
        return 0.5  # Default moderate effectiveness

    def get_complexity_score(self) -> float:
        """
        Get a complexity score for this strategy (0.0 to 1.0).
        Higher complexity may mean slower mutations but potentially better results.

        Returns:
            Complexity score
        """
        return 0.5  # Default moderate complexity