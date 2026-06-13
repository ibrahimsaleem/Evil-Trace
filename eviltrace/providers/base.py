from abc import ABC, abstractmethod
from typing import Optional


class BaseProvider(ABC):
    """Abstract base class for all LLM providers."""

    name: str = "base"

    @abstractmethod
    def complete(self, prompt: str, max_tokens: int = 1024) -> str:
        """Send a prompt and return a completion string."""
        ...

    def is_available(self) -> bool:
        return True

    def estimate_cost(self, prompt: str, response: str) -> float:
        return 0.0

    def token_count(self, text: str) -> int:
        return len(text.split())
