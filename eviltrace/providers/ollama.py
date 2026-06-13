import requests
from .base import BaseProvider
from .mock import MockProvider


class OllamaProvider(BaseProvider):
    """Ollama local provider."""

    name = "ollama"

    def __init__(self, endpoint: str = "http://localhost:11434", model: str = "llama3"):
        self._endpoint = endpoint.rstrip("/")
        self._model = model
        self._fallback = MockProvider()
        self._fallback_reason: str = ""

    def is_available(self) -> bool:
        try:
            r = requests.get(f"{self._endpoint}/api/tags", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def complete(self, prompt: str, max_tokens: int = 1024) -> str:
        try:
            resp = requests.post(
                f"{self._endpoint}/api/generate",
                json={"model": self._model, "prompt": prompt, "stream": False, "options": {"num_predict": max_tokens}},
                timeout=120,
            )
            resp.raise_for_status()
            return resp.json().get("response", "")
        except Exception as e:
            self._fallback_reason = f"Ollama error: {e}"
            return self._fallback.complete(prompt, max_tokens)

    def estimate_cost(self, prompt: str, response: str) -> float:
        return 0.0
