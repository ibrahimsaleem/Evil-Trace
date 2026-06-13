import os
import requests
from .base import BaseProvider
from .mock import MockProvider


class OpenRouterProvider(BaseProvider):
    """OpenRouter provider."""

    name = "openrouter"

    def __init__(self, api_key: str = "", model: str = "openai/gpt-4o-mini"):
        self._api_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        self._model = model
        self._fallback = MockProvider()
        self._fallback_reason: str = ""

    def is_available(self) -> bool:
        return bool(self._api_key)

    def complete(self, prompt: str, max_tokens: int = 1024) -> str:
        if not self._api_key:
            self._fallback_reason = "No OpenRouter API key provided"
            return self._fallback.complete(prompt, max_tokens)
        try:
            resp = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "HTTP-Referer": "https://eviltrace.repl.co",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": max_tokens,
                },
                timeout=60,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            reason = str(e)
            if self._api_key in reason:
                reason = reason.replace(self._api_key, "***")
            self._fallback_reason = f"OpenRouter error: {reason}"
            return self._fallback.complete(prompt, max_tokens)

    def estimate_cost(self, prompt: str, response: str) -> float:
        tokens = (len(prompt.split()) + len(response.split())) * 1.3
        return round(tokens * 0.0000015, 6)
