import os
import requests
import re
from .base import BaseProvider
from .mock import MockProvider

try:
    import google.generativeai as genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False


class GeminiProvider(BaseProvider):
    """Google Gemini provider supporting official SDK and REST API fallback."""

    name = "gemini"

    def __init__(self, api_key: str = "", model: str = "gemini-2.5-flash"):
        self._api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self._model = model
        self._fallback = MockProvider()
        self._fallback_reason: str = ""
        
        if not HAS_GENAI:
            print("[Info] Official google-generativeai SDK is not installed. Falling back to REST API. Run 'pip install google-generativeai' to use the official SDK.")

    def is_available(self) -> bool:
        return bool(self._api_key)

    def _sanitize(self, text: str) -> str:
        if not self._api_key:
            return text
        text = text.replace(self._api_key, "***")
        text = re.sub(r"key=[A-Za-z0-9_\-]+", "key=***", text)
        return text

    def complete(self, prompt: str, max_tokens: int = 1024) -> str:
        if not self._api_key:
            self._fallback_reason = "No Gemini API key provided"
            return self._fallback.complete(prompt, max_tokens)

        if HAS_GENAI:
            try:
                genai.configure(api_key=self._api_key)
                model = genai.GenerativeModel(self._model)
                resp = model.generate_content(
                    prompt,
                    generation_config=genai.types.GenerationConfig(max_output_tokens=max_tokens)
                )
                if resp and resp.text:
                    return resp.text
                else:
                    raise ValueError("Empty response received from Gemini SDK")
            except Exception as e:
                reason = self._sanitize(str(e))
                print(f"[Warning] Gemini SDK failed ({reason}). Attempting REST API fallback.")

        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self._model}:generateContent?key=REDACTED"
        )
        real_url = url.replace("REDACTED", self._api_key)
        try:
            resp = requests.post(
                real_url,
                json={"contents": [{"parts": [{"text": prompt}]}]},
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            reason = self._sanitize(str(e))
            self._fallback_reason = f"Gemini API error: {reason}"
            return self._fallback.complete(prompt, max_tokens)

    def estimate_cost(self, prompt: str, response: str) -> float:
        tokens = (len(prompt.split()) + len(response.split())) * 1.3
        return round(tokens * 0.000001, 6)
