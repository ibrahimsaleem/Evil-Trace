from .base import BaseProvider
from typing import Optional


class MockProvider(BaseProvider):
    """Deterministic mock provider — always works, no API key required."""

    name = "mock"

    RESPONSES = {
        "hypothesis": (
            "Based on the evidence, I identify the following potential incidents:\n"
            "1. Suspicious PowerShell execution with encoded commands\n"
            "2. Possible C2 beaconing to external IP\n"
            "3. Credential dumping attempt (requires verification of LSASS artifacts)\n"
            "4. Lateral movement via SMB admin shares\n"
            "5. Potential data exfiltration via outbound HTTP"
        ),
        "verify": (
            "Verification complete. Cross-referencing claims against evidence artifacts. "
            "Claims with direct artifact references are confirmed. "
            "Claims without supporting artifacts are rejected."
        ),
        "selfcorrect": (
            "Self-correction analysis complete. "
            "Reviewing all weak or rejected claims for hallucinations and unsupported assertions."
        ),
        "report": (
            "Executive Summary: Investigation identified multiple confirmed indicators of compromise. "
            "Suspicious PowerShell activity and beaconing confirmed. "
            "Credential dumping hypothesis rejected due to absence of LSASS/Mimikatz artifacts."
        ),
        "default": "Analysis complete. See structured findings for details.",
    }

    def complete(self, prompt: str, max_tokens: int = 1024) -> str:
        prompt_lower = prompt.lower()
        if "hypothesis" in prompt_lower or "incident" in prompt_lower:
            return self.RESPONSES["hypothesis"]
        if "verif" in prompt_lower or "confirm" in prompt_lower:
            return self.RESPONSES["verify"]
        if "self.correct" in prompt_lower or "hallucination" in prompt_lower or "correction" in prompt_lower:
            return self.RESPONSES["selfcorrect"]
        if "report" in prompt_lower or "executive" in prompt_lower or "summary" in prompt_lower:
            return self.RESPONSES["report"]
        return self.RESPONSES["default"]

    def estimate_cost(self, prompt: str, response: str) -> float:
        return 0.0

    def token_count(self, text: str) -> int:
        return len(text.split())
