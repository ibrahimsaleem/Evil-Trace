import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class AuditLoggerAgent:
    """Records every agent step, tool call, prompt, and response."""

    def __init__(self, output_path: Path = Path("outputs/audit_log.jsonl")):
        self.output_path = output_path
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self._entries: List[Dict] = []
        self._run_ts = datetime.utcnow().isoformat()

    def log(
        self,
        agent: str,
        step: str,
        tool_call: str = "",
        prompt_summary: str = "",
        response_summary: str = "",
        tokens_used: int = 0,
        cost_estimate: float = 0.0,
        duration_ms: int = 0,
        provider: str = "",
        model: str = "",
        status: str = "success",
        error: str = "",
        action: str = "",
    ) -> Dict:
        p = provider or getattr(self, "provider", "")
        m = model or getattr(self, "model", "")
        act = action or step

        entry = {
            "run_timestamp": self._run_ts,
            "event_timestamp": datetime.utcnow().isoformat(),
            "agent": agent,
            "action": act,
            "step": step,
            "tool_call": tool_call,
            "prompt_summary": prompt_summary[:300] if prompt_summary else "",
            "input_summary": prompt_summary[:300] if prompt_summary else "",
            "response_summary": response_summary[:300] if response_summary else "",
            "output_summary": response_summary[:300] if response_summary else "",
            "tokens_used": tokens_used,
            "cost_estimate": cost_estimate,
            "duration_ms": duration_ms,
            "provider": p,
            "model": m,
            "status": status,
            "error": error,
        }
        self._entries.append(entry)
        with open(self.output_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return entry

    def timed_log(self, agent: str, step: str, **kwargs):
        """Context manager-style helper with timing."""
        return _TimedLog(self, agent, step, **kwargs)

    def get_entries(self) -> List[Dict]:
        return list(self._entries)

    def save_all(self):
        with open(self.output_path, "w", encoding="utf-8") as f:
            for e in self._entries:
                f.write(json.dumps(e) + "\n")


class _TimedLog:
    def __init__(self, logger: AuditLoggerAgent, agent: str, step: str, **kwargs):
        self.logger = logger
        self.agent = agent
        self.step = step
        self.kwargs = kwargs
        self._start = None

    def __enter__(self):
        self._start = time.monotonic()
        return self

    def __exit__(self, *args):
        ms = int((time.monotonic() - self._start) * 1000)
        self.logger.log(self.agent, self.step, duration_ms=ms, **self.kwargs)
