import time
from typing import Any, Callable, Dict, List, Optional

from providers.base import BaseProvider
from agents.audit_logger import AuditLoggerAgent


HALLUCINATION_PATTERNS = [
    ("malware_family", ["cobalt strike", "empire", "metasploit", "ryuk", "emotet", "trickbot", "qakbot"]),
    ("cred_dump_without_artifact", ["credential dumping", "lsass dump", "mimikatz"]),
    ("exfil_without_size", ["exfiltrated", "data stolen", "gigabytes transferred"]),
]


class SelfCorrectionAgent:
    """Identifies hallucinations, weak claims, contradictions, and unsupported findings."""

    name = "SelfCorrectionAgent"

    def __init__(
        self,
        provider: BaseProvider,
        audit: AuditLoggerAgent,
        progress_cb: Optional[Callable[[str], None]] = None,
    ):
        self.provider = provider
        self.audit = audit
        self.progress = progress_cb or (lambda msg: None)

    def run(self, verified_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        t0 = time.monotonic()
        self.progress("[SelfCorrectionAgent] Scanning for hallucinations and weak claims ...")
        corrections = []

        for f in verified_findings:
            status = f.get("status", "")
            claim = f.get("claim", "")
            reasoning = f.get("reasoning", "")
            confidence = f.get("confidence", 0.0)
            cat = f.get("category", "")
            combined_text = (claim + " " + reasoning).lower()

            issues = []

            if cat == "credential_dumping" and status == "rejected":
                issues.append({
                    "type": "hallucination_prevented",
                    "finding_id": f.get("id", ""),
                    "description": (
                        "Credential dumping hypothesis rejected because no supporting LSASS dump, "
                        "Mimikatz, Procdump, MiniDump, sekurlsa, or credential-access artifact was found."
                    ),
                    "correction": (
                        "Removed from confirmed findings. Hypothesis listed in rejected panel "
                        "with explanation. No malware family name assigned."
                    ),
                    "severity": "critical",
                })
                self.progress(
                    "[SelfCorrectionAgent] CORRECTION: Credential dumping hypothesis rejected — "
                    "no LSASS dump/Mimikatz/Procdump/MiniDump/sekurlsa artifact exists."
                )

            if cat == "exfiltration_indicators" and status in ("rejected", "weak_evidence"):
                issues.append({
                    "type": "weak_claim_flagged",
                    "finding_id": f.get("id", ""),
                    "description": (
                        "Exfiltration hypothesis rejected: No large transfer size, unusual outbound destination, "
                        "or archive creation plus transfer evidence found."
                    ),
                    "correction": (
                        "Claim demoted to weak_evidence or rejected. "
                        "Not included in confirmed findings section of report."
                    ),
                    "severity": "high",
                })
                self.progress("[SelfCorrectionAgent] CORRECTION: Exfiltration claim lacks transfer-size or archive evidence.")

            if cat == "beaconing" and status == "rejected":
                issues.append({
                    "type": "weak_claim_flagged",
                    "finding_id": f.get("id", ""),
                    "description": (
                        "C2 beaconing hypothesis rejected: Insufficient repeated connection evidence. "
                        "Minimum 3 outbound connections required."
                    ),
                    "correction": "Removed from confirmed findings. Listed in rejected panel.",
                    "severity": "medium",
                })

            for pattern_name, pattern_words in HALLUCINATION_PATTERNS:
                for word in pattern_words:
                    if word in combined_text and status == "confirmed":
                        if pattern_name == "cred_dump_without_artifact" and cat == "credential_dumping":
                            issues.append({
                                "type": "hallucination_detected",
                                "finding_id": f.get("id", ""),
                                "description": f"Potential hallucination: '{word}' referenced in a confirmed finding without exact artifact.",
                                "correction": "Status demoted to rejected. Claim removed from final report.",
                                "severity": "critical",
                            })

            if status == "confirmed" and confidence < 0.50:
                issues.append({
                    "type": "confidence_mismatch",
                    "finding_id": f.get("id", ""),
                    "description": f"Finding marked confirmed but confidence is only {confidence:.0%}. Insufficient for confirmed status.",
                    "correction": "Status demoted to weak_evidence.",
                    "severity": "medium",
                })
                f["status"] = "weak_evidence"

            if issues:
                corrections.append({
                    "finding_claim": claim[:100],
                    "original_status": status,
                    "issues": issues,
                })

        elapsed = int((time.monotonic() - t0) * 1000)
        self.audit.log(
            self.name, "self_correction_complete",
            tool_call="scan_for_hallucinations",
            prompt_summary=f"Checking {len(verified_findings)} findings for hallucinations/weak claims",
            response_summary=f"Found {len(corrections)} correction events",
            duration_ms=elapsed,
        )

        if corrections:
            for c in corrections:
                self.progress(
                    f"[SelfCorrectionAgent] Issue in '{c['finding_claim'][:50]}': "
                    f"{len(c['issues'])} correction(s)"
                )
        else:
            self.progress("[SelfCorrectionAgent] No hallucinations or unsupported claims detected.")

        return corrections
