import time
from typing import Any, Callable, Dict, List, Optional

from providers.base import BaseProvider
from utils.mitre_mapper import map_to_mitre
from utils.scoring import compute_confidence, severity_from_confidence
from agents.audit_logger import AuditLoggerAgent


RULE_HYPOTHESES = [
    {
        "id": "H001",
        "claim": "Suspicious PowerShell execution with encoded or obfuscated commands detected",
        "category": "suspicious_powershell",
        "requires_keywords": ["encodedcommand", "-enc", "frombase64", "iex", "invoke-expression"],
        "mitre_tactic": "Execution",
        "mitre_technique": "PowerShell",
        "mitre_technique_id": "T1059.001",
    },
    {
        "id": "H002",
        "claim": "Malicious file download and execution via web transfer tools (curl/wget/IWR)",
        "category": "download_execution",
        "requires_keywords": ["curl", "wget", "invoke-webrequest", "downloadfile", "downloadstring"],
        "mitre_tactic": "Command and Control",
        "mitre_technique": "Ingress Tool Transfer",
        "mitre_technique_id": "T1105",
    },
    {
        "id": "H003",
        "claim": "Credential dumping attempt via LSASS memory access or Mimikatz-family tooling",
        "category": "credential_dumping",
        "requires_keywords": ["mimikatz", "lsass", "procdump", "sekurlsa", "minidump", "comsvcs", "ntds"],
        "mitre_tactic": "Credential Access",
        "mitre_technique": "OS Credential Dumping: LSASS Memory",
        "mitre_technique_id": "T1003.001",
    },
    {
        "id": "H004",
        "claim": "Lateral movement via SMB admin shares, PSExec, WMIC, or WinRM",
        "category": "lateral_movement",
        "requires_keywords": ["psexec", "wmic", "winrm", "winrs", "net use", "admin$"],
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "Remote Services",
        "mitre_technique_id": "T1021",
    },
    {
        "id": "H005",
        "claim": "C2 beaconing detected — repeated outbound connections to external IP",
        "category": "beaconing",
        "requires_keywords": ["repeated connection"],
        "mitre_tactic": "Command and Control",
        "mitre_technique": "Application Layer Protocol",
        "mitre_technique_id": "T1071",
    },
    {
        "id": "H006",
        "claim": "Possible data exfiltration via large outbound transfer or upload tools",
        "category": "exfiltration_indicators",
        "requires_keywords": ["upload", "ftp", "scp", "large transfer", "curl -x post"],
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "Exfiltration Over C2 Channel",
        "mitre_technique_id": "T1041",
    },
]


class HypothesisAgent:
    """Proposes hypotheses based on rule hits and optional LLM augmentation."""

    name = "HypothesisAgent"

    def __init__(
        self,
        provider: BaseProvider,
        audit: AuditLoggerAgent,
        progress_cb: Optional[Callable[[str], None]] = None,
    ):
        self.provider = provider
        self.audit = audit
        self.progress = progress_cb or (lambda msg: None)

    def run(
        self,
        records: List[Dict[str, Any]],
        tool_results: Dict[str, List[Dict]],
    ) -> List[Dict[str, Any]]:
        t0 = time.monotonic()
        self.progress("[HypothesisAgent] Generating hypotheses ...")

        hypotheses = []
        for h in RULE_HYPOTHESES:
            cat = h["category"]
            hits = tool_results.get(cat, [])
            rule_hit = len(hits) > 0

            artifact_count = len(hits)
            artifact_exact = any(
                any(kw.lower() in (r.get("raw_record", "") or "").lower()
                    for kw in h["requires_keywords"])
                for r in hits
            ) if hits else False

            llm_hit = False
            llm_response = ""
            if rule_hit:
                prompt = (
                    f"You are a DFIR analyst. A detection rule fired for category: {cat}.\n"
                    f"Hypothesis: {h['claim']}\n"
                    f"Number of matching records: {artifact_count}\n"
                    f"Based on this, do you consider this a plausible hypothesis? "
                    f"Respond with one sentence assessing plausibility."
                )
                llm_response = self.provider.complete(prompt, max_tokens=100)
                llm_hit = "plausible" in llm_response.lower() or "likely" in llm_response.lower() or "suspect" in llm_response.lower()

            confidence = compute_confidence(rule_hit, llm_hit, artifact_count, artifact_exact)
            severity = severity_from_confidence(confidence)
            origin = "rule+llm" if (rule_hit and llm_hit) else ("rule" if rule_hit else "llm")

            sample_hit = hits[0] if hits else {}
            hyp = {
                "id": h["id"],
                "claim": h["claim"],
                "category": cat,
                "status": "proposed",
                "severity": severity,
                "confidence": confidence,
                "mitre_tactic": h["mitre_tactic"],
                "mitre_technique": h["mitre_technique"],
                "mitre_technique_id": h["mitre_technique_id"],
                "source_file": sample_hit.get("source_file", ""),
                "line_number": sample_hit.get("line_number", 0),
                "timestamp": sample_hit.get("timestamp", ""),
                "supporting_artifact": sample_hit.get("raw_record", "")[:200] if sample_hit else "",
                "reasoning": llm_response[:300] if llm_response else f"Rule-based: {artifact_count} artifact(s) matched.",
                "origin": origin,
                "artifact_hits": hits[:5],
                "rule_hit": rule_hit,
                "llm_hit": llm_hit,
            }
            hypotheses.append(hyp)
            self.progress(f"[HypothesisAgent] {h['id']}: {h['claim'][:60]}... confidence={confidence}")

        elapsed = int((time.monotonic() - t0) * 1000)
        self.audit.log(
            self.name, "hypotheses_generated",
            tool_call="generate_hypotheses",
            prompt_summary=f"Generated {len(hypotheses)} hypotheses from {len(RULE_HYPOTHESES)} rule templates",
            response_summary=", ".join(f"{h['id']}={h['confidence']}" for h in hypotheses),
            duration_ms=elapsed,
        )
        return hypotheses
