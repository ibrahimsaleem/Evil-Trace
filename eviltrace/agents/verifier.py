import re
import time
from typing import Any, Callable, Dict, List, Optional

from providers.base import BaseProvider
from utils.scoring import status_from_confidence
from agents.audit_logger import AuditLoggerAgent


REJECTION_THRESHOLD = 0.25
CONFIRMATION_THRESHOLD = 0.50

# These require exact invocation of credential-dumping tools/methods — NOT just mentioning lsass
CRED_DUMP_EXACT = [
    "mimikatz", "sekurlsa", "lsadump", "procdump", "minidump", "comsvcs",
    "ntds.dit", "wce.exe", "hashdump", "invoke-mimikatz",
    "dump-lsass", "dumplsass", "lsass.dmp", "lsass.exe -",
    "rundll32.*comsvcs", "out-minidump",
]

EXFIL_EXACT = ["upload", "ftp put", "scp ", "rsync ", "curl.*post", "invoke-webrequest.*post", "curl.*-f", "curl.*--form"]

LATERAL_EXACT = [
    "psexec", "wmic", "winrm", "winrs", "net use", "admin$", "ipc$", "c$", "remote service",
    "rdp", "invoke-command", "psexesvc", "wmiexec"
]

POWERSHELL_EXACT = [
    "encodedcommand", "-enc ", "-e ", "frombase64", "iex", "invoke-expression", "bypass", "hidden",
    "downloadstring", "downloadfile", "invoke-webrequest", "iwr"
]

MALWARE_EXEC_EXACT = [
    ".exe", ".ps1", ".vbs", ".bat", "schtasks", "reg add", "runonce", "parent", "hash", "command line", "public\\", "cron", "crontab", "beacon.sh"
]


def _has_exact_artifact(claim_text: str, hits: List[Dict], required_keywords: List[str]) -> bool:
    combined = " ".join([
        (h.get("raw_record", "") or "") + " " + (h.get("command_line", "") or "") + " " + (h.get("process", "") or "")
        for h in hits
    ]).lower()
    return any(kw.lower() in combined for kw in required_keywords)


class VerificationAgent:
    """Confirms or rejects every hypothesis using exact evidence references."""

    name = "VerificationAgent"

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
        hypotheses: List[Dict[str, Any]],
        tool_results: Dict[str, List[Dict]],
    ) -> List[Dict[str, Any]]:
        t0 = time.monotonic()
        self.progress("[VerificationAgent] Verifying all hypotheses ...")

        verified = []
        for h in hypotheses:
            result = dict(h)
            cat = h.get("category", "")
            hits = tool_results.get(cat, [])
            confidence = h.get("confidence", 0.0)
            rule_hit = h.get("rule_hit", False)

            # Determine detection_source
            origin = h.get("origin", "rule")
            if origin == "rule+llm":
                detection_source = "both"
            elif origin == "llm":
                detection_source = "LLM"
            else:
                detection_source = "rules"

            result["detection_source"] = detection_source

            if cat == "credential_dumping":
                artifact_exact = _has_exact_artifact(h["claim"], hits, CRED_DUMP_EXACT)
                if not artifact_exact:
                    result["status"] = "rejected"
                    result["confidence"] = min(confidence, 0.10)
                    result["severity"] = "low"
                    result["reasoning"] = (
                        "Credential dumping hypothesis rejected because no supporting LSASS dump, Mimikatz, "
                        "Procdump, MiniDump, sekurlsa, or credential-access artifact was found."
                    )
                    self.progress(f"[VerificationAgent] {h['id']} REJECTED — no cred-dump artifact")
                else:
                    result["status"] = "confirmed"
                    result["confidence"] = max(confidence, 0.85)
                    result["reasoning"] = "Confirmed: Credential dumping tool/method found in evidence."

            elif cat == "exfiltration_indicators":
                has_large_transfer = any(r.get("_transfer_bytes", 0) > 100000 for r in hits)
                
                # Check for archive creation plus transfer evidence
                combined_cmd = " ".join([r.get("command_line", "") or "" for r in hits]).lower()
                has_archive = any(ext in combined_cmd for ext in [".zip", ".rar", ".7z", ".tar", ".gz", "compress-archive"])
                has_transfer_tool = any(tool in combined_cmd for tool in ["ftp", "scp", "rsync", "curl", "wget", "upload", "webrequest"])
                has_archive_and_transfer = has_archive and has_transfer_tool

                artifact_exact = _has_exact_artifact(h["claim"], hits, EXFIL_EXACT) or has_large_transfer or has_archive_and_transfer
                
                if not artifact_exact:
                    result["status"] = "rejected"
                    result["confidence"] = min(confidence, 0.10)
                    result["severity"] = "low"
                    result["reasoning"] = (
                        "Exfiltration hypothesis rejected: No large transfer size, unusual outbound destination, "
                        "or archive creation plus transfer evidence found."
                    )
                    self.progress(f"[VerificationAgent] {h['id']} REJECTED — insufficient exfil evidence")
                elif has_large_transfer or has_archive_and_transfer:
                    result["status"] = "confirmed"
                    result["confidence"] = max(confidence, 0.80)
                    result["reasoning"] = "Confirmed: Data exfiltration activity with transfer size or archive creation."
                else:
                    result["status"] = "weak_evidence"
                    result["confidence"] = max(confidence, 0.45)
                    result["reasoning"] = "Weak evidence: Exfiltration keyword found, but lacking large transfer size or archive creation."

            elif cat == "beaconing":
                if not hits:
                    result["status"] = "rejected"
                    result["confidence"] = min(confidence, 0.10)
                    result["severity"] = "low"
                    result["reasoning"] = "C2 beaconing hypothesis rejected: Insufficient repeated connection evidence. Minimum 3 outbound connections required."
                    self.progress(f"[VerificationAgent] {h['id']} REJECTED — no beacon pattern")
                else:
                    max_count = max(r.get("_beacon_count", 0) for r in hits)
                    if max_count >= 5:
                        result["status"] = "confirmed"
                        result["confidence"] = max(confidence, 0.80)
                        result["reasoning"] = f"Confirmed: C2 beaconing pattern detected with {max_count} repeated connections."
                    elif max_count >= 3:
                        result["status"] = "weak_evidence"
                        result["confidence"] = max(confidence, 0.45)
                        result["reasoning"] = f"Weak evidence: Potential C2 beaconing pattern with {max_count} repeated connections."
                    else:
                        result["status"] = "rejected"
                        result["confidence"] = min(confidence, 0.10)
                        result["severity"] = "low"
                        result["reasoning"] = "C2 beaconing hypothesis rejected: Insufficient repeated connection evidence. Minimum 3 outbound connections required."
                        self.progress(f"[VerificationAgent] {h['id']} REJECTED — beacon count {max_count} too low")

            elif cat == "suspicious_powershell":
                artifact_exact = _has_exact_artifact(h["claim"], hits, POWERSHELL_EXACT)
                if not artifact_exact or not hits:
                    result["status"] = "rejected"
                    result["confidence"] = min(confidence, 0.10)
                    result["severity"] = "low"
                    result["reasoning"] = "Suspicious PowerShell hypothesis rejected: No exact command evidence found."
                    self.progress(f"[VerificationAgent] {h['id']} REJECTED — no powershell command evidence")
                else:
                    result["status"] = "confirmed"
                    result["confidence"] = max(confidence, 0.80)
                    result["reasoning"] = "Confirmed: Suspicious PowerShell command matching encoded or execution patterns."

            elif cat == "lateral_movement":
                artifact_exact = _has_exact_artifact(h["claim"], hits, LATERAL_EXACT)
                if not artifact_exact or not hits:
                    result["status"] = "rejected"
                    result["confidence"] = min(confidence, 0.10)
                    result["severity"] = "low"
                    result["reasoning"] = "Lateral movement hypothesis rejected: No psexec, wmic, winrm, smb admin shares, remote service, or RDP brute force indicators found."
                    self.progress(f"[VerificationAgent] {h['id']} REJECTED — no lateral movement indicators")
                else:
                    result["status"] = "confirmed"
                    result["confidence"] = max(confidence, 0.80)
                    result["reasoning"] = "Confirmed: Lateral movement technique identified via remote services or admin tools."

            elif cat == "download_execution":
                has_hash = any(r.get("hash") for r in hits)
                has_susp_path = _has_exact_artifact(h["claim"], hits, MALWARE_EXEC_EXACT)
                has_parent_child = any(r.get("process") and r.get("command_line") for r in hits)
                
                artifact_exact = has_hash or has_susp_path or has_parent_child
                if not artifact_exact or not hits:
                    result["status"] = "rejected"
                    result["confidence"] = min(confidence, 0.10)
                    result["severity"] = "low"
                    result["reasoning"] = "Malware execution hypothesis rejected: No suspicious executable path, hash, parent-child chain, command line, or persistence artifact found."
                    self.progress(f"[VerificationAgent] {h['id']} REJECTED — no malware execution evidence")
                else:
                    result["status"] = "confirmed"
                    result["confidence"] = max(confidence, 0.80)
                    result["reasoning"] = "Confirmed: Malware execution detected via hash, path, chain, or persistence artifact."

            else:
                if not rule_hit or confidence < REJECTION_THRESHOLD:
                    result["status"] = "rejected"
                    result["reasoning"] = f"VERIFICATION FAILED: No supporting artifact found for '{cat}'."
                elif confidence >= CONFIRMATION_THRESHOLD and hits:
                    result["status"] = "confirmed"
                else:
                    result["status"] = "weak_evidence"

            prompt = (
                f"Verify this DFIR finding:\nClaim: {h['claim']}\n"
                f"Status determined by rules: {result['status']}\n"
                f"Artifact hits: {len(hits)}\n"
                f"Provide a one-sentence verification statement."
            )
            llm_verify = self.provider.complete(prompt, max_tokens=80)
            result["verification_note"] = llm_verify[:200]

            self.progress(
                f"[VerificationAgent] {h['id']}: {result['status']} "
                f"(confidence={result['confidence']:.2f})"
            )
            verified.append(result)

        elapsed = int((time.monotonic() - t0) * 1000)
        confirmed = sum(1 for v in verified if v["status"] == "confirmed")
        rejected = sum(1 for v in verified if v["status"] == "rejected")
        weak = sum(1 for v in verified if v["status"] == "weak_evidence")

        self.audit.log(
            self.name, "verification_complete",
            tool_call="verify_hypotheses",
            prompt_summary=f"Verifying {len(hypotheses)} hypotheses",
            response_summary=f"confirmed={confirmed}, weak={weak}, rejected={rejected}",
            duration_ms=elapsed,
        )
        return verified
