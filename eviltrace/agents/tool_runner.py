import re
import time
from collections import Counter
from typing import Any, Callable, Dict, List, Optional

from utils.mitre_mapper import map_to_mitre
from agents.audit_logger import AuditLoggerAgent


SUSPICIOUS_PS_KEYWORDS = [
    "encodedcommand", "-enc ", "frombase64string", "downloadstring", "downloadfile",
    "invoke-expression", "iex", "invoke-webrequest", "iwr", "bypass", "hidden",
    "amsi", "reflection.assembly", "memorystream", "compress", "shellcode",
]

CRED_DUMP_KEYWORDS = [
    "mimikatz", "sekurlsa", "lsadump", "procdump", "minidump", "comsvcs",
    "lsass", "ntds.dit", "sam dump", "hashdump", "wce.exe",
]

LATERAL_KEYWORDS = [
    "psexec", "psexesvc", "wmiexec", "wmic", "winrm", "winrs",
    "invoke-command", "net use", "admin$", "ipc$", "c$",
]

DOWNLOAD_EXEC_KEYWORDS = [
    "curl ", "wget ", "invoke-webrequest", "iwr ", "downloadfile", "downloadstring",
    "bitsadmin", "certutil -urlcache", "start-bitstransfer",
]

EXFIL_INDICATORS = [
    "upload", "invoke-webrequest -method post", "curl -x post",
    "ftp put", "scp ", "rsync ", "robocopy", "xcopy /s",
]


def _search_records(records: List[Dict], keywords: List[str]) -> List[Dict]:
    hits = []
    for r in records:
        combined = " ".join([
            r.get("command_line", "") or "",
            r.get("raw_record", "") or "",
            r.get("process", "") or "",
            r.get("file_path", "") or "",
        ]).lower()
        for kw in keywords:
            if kw.lower() in combined:
                hits.append({**r, "_matched_keyword": kw})
                break
    return hits


def _detect_beaconing(records: List[Dict]) -> List[Dict]:
    ip_times: Dict[str, List[str]] = {}
    for r in records:
        dst = r.get("dst_ip", "")
        ts = r.get("timestamp", "")
        if dst and ts and not _is_private_ip(dst):
            ip_times.setdefault(dst, []).append(ts)
    beacons = []
    for ip, times in ip_times.items():
        if len(times) >= 3:
            sample = [r for r in records if r.get("dst_ip") == ip]
            if sample:
                beacons.append({
                    **sample[0],
                    "_beacon_ip": ip,
                    "_beacon_count": len(times),
                    "_matched_keyword": f"repeated connection x{len(times)}",
                })
    return beacons


def _is_private_ip(ip: str) -> bool:
    return bool(re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.|255\.)", ip or ""))


def _detect_large_outbound(records: List[Dict]) -> List[Dict]:
    hits = []
    for r in records:
        raw = r.get("raw_record", "") or ""
        m = re.search(r"\b(\d{6,})\b", raw)
        if m:
            size = int(m.group(1))
            if size > 100000:
                hits.append({**r, "_transfer_bytes": size, "_matched_keyword": f"large transfer {size}B"})
    return hits


class ToolRunnerAgent:
    """Runs local deterministic analysis functions against evidence records."""

    name = "ToolRunnerAgent"

    def __init__(
        self,
        audit: AuditLoggerAgent,
        progress_cb: Optional[Callable[[str], None]] = None,
    ):
        self.audit = audit
        self.progress = progress_cb or (lambda msg: None)

    def run(self, records: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        t0 = time.monotonic()
        self.progress("[ToolRunner] Running detection rules ...")

        results: Dict[str, List[Dict]] = {}

        results["suspicious_powershell"] = _search_records(records, SUSPICIOUS_PS_KEYWORDS)
        results["credential_dumping"] = _search_records(records, CRED_DUMP_KEYWORDS)
        results["lateral_movement"] = _search_records(records, LATERAL_KEYWORDS)
        results["download_execution"] = _search_records(records, DOWNLOAD_EXEC_KEYWORDS)
        results["exfiltration_indicators"] = _search_records(records, EXFIL_INDICATORS) + _detect_large_outbound(records)
        results["beaconing"] = _detect_beaconing(records)

        for name, hits in results.items():
            self.progress(f"[ToolRunner] {name}: {len(hits)} hits")

        elapsed = int((time.monotonic() - t0) * 1000)
        self.audit.log(
            self.name, "detection_complete",
            tool_call="run_all_detection_rules",
            prompt_summary=f"Running {len(results)} detection categories on {len(records)} records",
            response_summary=", ".join(f"{k}={len(v)}" for k, v in results.items()),
            duration_ms=elapsed,
        )
        return results
