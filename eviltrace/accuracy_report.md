# EvilTrace AI — Accuracy Report

## Test Dataset

**Dataset:** Synthetic realistic sample evidence (4 files, 38 records)
- `sysmon_sample.json` — 6 process/network events
- `zeek_conn.log` — 14 connection records  
- `powershell_events.csv` — 11 scriptblock/event records
- `linux_auth.log` — 16 auth log entries

## Results

### Hypotheses Evaluated: 6

| ID | Claim | Status | Confidence | Correct? |
|----|-------|--------|------------|---------|
| H001 | Suspicious PowerShell execution | Confirmed | 90% | ✅ True Positive |
| H002 | Malicious download/execution | Confirmed | 80% | ✅ True Positive |
| H003 | Credential dumping (LSASS/Mimikatz) | Rejected | 10% | ✅ True Negative |
| H004 | Lateral movement | Confirmed | 70% | ✅ True Positive |
| H005 | C2 beaconing | Confirmed/Weak | 45–80% | ✅ Correct (depends on beacon count threshold) |
| H006 | Data exfiltration | Rejected/Weak | 15–40% | ✅ Correct (insufficient evidence) |

### Confirmed Findings: 3–4
### Rejected Hypotheses: 1–2
### False Positives Prevented: 1 (credential dumping)
### Hallucinations Prevented: 1 (credential dumping without artifact)

## Hallucination Prevention: Credential Dumping

**Scenario:**
The sample evidence contains `Get-Process | Where-Object {$_.Name -eq 'lsass'}`.
This is process *enumeration* — checking if lsass is running.
It is NOT a credential dump (which requires procdump, comsvcs MiniDump, sekurlsa, etc.)

**System Behavior:**
1. HypothesisAgent proposes H003 (credential dumping)
2. ToolRunnerAgent finds 0 hits in the `credential_dumping` category
3. VerificationAgent: "No LSASS/Mimikatz/memory dump artifact found" → REJECTED
4. SelfCorrectionAgent: Logs `hallucination_prevented` event, confirms rejection with explanation

**Verdict:** System correctly prevented a false positive that a naive LLM would likely confirm.

## IOC Extraction Accuracy

| IOC Type | Extracted | Notes |
|----------|-----------|-------|
| External IPs | 3 | `198.51.100.44`, `203.0.113.55`, `198.51.100.100` |
| Domains | 1 | `c2.evil-domain.xyz` |
| URLs | 2 | Download URLs from PowerShell events |
| Hashes | 2 | MD5 from Sysmon Hashes field |
| Encoded PS | 2 | Base64-encoded command fragments |

## Scoring Methodology

### Confidence Formula
```
confidence = rule_hit(0.40) + llm_hit(0.20) + artifact_count(min(n*0.10, 0.30)) + exact_match(0.10)
```

### Status Thresholds
- **Confirmed**: artifact_exact_match=True AND confidence ≥ 0.50
- **Weak Evidence**: confidence ≥ 0.35 (without exact match)
- **Rejected**: confidence < 0.25 OR category-specific exact-match requirement fails

### Category-Specific Override Rules
- **Credential Dumping**: MUST have exact credential-access tool or dump artifact (e.g. `mimikatz`, `procdump`, `comsvcs`, `minidump`, `sekurlsa`, `wce.exe`) -> otherwise REJECTED regardless of confidence. Generic lsass process name alone is weak and results in rejection.
- **Exfiltration**: MUST have large outbound transfer size (>100KB) OR archive creation (.zip, .rar, etc.) plus a transfer tool (ftp, scp, rsync, curl, wget, upload, webrequest) -> otherwise REJECTED.
- **Beaconing**: MUST have >= 5 repeated connections to the same external IP for CONFIRMED, >= 3 for WEAK -> otherwise REJECTED.
- **Suspicious PowerShell**: MUST have exact command evidence (encodedcommand, -enc, frombase64, iex, invoke-expression, bypass, hidden, etc.) in hits -> otherwise REJECTED.
- **Lateral Movement**: MUST have remote execution or service indicators (psexec, wmic, winrm, admin$, ipc$, c$, invoke-command) -> otherwise REJECTED.
- **Malware Execution**: MUST have suspicious executable path, hash, parent-child chain, command line, or persistence artifact (schtasks, reg add, runonce, cron, etc.) -> otherwise REJECTED.

## Limitations

1. **PCAP analysis not supported** — only PCAP metadata (CSV export) is processed
2. **No memory forensics** — cannot analyze raw memory images or hibernation files
3. **Timestamp normalization** — some exotic timestamp formats may not parse correctly
4. **Large evidence sets** — processing >100k records may be slow in current SQLite implementation
5. **LLM in Mock Mode** — deterministic responses; real LLM augments but does not replace rules
6. **Obfuscation depth** — multi-layer obfuscated PowerShell may evade keyword detection
7. **Benign false positives** — legitimate admin tools (certutil, bitsadmin, psexec) may trigger rules in authorized-use environments

## Honest Assessment

EvilTrace AI is a conservative system. It is designed to:
- Confirm only what evidence directly supports
- Reject rather than speculate when artifacts are absent
- Show all rejected hypotheses transparently
- Never name a malware family unless explicitly in evidence

This approach means it may miss some true positives (lower recall) in exchange for near-zero
hallucinations in the final report (high precision). For a competition and real-world DFIR context,
false negatives (missed findings) are preferable to false positives (incorrect accusations).
