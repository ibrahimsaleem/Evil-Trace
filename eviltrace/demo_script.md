# EvilTrace AI — Demo Script (≤5 minutes)

## Video Script

### [0:00–0:20] Hook

> "What if your incident response assistant could read real forensic logs, form hypotheses,
> verify every claim against exact artifacts, catch its own mistakes, and produce a
> judge-ready report — all without hallucinating?"
>
> "That's EvilTrace AI. Let's see it live."

---

### [0:20–0:45] Show the Evidence

```bash
ls -la sample_evidence/
```

> "We have four evidence files: Sysmon process creation logs in JSON,
> a Zeek network connection log, a PowerShell script block log CSV,
> and a Linux authentication log. These are realistic synthetic logs
> that mirror what you'd find in a SIFT Workstation case."

---

### [0:45–1:30] Run the CLI Investigation

```bash
python main.py --evidence ./sample_evidence --output outputs/report.md
```

Watch the output:

```
EvilTrace AI — Starting Investigation
  Evidence: sample_evidence/
  Provider: mock

[EvidenceCollector] Scanning sample_evidence/ ...
[EvidenceCollector] Parsed 38 raw records
[EvidenceCollector] Stored 38 records in DB. Files: [sysmon_sample.json, zeek_conn.log, ...]

[ToolRunner] Running detection rules ...
[ToolRunner] suspicious_powershell: 7 hits
[ToolRunner] credential_dumping: 0 hits
[ToolRunner] lateral_movement: 3 hits
[ToolRunner] download_execution: 4 hits
[ToolRunner] exfiltration_indicators: 1 hits
[ToolRunner] beaconing: 2 hits

[HypothesisAgent] Generating hypotheses ...
[HypothesisAgent] H001: Suspicious PowerShell... confidence=0.90
[HypothesisAgent] H002: File download execution... confidence=0.80
[HypothesisAgent] H003: Credential dumping... confidence=0.10   ← Note: very low
[HypothesisAgent] H004: Lateral movement... confidence=0.70
[HypothesisAgent] H005: C2 beaconing... confidence=0.70
[HypothesisAgent] H006: Exfiltration indicators... confidence=0.50

[VerificationAgent] Verifying all hypotheses ...
[VerificationAgent] H001: confirmed (confidence=0.90)
[VerificationAgent] H002: confirmed (confidence=0.80)
[VerificationAgent] H003: REJECTED — no cred-dump artifact
[VerificationAgent] H004: confirmed (confidence=0.70)
[VerificationAgent] H005: weak_evidence (confidence=0.45)
[VerificationAgent] H006: rejected — insufficient exfil evidence

[SelfCorrectionAgent] Scanning for hallucinations and weak claims ...
[SelfCorrectionAgent] CORRECTION: Credential dumping hypothesis rejected —
    no LSASS/Mimikatz/memory dump artifact exists.
[SelfCorrectionAgent] CORRECTION: Exfiltration claim lacks transfer-size evidence.
```

---

### [1:30–2:15] Highlight: Confirmed PowerShell Finding

> "Let's look at the confirmed PowerShell finding."

```
[T1059.001] Suspicious PowerShell execution with encoded or obfuscated commands
  Status: ✅ Confirmed
  Severity: CRITICAL
  Confidence: 90%
  Source: sample_evidence/powershell_events.csv line 2
  Timestamp: 2024-03-15T02:13:30
  Artifact: powershell.exe -NoP -NonI -W Hidden -EncodedCommand JABjAGwAaQBlAG4A...
```

---

### [2:15–2:45] Highlight: Self-Correction — Credential Dumping REJECTED

> "Now watch the self-correction. The system proposed credential dumping
> as a hypothesis — but it found no LSASS access, no Mimikatz invocation,
> no memory dump. So it rejected the claim and flagged it."

```
[SelfCorrectionAgent] CORRECTION:
  Type: hallucination_prevented
  Description: Credential dumping hypothesis rejected because no supporting LSASS,
               Mimikatz, memory dump, or credential-access artifact was found.
               This claim would constitute a hallucination if reported as confirmed.
  Correction: Removed from confirmed findings. Listed in rejected panel.
```

---

### [2:45–3:15] Show the Final Report

```bash
cat outputs/report.md | head -80
```

> "The final report has confirmed findings with exact evidence references,
> rejected hypotheses transparently listed, self-correction log, IOC table,
> and a full MITRE ATT&CK mapping."

---

### [3:15–3:45] Show Audit Trail

```bash
cat outputs/audit_log.jsonl | python3 -c "import sys,json; [print(json.dumps(json.loads(l), indent=2)) for l in sys.stdin]" | head -60
```

> "Every decision is in the audit log — which agent ran, what tool it called,
> what the prompt said, what the response was, and how long it took.
> Full traceability from raw log to final finding."

---

### [3:45–4:15] Streamlit UI Demo

```bash
streamlit run app.py
```

> "Now in the Streamlit UI — same investigation, visual interface.
> Findings table, rejected hypotheses panel, self-correction log,
> timeline, IOC table, MITRE mapping, and one-click report download."

---

### [4:15–4:45] Swap to Real Evidence

```bash
# Drop real logs into evidence_input/
cp /path/to/real/case/*.json ./evidence_input/
cp /path/to/real/case/*.log ./evidence_input/

python main.py --evidence ./evidence_input --output outputs/report.md
```

> "And because the detection is rule-based and not hardcoded to sample data,
> it works equally well on real evidence. Drop any DFIR logs in and run."

---

### [4:45–5:00] Wrap-up

> "EvilTrace AI: real evidence analysis, verified findings, self-correcting hypotheses,
> and a complete audit trail. No hallucinations. No unsupported claims.
> Built for FIND EVIL — let's find evil."
