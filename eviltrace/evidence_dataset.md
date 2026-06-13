# Evidence Dataset Documentation

## Sample Evidence Files

### `sample_evidence/sysmon_sample.json`
**Format:** JSON array of Sysmon event objects

**Contains:**
- EventID 1 (Process Create): powershell.exe with -EncodedCommand flag
- EventID 1: PowerShell downloading and executing `payload.exe` from `198.51.100.44`
- EventID 3 (Network Connect): payload.exe connecting to `c2.evil-domain.xyz:443`
- EventID 1: `net use` connecting to admin$ share on 10.0.1.100
- EventID 1: `schtasks` creating a persistence task named "Windows Update"
- EventID 1: `whoami /all` for discovery

**Expected Confirmed Findings:**
- Suspicious PowerShell with encoded command (T1059.001)
- Malicious download via WebClient DownloadFile (T1105)
- Lateral movement via net use admin$ (T1021.002)

**Expected Rejected Findings:**
- Credential dumping (H003) — no lsass/mimikatz/procdump artifact in this file

---

### `sample_evidence/zeek_conn.log`
**Format:** Zeek/Bro TSV with `#fields` header

**Contains:**
- 10 repeated connections from `10.0.1.50` to `198.51.100.44:443` at ~60s intervals
- DNS queries to 8.8.8.8
- SMB connection from 10.0.1.100 to 10.0.1.50:445 (153600 bytes = lateral movement indicator)
- HTTP connection from 10.0.1.50 to 203.0.113.55:80 (524288 bytes outbound)

**Expected Confirmed Findings:**
- C2 beaconing: 10 repeated connections to 198.51.100.44 (T1071)

**Expected Weak/Rejected Findings:**
- Exfiltration: 524KB outbound is flagged but not definitively confirmed without upload artifact

---

### `sample_evidence/powershell_events.csv`
**Format:** CSV with columns: timestamp, host, user, event_type, command_line, src_ip, dst_ip, process, file_path

**Contains:**
- EventID 4104 (ScriptBlock Logging): `-EncodedCommand` with base64 payload
- EventID 4103: `Invoke-Expression` / `FromBase64String`
- EventID 4104: `DownloadFile` from 198.51.100.44
- EventID 4104: `Start-Process` for payload.exe
- EventID 4104: `Set-MpPreference -DisableRealtimeMonitoring $true` (AMSI bypass / AV disable)
- EventID 4104: `Get-Process` filtering for lsass (note: process enumeration, NOT dump)
- EventID 4104: `Invoke-WebRequest` for stage2
- EventID 4104: `wmic` for lateral movement to workstation
- EventID 4103: `Get-ADUser` for domain recon
- EventID 4104: `Invoke-Command` WinRM lateral movement

**Expected Confirmed Findings:**
- PowerShell encoded command (T1059.001)
- Download execution via IWR/DownloadFile (T1105)
- Lateral movement via WMIC/WinRM (T1047, T1021.006)

**Note on Credential Dumping:**
The log contains `Get-Process | Where-Object {$_.Name -eq 'lsass'}` — this is process *enumeration*,
NOT credential dumping. The VerificationAgent correctly rejects the credential dumping hypothesis
because there is no actual dump invocation (procdump, comsvcs MiniDump, sekurlsa, mimikatz).
This is the intentional self-correction demo scenario.

---

### `sample_evidence/linux_auth.log`
**Format:** Linux syslog auth.log format

**Contains:**
- SSH login as root from 203.0.113.55 (external IP)
- wget of linpeas.sh from 198.51.100.44
- `useradd backdoor` — persistence via new account creation (T1136)
- crontab entry running `beacon.sh` every minute (T1053.003)
- curl POST of /etc/passwd to 198.51.100.44 (potential exfiltration, but no size)
- SSH login as `backdoor` user from 203.0.113.55
- SSH brute-force attempts from 198.51.100.100

**Expected Confirmed Findings:**
- Suspicious download execution via wget/curl (T1105)

**Expected Weak/Rejected Findings:**
- Exfiltration via curl POST (flagged as weak — no byte count in auth log)
- Credential dumping (no lsass artifact in linux logs)

---

## How to Replace Sample Evidence

### Method 1: SIFT Workstation Case
```bash
# On SIFT or DFIR workstation:
cp /cases/your-case/zeek/*.log ./evidence_input/
cp /cases/your-case/sysmon/*.json ./evidence_input/
cp /cases/your-case/powershell/*.csv ./evidence_input/
cp /var/log/auth.log ./evidence_input/

python main.py --evidence ./evidence_input --output outputs/report.md
```

### Method 2: Protocol/Devpost SIFT Starter
```bash
# Extract the provided starter kit:
unzip devpost-starter.zip -d evidence_input/
python main.py --evidence ./evidence_input --output outputs/report.md
```

### Method 3: Custom Evidence
Any combination of:
- Sysmon JSON exports from Windows Event Viewer
- Zeek connection logs from network capture analysis
- PowerShell ScriptBlock logging CSV exports
- `/var/log/auth.log` from Linux systems
- Any JSON, CSV, or log file with security events

The system never hardcodes results for specific file names or content.
All detection logic runs on the normalized record content.
