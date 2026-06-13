# evidence_input/ — Drop Your Evidence Here

Place your DFIR evidence files in this directory, then run:

```bash
python main.py --evidence ./evidence_input --output outputs/report.md
```

## Supported File Formats

| File Type | Detection | Notes |
|-----------|-----------|-------|
| `sysmon_*.json` | Sysmon JSON event logs | Must contain `EventData` or flat event fields |
| `zeek_conn.log` | Zeek/Bro TSV conn log | Must have `#fields` header |
| `*.csv` | Generic CSV | First row must be headers |
| `*.json` | Generic JSON | Array of objects or single object |
| `auth.log`, `*.log` | Linux syslog auth | Standard syslog format |
| `*.txt` | Generic text | Line-by-line |

## SIFT Workstation Evidence

If using a SIFT Workstation case:

1. Copy Zeek/Bro network logs: `cp /cases/<case>/zeek/*.log ./evidence_input/`
2. Copy Sysmon/Windows event logs: `cp /cases/<case>/logs/*.json ./evidence_input/`
3. Export PowerShell logs: `cp /cases/<case>/powershell/*.csv ./evidence_input/`
4. Run the investigation as above

## Protocol SIFT Starter Evidence

From the Devpost/Protocol SIFT starter kit:
- Extract the provided zip to a working directory
- Copy the log files into `evidence_input/`
- Supported: any JSON, CSV, TSV, or log format

## File Naming Tips

The parser auto-detects file types based on:
1. File name keywords (`sysmon`, `zeek`, `auth`, etc.)
2. File extension (`.json`, `.csv`, `.log`, `.txt`)
3. Content structure (JSON array, CSV headers, syslog format)

Rename files to include type hints if detection fails:
- `sysmon_events.json` for Sysmon
- `zeek_conn.log` for Zeek
- `auth.log` for Linux auth
