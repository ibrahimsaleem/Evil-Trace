from typing import Dict, List, Tuple

MITRE_MAP: List[Dict] = [
    {"keyword": ["powershell", "encodedcommand", "-enc ", "-e "], "tactic": "Execution", "technique": "PowerShell", "id": "T1059.001"},
    {"keyword": ["cmd.exe", "command.exe"], "tactic": "Execution", "technique": "Windows Command Shell", "id": "T1059.003"},
    {"keyword": ["wscript", "cscript", "vbscript", "jscript"], "tactic": "Execution", "technique": "Visual Basic", "id": "T1059.005"},
    {"keyword": ["mshta", "hta"], "tactic": "Execution", "technique": "Mshta", "id": "T1218.005"},
    {"keyword": ["regsvr32", "regsvcs", "regasm"], "tactic": "Defense Evasion", "technique": "Regsvr32", "id": "T1218.010"},
    {"keyword": ["certutil", "certutil.exe"], "tactic": "Defense Evasion", "technique": "Deobfuscate/Decode Files", "id": "T1140"},
    {"keyword": ["mimikatz", "sekurlsa", "lsadump"], "tactic": "Credential Access", "technique": "OS Credential Dumping", "id": "T1003.001"},
    {"keyword": ["lsass", "procdump", "minidump"], "tactic": "Credential Access", "technique": "LSASS Memory", "id": "T1003.001"},
    {"keyword": ["psexec", "psexesvc"], "tactic": "Lateral Movement", "technique": "SMB/Windows Admin Shares", "id": "T1021.002"},
    {"keyword": ["wmic", "wmiexec"], "tactic": "Lateral Movement", "technique": "Windows Management Instrumentation", "id": "T1047"},
    {"keyword": ["winrm", "winrs", "invoke-command"], "tactic": "Lateral Movement", "technique": "Windows Remote Management", "id": "T1021.006"},
    {"keyword": ["net use", "net view", "admin$", "ipc$", "c$"], "tactic": "Lateral Movement", "technique": "SMB/Windows Admin Shares", "id": "T1021.002"},
    {"keyword": ["curl", "wget", "invoke-webrequest", "iwr", "downloadstring", "downloadfile"], "tactic": "Command and Control", "technique": "Ingress Tool Transfer", "id": "T1105"},
    {"keyword": ["bitsadmin", "bits"], "tactic": "Defense Evasion", "technique": "BITS Jobs", "id": "T1197"},
    {"keyword": ["schtasks", "at.exe", "task scheduler"], "tactic": "Persistence", "technique": "Scheduled Task/Job", "id": "T1053.005"},
    {"keyword": ["reg add", "reg save", "registry"], "tactic": "Persistence", "technique": "Registry Run Keys", "id": "T1547.001"},
    {"keyword": ["sc create", "sc start", "services"], "tactic": "Persistence", "technique": "Windows Service", "id": "T1543.003"},
    {"keyword": ["beacon", "beaconing", "c2", "command and control"], "tactic": "Command and Control", "technique": "Application Layer Protocol", "id": "T1071"},
    {"keyword": ["exfil", "exfiltration", "upload", "post data", "data transfer"], "tactic": "Exfiltration", "technique": "Exfiltration Over C2 Channel", "id": "T1041"},
    {"keyword": ["whoami", "net user", "net group", "get-aduser"], "tactic": "Discovery", "technique": "Account Discovery", "id": "T1087"},
    {"keyword": ["ipconfig", "ifconfig", "arp", "netstat", "nslookup"], "tactic": "Discovery", "technique": "System Network Configuration Discovery", "id": "T1016"},
    {"keyword": ["tasklist", "ps aux", "get-process"], "tactic": "Discovery", "technique": "Process Discovery", "id": "T1057"},
    {"keyword": ["nmap", "masscan", "portscan"], "tactic": "Discovery", "technique": "Network Service Scanning", "id": "T1046"},
    {"keyword": ["vssadmin", "shadow copy", "wbadmin"], "tactic": "Impact", "technique": "Inhibit System Recovery", "id": "T1490"},
    {"keyword": ["cipher /w", "sdelete", "wipe"], "tactic": "Defense Evasion", "technique": "File Deletion", "id": "T1070.004"},
    {"keyword": ["useradd", "net user /add", "new-localuser"], "tactic": "Persistence", "technique": "Create Account", "id": "T1136"},
    {"keyword": ["base64", "frombase64", "convert::frombase64"], "tactic": "Defense Evasion", "technique": "Obfuscated Files or Information", "id": "T1027"},
    {"keyword": ["amsi", "bypass", "reflection.assembly"], "tactic": "Defense Evasion", "technique": "Impair Defenses", "id": "T1562"},
    {"keyword": ["crontab", "cron", "/etc/cron"], "tactic": "Persistence", "technique": "Cron", "id": "T1053.003"},
    {"keyword": ["ssh", "authorized_keys", "known_hosts"], "tactic": "Lateral Movement", "technique": "SSH", "id": "T1021.004"},
]


def map_to_mitre(text: str) -> Tuple[str, str, str]:
    """Return (tactic, technique, technique_id) for the best matching rule."""
    text_lower = text.lower()
    for rule in MITRE_MAP:
        for kw in rule["keyword"]:
            if kw.lower() in text_lower:
                return rule["tactic"], rule["technique"], rule["id"]
    return "Unknown", "Unknown", ""


def map_all(text: str) -> List[Dict]:
    """Return all matching MITRE mappings."""
    text_lower = text.lower()
    results = []
    seen_ids = set()
    for rule in MITRE_MAP:
        for kw in rule["keyword"]:
            if kw.lower() in text_lower and rule["id"] not in seen_ids:
                results.append({
                    "tactic": rule["tactic"],
                    "technique": rule["technique"],
                    "id": rule["id"],
                    "keyword_matched": kw,
                })
                seen_ids.add(rule["id"])
                break
    return results
