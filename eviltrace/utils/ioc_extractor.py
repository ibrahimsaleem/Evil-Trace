import re
from typing import List, Dict, Any


IPV4_RE = re.compile(r"\b(?!10\.\d|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)(\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|xyz|info|biz|top|club|tk|pw|cc|su|onion)\b", re.I)
MD5_RE = re.compile(r"\b[0-9a-fA-F]{32}\b")
SHA256_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
SHA1_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b")
BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")
ENCODED_PS_RE = re.compile(r"-[Ee](?:ncoded[Cc]ommand)?\s+([A-Za-z0-9+/=]{20,})", re.I)

PRIVATE_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^127\."),
    re.compile(r"^0\."),
    re.compile(r"^255\."),
]


def is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_RANGES)


def extract_iocs(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    iocs = []
    seen = set()

    def add(ioc_type, value, context, source_file, timestamp, severity="medium"):
        key = f"{ioc_type}:{value}"
        if key not in seen:
            seen.add(key)
            iocs.append({
                "ioc_type": ioc_type,
                "value": value,
                "context": context[:200],
                "source_file": source_file,
                "timestamp": timestamp,
                "severity": severity,
            })

    for r in records:
        raw = r.get("raw_record", "") or ""
        src = r.get("source_file", "")
        ts = r.get("timestamp", "")

        for m in IPV4_RE.finditer(raw):
            ip = m.group(0)
            if not is_private_ip(ip):
                add("ip", ip, raw[:100], src, ts, "high")

        for m in DOMAIN_RE.finditer(raw):
            add("domain", m.group(0).lower(), raw[:100], src, ts, "medium")

        for m in URL_RE.finditer(raw):
            add("url", m.group(0), raw[:100], src, ts, "high")

        for m in MD5_RE.finditer(raw):
            add("md5", m.group(0).lower(), raw[:100], src, ts, "medium")

        for m in SHA256_RE.finditer(raw):
            add("sha256", m.group(0).lower(), raw[:100], src, ts, "medium")

        for m in SHA1_RE.finditer(raw):
            add("sha1", m.group(0).lower(), raw[:100], src, ts, "low")

        for m in EMAIL_RE.finditer(raw):
            add("email", m.group(0).lower(), raw[:100], src, ts, "low")

        for m in ENCODED_PS_RE.finditer(raw):
            add("encoded_powershell", m.group(1)[:64] + "...", raw[:100], src, ts, "critical")

        cl = r.get("command_line", "") or ""
        if cl:
            for m in ENCODED_PS_RE.finditer(cl):
                add("encoded_powershell", m.group(1)[:64] + "...", cl[:100], src, ts, "critical")

        if r.get("dst_ip") and not is_private_ip(r.get("dst_ip", "")):
            add("ip", r["dst_ip"], f"Outbound connection from {r.get('src_ip','?')}", src, ts, "medium")

        if r.get("domain"):
            d = r["domain"]
            if len(d) > 4 and "." in d:
                add("domain", d, f"DNS/connection to {d}", src, ts, "medium")

        if r.get("hash"):
            h = r["hash"]
            parts = h.split("=")[-1] if "=" in h else h
            parts = parts.split(",")[0].strip()
            if len(parts) in (32, 40, 64):
                t = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(parts), "hash")
                add(t, parts.lower(), f"File hash from {r.get('file_path','?')}", src, ts, "medium")

    return iocs
