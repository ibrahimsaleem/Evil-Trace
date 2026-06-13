import json
import csv
import re
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime


def _normalize_ts(ts: Any) -> str:
    if not ts:
        return ""
    s = str(ts).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
                "%m/%d/%Y %H:%M:%S", "%b %d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(s[:19], fmt[:len(s[:19])]).isoformat()
        except Exception:
            pass
    return s


def parse_sysmon_json(filepath: Path) -> List[Dict[str, Any]]:
    records = []
    try:
        with open(filepath, "r", errors="replace", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("Events", data.get("events", [data]))
        else:
            items = []
        for i, item in enumerate(items):
            ev = item.get("EventData", item)
            records.append({
                "source_file": str(filepath),
                "line_number": i + 1,
                "timestamp": _normalize_ts(ev.get("UtcTime") or ev.get("TimeCreated") or ev.get("timestamp") or ""),
                "host": ev.get("Computer") or ev.get("host") or "",
                "user": ev.get("User") or ev.get("SubjectUserName") or "",
                "process": ev.get("Image") or ev.get("ProcessName") or ev.get("process") or "",
                "command_line": ev.get("CommandLine") or ev.get("command_line") or "",
                "src_ip": ev.get("SourceIp") or ev.get("src_ip") or "",
                "dst_ip": ev.get("DestinationIp") or ev.get("dst_ip") or "",
                "domain": ev.get("DestinationHostname") or ev.get("domain") or "",
                "hash": ev.get("Hashes") or ev.get("hash") or "",
                "file_path": ev.get("TargetFilename") or ev.get("file_path") or "",
                "event_type": f"sysmon:{ev.get('EventID') or ev.get('event_id') or 'unknown'}",
                "raw_record": json.dumps(item),
            })
    except Exception as e:
        records.append({
            "source_file": str(filepath), "line_number": 0,
            "event_type": "parse_error", "raw_record": str(e),
        })
    return records


def parse_zeek_conn(filepath: Path) -> List[Dict[str, Any]]:
    records = []
    try:
        with open(filepath, "r", errors="replace", encoding="utf-8") as f:
            lines = f.readlines()
        headers = []
        for i, line in enumerate(lines):
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                headers = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            else:
                parts = line.split("\t")
                if not headers:
                    continue
                row = dict(zip(headers, parts))
                records.append({
                    "source_file": str(filepath),
                    "line_number": i + 1,
                    "timestamp": _normalize_ts(row.get("ts") or ""),
                    "host": row.get("id.orig_h") or "",
                    "user": "",
                    "process": row.get("service") or "",
                    "command_line": "",
                    "src_ip": row.get("id.orig_h") or "",
                    "dst_ip": row.get("id.resp_h") or "",
                    "domain": row.get("query") or "",
                    "hash": "",
                    "file_path": "",
                    "event_type": f"zeek:{row.get('proto', 'conn')}",
                    "raw_record": line,
                })
    except Exception as e:
        records.append({
            "source_file": str(filepath), "line_number": 0,
            "event_type": "parse_error", "raw_record": str(e),
        })
    return records


def parse_csv_generic(filepath: Path) -> List[Dict[str, Any]]:
    records = []
    try:
        with open(filepath, "r", errors="replace", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                r = {k.lower().strip(): v for k, v in row.items()}
                records.append({
                    "source_file": str(filepath),
                    "line_number": i + 2,
                    "timestamp": _normalize_ts(
                        r.get("timestamp") or r.get("time") or r.get("datetime") or r.get("date") or ""),
                    "host": r.get("host") or r.get("hostname") or r.get("computer") or "",
                    "user": r.get("user") or r.get("username") or r.get("subjectusernam") or "",
                    "process": r.get("process") or r.get("processname") or r.get("image") or "",
                    "command_line": r.get("commandline") or r.get("command_line") or r.get("scriptblocktext") or "",
                    "src_ip": r.get("src_ip") or r.get("sourceip") or r.get("sourceaddress") or "",
                    "dst_ip": r.get("dst_ip") or r.get("destip") or r.get("destinationip") or "",
                    "domain": r.get("domain") or r.get("destinationhostname") or "",
                    "hash": r.get("hash") or r.get("md5") or r.get("sha256") or "",
                    "file_path": r.get("file_path") or r.get("filepath") or r.get("targetfilename") or "",
                    "event_type": r.get("event_type") or r.get("eventid") or "csv:generic",
                    "raw_record": json.dumps(dict(row)),
                })
    except Exception as e:
        records.append({
            "source_file": str(filepath), "line_number": 0,
            "event_type": "parse_error", "raw_record": str(e),
        })
    return records


def parse_json_generic(filepath: Path) -> List[Dict[str, Any]]:
    records = []
    try:
        with open(filepath, "r", errors="replace", encoding="utf-8") as f:
            data = json.load(f)
        items = data if isinstance(data, list) else [data]
        for i, item in enumerate(items):
            flat = {k.lower(): str(v) for k, v in item.items() if not isinstance(v, (dict, list))}
            records.append({
                "source_file": str(filepath),
                "line_number": i + 1,
                "timestamp": _normalize_ts(
                    flat.get("timestamp") or flat.get("time") or flat.get("@timestamp") or ""),
                "host": flat.get("host") or flat.get("hostname") or flat.get("computer") or "",
                "user": flat.get("user") or flat.get("username") or "",
                "process": flat.get("process") or flat.get("image") or "",
                "command_line": flat.get("commandline") or flat.get("command_line") or "",
                "src_ip": flat.get("src_ip") or flat.get("source_ip") or "",
                "dst_ip": flat.get("dst_ip") or flat.get("dest_ip") or "",
                "domain": flat.get("domain") or "",
                "hash": flat.get("hash") or flat.get("md5") or "",
                "file_path": flat.get("file_path") or flat.get("filepath") or "",
                "event_type": flat.get("event_type") or flat.get("eventid") or "json:generic",
                "raw_record": json.dumps(item),
            })
    except Exception as e:
        records.append({
            "source_file": str(filepath), "line_number": 0,
            "event_type": "parse_error", "raw_record": str(e),
        })
    return records


def parse_linux_auth(filepath: Path) -> List[Dict[str, Any]]:
    records = []
    pattern = re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<proc>\S+):\s+(?P<msg>.+)"
    )
    try:
        with open(filepath, "r", errors="replace", encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.rstrip("\n")
                m = pattern.match(line)
                if m:
                    g = m.groupdict()
                    ts_str = f"2024-{g['month']}-{g['day'].zfill(2)} {g['time']}"
                    ts = _normalize_ts(ts_str)
                    msg = g["msg"]
                    user_m = re.search(r"user (\w+)", msg, re.I)
                    user = user_m.group(1) if user_m else ""
                    records.append({
                        "source_file": str(filepath),
                        "line_number": i + 1,
                        "timestamp": ts,
                        "host": g["host"],
                        "user": user,
                        "process": g["proc"],
                        "command_line": "",
                        "src_ip": "",
                        "dst_ip": "",
                        "domain": "",
                        "hash": "",
                        "file_path": "",
                        "event_type": "linux:auth",
                        "raw_record": line,
                    })
                else:
                    if line.strip():
                        records.append({
                            "source_file": str(filepath),
                            "line_number": i + 1,
                            "timestamp": "",
                            "host": "",
                            "user": "",
                            "process": "",
                            "command_line": "",
                            "src_ip": "",
                            "dst_ip": "",
                            "domain": "",
                            "hash": "",
                            "file_path": "",
                            "event_type": "linux:auth",
                            "raw_record": line,
                        })
    except Exception as e:
        records.append({
            "source_file": str(filepath), "line_number": 0,
            "event_type": "parse_error", "raw_record": str(e),
        })
    return records


def parse_txt_generic(filepath: Path) -> List[Dict[str, Any]]:
    records = []
    try:
        with open(filepath, "r", errors="replace", encoding="utf-8") as f:
            for i, line in enumerate(f):
                line = line.rstrip("\n")
                if line.strip():
                    records.append({
                        "source_file": str(filepath),
                        "line_number": i + 1,
                        "timestamp": "",
                        "host": "",
                        "user": "",
                        "process": "",
                        "command_line": line,
                        "src_ip": "",
                        "dst_ip": "",
                        "domain": "",
                        "hash": "",
                        "file_path": "",
                        "event_type": "txt:generic",
                        "raw_record": line,
                    })
    except Exception as e:
        records.append({
            "source_file": str(filepath), "line_number": 0,
            "event_type": "parse_error", "raw_record": str(e),
        })
    return records


PARSER_MAP = {
    ".json": None,
    ".csv": parse_csv_generic,
    ".log": None,
    ".txt": parse_txt_generic,
}


def parse_file(filepath: Path) -> List[Dict[str, Any]]:
    name = filepath.name.lower()
    suffix = filepath.suffix.lower()

    if "sysmon" in name and suffix == ".json":
        return parse_sysmon_json(filepath)
    if "zeek" in name or "conn" in name and suffix == ".log":
        return parse_zeek_conn(filepath)
    if "auth" in name and (suffix == ".log" or suffix == ".txt"):
        return parse_linux_auth(filepath)
    if suffix == ".json":
        return parse_json_generic(filepath)
    if suffix == ".csv":
        return parse_csv_generic(filepath)
    if suffix == ".log":
        return parse_zeek_conn(filepath) if "zeek" in name else parse_txt_generic(filepath)
    if suffix == ".txt":
        return parse_txt_generic(filepath)
    return []


def parse_evidence_folder(folder: Path) -> List[Dict[str, Any]]:
    all_records = []
    supported = {".json", ".csv", ".log", ".txt"}
    for f in sorted(folder.rglob("*")):
        if f.is_file() and f.suffix.lower() in supported:
            records = parse_file(f)
            all_records.extend(records)
    return all_records
