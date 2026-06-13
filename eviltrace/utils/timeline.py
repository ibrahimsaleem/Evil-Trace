from typing import List, Dict, Any
from datetime import datetime


def build_timeline(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    timeline = []
    for r in records:
        ts = r.get("timestamp", "")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts[:19])
        except Exception:
            continue
        timeline.append({
            "timestamp": ts,
            "dt": dt.isoformat(),
            "host": r.get("host", ""),
            "user": r.get("user", ""),
            "process": r.get("process", ""),
            "event_type": r.get("event_type", ""),
            "command_line": r.get("command_line", ""),
            "src_ip": r.get("src_ip", ""),
            "dst_ip": r.get("dst_ip", ""),
            "source_file": r.get("source_file", ""),
            "line_number": r.get("line_number", 0),
        })
    timeline.sort(key=lambda x: x.get("dt", ""))
    return timeline


def summarize_timeline(timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not timeline:
        return {"total_events": 0, "start": None, "end": None, "hosts": [], "users": []}
    hosts = list({t["host"] for t in timeline if t.get("host")})
    users = list({t["user"] for t in timeline if t.get("user")})
    return {
        "total_events": len(timeline),
        "start": timeline[0]["dt"],
        "end": timeline[-1]["dt"],
        "hosts": hosts,
        "users": users,
    }
