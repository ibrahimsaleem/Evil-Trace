import sqlite3
import json
from pathlib import Path
from typing import List, Dict, Any, Optional


DB_PATH = Path("outputs/eviltrace.db")


def get_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = db_path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[Path] = None):
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_file TEXT,
            line_number INTEGER,
            timestamp TEXT,
            host TEXT,
            user TEXT,
            process TEXT,
            command_line TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            domain TEXT,
            hash TEXT,
            file_path TEXT,
            event_type TEXT,
            raw_record TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            claim TEXT,
            status TEXT,
            severity TEXT,
            confidence REAL,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            mitre_technique_id TEXT,
            source_file TEXT,
            line_number INTEGER,
            timestamp TEXT,
            supporting_artifact TEXT,
            reasoning TEXT,
            origin TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_timestamp TEXT,
            agent TEXT,
            step TEXT,
            tool_call TEXT,
            prompt_summary TEXT,
            response_summary TEXT,
            tokens_used INTEGER,
            cost_estimate REAL,
            duration_ms INTEGER
        );

        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_type TEXT,
            value TEXT,
            context TEXT,
            source_file TEXT,
            timestamp TEXT,
            severity TEXT
        );
    """)
    conn.commit()
    conn.close()


def insert_evidence(records: List[Dict[str, Any]], db_path: Optional[Path] = None):
    conn = get_connection(db_path)
    cur = conn.cursor()
    for r in records:
        cur.execute("""
            INSERT INTO evidence (
                source_file, line_number, timestamp, host, user, process,
                command_line, src_ip, dst_ip, domain, hash, file_path,
                event_type, raw_record
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            r.get("source_file"), r.get("line_number"), r.get("timestamp"),
            r.get("host"), r.get("user"), r.get("process"),
            r.get("command_line"), r.get("src_ip"), r.get("dst_ip"),
            r.get("domain"), r.get("hash"), r.get("file_path"),
            r.get("event_type"), r.get("raw_record"),
        ))
    conn.commit()
    conn.close()


def insert_finding(finding: Dict[str, Any], db_path: Optional[Path] = None):
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO findings (
            claim, status, severity, confidence, mitre_tactic,
            mitre_technique, mitre_technique_id, source_file, line_number,
            timestamp, supporting_artifact, reasoning, origin
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        finding.get("claim"), finding.get("status"), finding.get("severity"),
        finding.get("confidence"), finding.get("mitre_tactic"),
        finding.get("mitre_technique"), finding.get("mitre_technique_id"),
        finding.get("source_file"), finding.get("line_number"),
        finding.get("timestamp"), finding.get("supporting_artifact"),
        finding.get("reasoning"), finding.get("origin"),
    ))
    conn.commit()
    conn.close()


def insert_ioc(ioc: Dict[str, Any], db_path: Optional[Path] = None):
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO iocs (ioc_type, value, context, source_file, timestamp, severity)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        ioc.get("ioc_type"), ioc.get("value"), ioc.get("context"),
        ioc.get("source_file"), ioc.get("timestamp"), ioc.get("severity"),
    ))
    conn.commit()
    conn.close()


def insert_audit(entry: Dict[str, Any], db_path: Optional[Path] = None):
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO audit_log (
            run_timestamp, agent, step, tool_call, prompt_summary,
            response_summary, tokens_used, cost_estimate, duration_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        entry.get("run_timestamp"), entry.get("agent"), entry.get("step"),
        entry.get("tool_call"), entry.get("prompt_summary"),
        entry.get("response_summary"), entry.get("tokens_used"),
        entry.get("cost_estimate"), entry.get("duration_ms"),
    ))
    conn.commit()
    conn.close()


def query_evidence(filters: Optional[Dict] = None, db_path: Optional[Path] = None) -> List[Dict]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    query = "SELECT * FROM evidence"
    params = []
    if filters:
        clauses = []
        for k, v in filters.items():
            clauses.append(f"{k} LIKE ?")
            params.append(f"%{v}%")
        query += " WHERE " + " AND ".join(clauses)
    cur.execute(query, params)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def query_all_evidence(db_path: Optional[Path] = None) -> List[Dict]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM evidence ORDER BY timestamp ASC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def query_all_findings(db_path: Optional[Path] = None) -> List[Dict]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM findings ORDER BY severity DESC, confidence DESC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def query_all_iocs(db_path: Optional[Path] = None) -> List[Dict]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM iocs")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def query_audit_log(db_path: Optional[Path] = None) -> List[Dict]:
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM audit_log ORDER BY id ASC")
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def clear_db(db_path: Optional[Path] = None):
    conn = get_connection(db_path)
    cur = conn.cursor()
    cur.executescript("""
        DELETE FROM evidence;
        DELETE FROM findings;
        DELETE FROM audit_log;
        DELETE FROM iocs;
    """)
    conn.commit()
    conn.close()
