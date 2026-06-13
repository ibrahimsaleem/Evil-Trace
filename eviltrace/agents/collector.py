import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from utils.parsers import parse_evidence_folder
from utils.database import init_db, insert_evidence, clear_db, query_all_evidence
from agents.audit_logger import AuditLoggerAgent


class EvidenceCollectorAgent:
    """Parses evidence files and stores normalized records in SQLite."""

    name = "EvidenceCollectorAgent"

    def __init__(
        self,
        audit: AuditLoggerAgent,
        db_path: Optional[Path] = None,
        progress_cb: Optional[Callable[[str], None]] = None,
    ):
        self.audit = audit
        self.db_path = db_path
        self.progress = progress_cb or (lambda msg: None)

    def run(self, evidence_dir: Path) -> List[Dict[str, Any]]:
        t0 = time.monotonic()
        self.progress(f"[EvidenceCollector] Scanning {evidence_dir} ...")

        init_db(self.db_path)
        clear_db(self.db_path)

        self.audit.log(
            self.name, "start",
            tool_call="init_db + clear_db",
            prompt_summary=f"Initializing DB and clearing previous run",
            response_summary="DB initialized",
        )

        records = parse_evidence_folder(evidence_dir)
        self.progress(f"[EvidenceCollector] Parsed {len(records)} raw records from {evidence_dir}")

        insert_evidence(records, self.db_path)
        elapsed = int((time.monotonic() - t0) * 1000)

        files_seen = list({r.get("source_file", "") for r in records})
        self.audit.log(
            self.name, "parse_complete",
            tool_call="parse_evidence_folder + insert_evidence",
            prompt_summary=f"Parsing {evidence_dir}, files: {len(files_seen)}",
            response_summary=f"Stored {len(records)} normalized records from {len(files_seen)} files",
            duration_ms=elapsed,
        )

        self.progress(f"[EvidenceCollector] Stored {len(records)} records in DB. Files: {files_seen}")
        return records
