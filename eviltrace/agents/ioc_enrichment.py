import logging
from typing import List, Dict, Any, Optional, Callable
from providers.exa import ExaProvider
from utils.ioc_extractor import extract_iocs

class IOCEnrichmentAgent:
    """Agent that enriches confirmed/weak IOCs with external threat intelligence using Exa."""

    name = "IOCEnrichmentAgent"

    def __init__(self, api_key: str = "", progress_cb: Optional[Callable[[str], None]] = None):
        self.provider = ExaProvider(api_key=api_key)
        self.progress = progress_cb or (lambda msg: None)

    def run(
        self,
        findings: List[Dict[str, Any]],
        tool_results: Dict[str, List[Dict]],
        enabled: bool = True
    ) -> List[Dict[str, Any]]:
        """Filter IOCs of confirmed/weak findings, and enrich them via Exa."""
        if not enabled:
            self.progress("[IOCEnrichmentAgent] Exa IOC Enrichment is disabled. Skipping.")
            return []

        if not self.provider.is_available():
            self.progress("[IOCEnrichmentAgent] Exa API key is missing. Skipping enrichment.")
            return []

        self.progress("[IOCEnrichmentAgent] Starting Exa IOC enrichment for confirmed/weak findings...")

        # 1. Identify categories that are confirmed or weak
        active_categories = set()
        for f in findings:
            if f.get("status") in ("confirmed", "weak_evidence"):
                active_categories.add(f.get("category"))

        # 2. Gather records associated with active findings
        active_records = []
        seen_rec = set()
        for cat in active_categories:
            for rec in tool_results.get(cat, []):
                # Unique identifier for record to avoid duplicates
                rec_id = (rec.get("timestamp"), rec.get("source_file"), rec.get("raw_record", "")[:100])
                if rec_id not in seen_rec:
                    seen_rec.add(rec_id)
                    active_records.append(rec)

        # 3. Extract IOCs from these active records
        confirmed_iocs = extract_iocs(active_records)
        if not confirmed_iocs:
            self.progress("[IOCEnrichmentAgent] No confirmed IOCs found to enrich.")
            return []

        self.progress(f"[IOCEnrichmentAgent] Found {len(confirmed_iocs)} confirmed IOC(s) to enrich.")
        
        enriched_results = []
        for ioc_item in confirmed_iocs:
            ioc_val = ioc_item["value"]
            ioc_type = ioc_item["ioc_type"]
            self.progress(f"[IOCEnrichmentAgent] Querying Exa for {ioc_type}: {ioc_val} ...")
            
            try:
                enrichment = self.provider.enrich_ioc(ioc_val, ioc_type)
                enriched_results.append(enrichment)
            except Exception as e:
                # Mask key in errors and continue investigation gracefully
                sanitized_error = self.provider._sanitize(str(e))
                self.progress(f"[Warning] Failed to enrich IOC {ioc_val}: {sanitized_error}")

        self.progress(f"[IOCEnrichmentAgent] Enrichment complete. Enriched {len(enriched_results)} IOC(s).")
        return enriched_results
