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
        enabled: bool = True,
        enrich_weak: bool = False
    ) -> List[Dict[str, Any]]:
        """Filter IOCs of confirmed (and optionally weak) findings, and enrich them via Exa."""
        if not enabled:
            self.progress("[IOCEnrichmentAgent] Exa IOC Enrichment is disabled. Skipping.")
            return []

        if not self.provider.is_available():
            self.progress("[IOCEnrichmentAgent] Exa API key is missing. Skipping enrichment.")
            return []

        self.progress(f"[IOCEnrichmentAgent] Starting Exa IOC enrichment (enrich_weak={enrich_weak})...")

        # 1. Map category to status (confirmed/weak_evidence)
        category_statuses = {}
        for f in findings:
            status = f.get("status")
            cat = f.get("category")
            if status == "confirmed":
                category_statuses[cat] = "confirmed"
            elif status == "weak_evidence" and enrich_weak:
                category_statuses[cat] = "weak_evidence"

        # 2. Gather records associated with active findings
        active_records_confirmed = []
        active_records_weak = []
        seen_rec = set()
        
        for cat, status in category_statuses.items():
            for rec in tool_results.get(cat, []):
                rec_id = (rec.get("timestamp"), rec.get("source_file"), rec.get("raw_record", "")[:100])
                if rec_id not in seen_rec:
                    seen_rec.add(rec_id)
                    if status == "confirmed":
                        active_records_confirmed.append(rec)
                    else:
                        active_records_weak.append(rec)

        # 3. Extract IOCs
        confirmed_iocs = extract_iocs(active_records_confirmed)
        weak_iocs = extract_iocs(active_records_weak)
        
        # Avoid enriching the same IOC twice (e.g. if it appears in both confirmed and weak, prioritize confirmed)
        confirmed_values = {ioc["value"] for ioc in confirmed_iocs}
        weak_iocs = [ioc for ioc in weak_iocs if ioc["value"] not in confirmed_values]

        if not confirmed_iocs and not weak_iocs:
            self.progress("[IOCEnrichmentAgent] No active IOCs found to enrich.")
            return []

        self.progress(f"[IOCEnrichmentAgent] Found {len(confirmed_iocs)} confirmed IOC(s) and {len(weak_iocs)} weak IOC(s) to enrich.")
        
        enriched_results = []
        
        # Helper to query and construct enrichment dict
        def enrich_list(ioc_list, status_label):
            for ioc_item in ioc_list:
                ioc_val = ioc_item["value"]
                ioc_type = ioc_item["ioc_type"]
                self.progress(f"[IOCEnrichmentAgent] Querying Exa for {status_label} {ioc_type}: {ioc_val} ...")
                try:
                    enrichment = self.provider.enrich_ioc(ioc_val, ioc_type)
                    enrichment["finding_status"] = status_label
                    enriched_results.append(enrichment)
                except Exception as e:
                    sanitized_error = self.provider._sanitize(str(e))
                    self.progress(f"[Warning] Failed to enrich {status_label} IOC {ioc_val}: {sanitized_error}")

        enrich_list(confirmed_iocs, "confirmed")
        enrich_list(weak_iocs, "weak_evidence")

        self.progress(f"[IOCEnrichmentAgent] Enrichment complete. Enriched {len(enriched_results)} IOC(s).")
        return enriched_results
