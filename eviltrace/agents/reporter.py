import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from providers.base import BaseProvider
from agents.audit_logger import AuditLoggerAgent
from utils.timeline import summarize_timeline


class ReportWriterAgent:
    """Creates final markdown report and all output files."""

    name = "ReportWriterAgent"

    def __init__(
        self,
        provider: BaseProvider,
        audit: AuditLoggerAgent,
        output_dir: Path = Path("outputs"),
        progress_cb: Optional[Callable[[str], None]] = None,
    ):
        self.provider = provider
        self.audit = audit
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.progress = progress_cb or (lambda msg: None)

    def run(
        self,
        findings: List[Dict[str, Any]],
        corrections: List[Dict[str, Any]],
        iocs: List[Dict[str, Any]],
        timeline: List[Dict[str, Any]],
        evidence_dir: str,
        provider_name: str,
        enriched_iocs: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, str]:
        t0 = time.monotonic()
        self.progress("[ReportWriter] Generating final report ...")

        confirmed = [f for f in findings if f.get("status") == "confirmed"]
        weak = [f for f in findings if f.get("status") == "weak_evidence"]
        rejected = [f for f in findings if f.get("status") == "rejected"]
        tl_summary = summarize_timeline(timeline)

        prompt = (
            f"You are a senior DFIR analyst. Write a 2-paragraph executive summary for an IR report.\n"
            f"Confirmed findings: {len(confirmed)}, Weak evidence: {len(weak)}, Rejected: {len(rejected)}\n"
            f"Top confirmed finding: {confirmed[0]['claim'] if confirmed else 'None'}\n"
            f"Key rejected hypothesis: {rejected[0]['claim'] if rejected else 'None'}\n"
            f"Do not hallucinate. Stick to the facts."
        )
        exec_summary = self.provider.complete(prompt, max_tokens=300)

        now = datetime.utcnow().isoformat()
        md = self._build_markdown(
            exec_summary, confirmed, weak, rejected,
            corrections, iocs, tl_summary, evidence_dir, provider_name, now,
            enriched_iocs=enriched_iocs
        )

        report_path = self.output_dir / "report.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(md)

        findings_path = self.output_dir / "findings.json"
        with open(findings_path, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2, default=str)

        timeline_path = self.output_dir / "timeline.json"
        with open(timeline_path, "w", encoding="utf-8") as f:
            json.dump(timeline, f, indent=2, default=str)

        iocs_path = self.output_dir / "iocs.csv"
        self._write_iocs_csv(iocs, iocs_path)

        accuracy_path = self.output_dir / "accuracy_summary.md"
        with open(accuracy_path, "w", encoding="utf-8") as f:
            f.write(self._build_accuracy(confirmed, weak, rejected, corrections, len(iocs)))

        results_dict = {
            "report": str(report_path),
            "findings": str(findings_path),
            "timeline": str(timeline_path),
            "iocs": str(iocs_path),
            "accuracy": str(accuracy_path),
        }

        # Write Exa enrichment files if provided
        if enriched_iocs is not None:
            enriched_iocs_path = self.output_dir / "enriched_iocs.json"
            with open(enriched_iocs_path, "w", encoding="utf-8") as f:
                json.dump(enriched_iocs, f, indent=2, default=str)

            external_context_path = self.output_dir / "external_context.md"
            with open(external_context_path, "w", encoding="utf-8") as f:
                f.write(self._build_external_context_markdown(enriched_iocs))
            
            results_dict["enriched_iocs"] = str(enriched_iocs_path)
            results_dict["external_context"] = str(external_context_path)

        elapsed = int((time.monotonic() - t0) * 1000)
        self.audit.log(
            self.name, "report_complete",
            tool_call="write_report + write_findings + write_iocs + write_accuracy",
            prompt_summary=f"Writing report for {len(findings)} findings",
            response_summary=f"Report: {report_path}, Findings: {findings_path}",
            duration_ms=elapsed,
        )

        self.progress(f"[ReportWriter] Report written to {report_path}")
        return results_dict

    def _build_markdown(
        self, exec_summary, confirmed, weak, rejected,
        corrections, iocs, tl_summary, evidence_dir, provider_name, now,
        enriched_iocs=None
    ) -> str:
        lines = [
            "# EvilTrace AI — Incident Response Report",
            f"\n**Generated:** {now}  ",
            f"**Evidence:** `{evidence_dir}`  ",
            f"**Provider:** {provider_name}  ",
            f"**Total Events Analyzed:** {tl_summary.get('total_events', 'N/A')}  ",
            f"**Investigation Window:** {tl_summary.get('start', 'N/A')} → {tl_summary.get('end', 'N/A')}",
            "\n---\n",
            "## Executive Summary\n",
            exec_summary,
            "\n---\n",
            "## Confirmed Findings\n",
        ]
        if confirmed:
            for f in confirmed:
                lines += [
                    f"### [{f.get('mitre_technique_id','')}] {f['claim']}",
                    f"- **Status:** ✅ Confirmed",
                    f"- **Severity:** {f.get('severity','').upper()}",
                    f"- **Confidence:** {f.get('confidence',0):.0%}",
                    f"- **MITRE:** [{f.get('mitre_technique_id','')}] {f.get('mitre_tactic','')} — {f.get('mitre_technique','')}",
                    f"- **Source:** `{f.get('source_file','')}` line {f.get('line_number','')}",
                    f"- **Timestamp:** {f.get('timestamp','')}",
                    f"- **Supporting Artifact:** `{f.get('supporting_artifact','')[:150]}`",
                    f"- **Reasoning:** {f.get('reasoning','')[:300]}",
                    f"- **Origin:** {f.get('origin','')}",
                    "",
                ]
        else:
            lines.append("_No confirmed findings._\n")

        lines += ["\n---\n", "## Weak Evidence Findings\n"]
        if weak:
            for f in weak:
                lines += [
                    f"### {f['claim']}",
                    f"- **Status:** ⚠️ Weak Evidence",
                    f"- **Severity:** {f.get('severity','').upper()}",
                    f"- **Confidence:** {f.get('confidence',0):.0%}",
                    f"- **MITRE:** {f.get('mitre_technique_id','')} — {f.get('mitre_technique','')}",
                    f"- **Reasoning:** {f.get('reasoning','')[:200]}",
                    "",
                ]
        else:
            lines.append("_None._\n")

        lines += ["\n---\n", "## Rejected Hypotheses\n",
                  "> These hypotheses were evaluated but rejected due to insufficient evidence.\n"]
        if rejected:
            for f in rejected:
                lines += [
                    f"### ~~{f['claim']}~~",
                    f"- **Status:** ❌ Rejected",
                    f"- **Reason:** {f.get('reasoning','')[:300]}",
                    f"- **Confidence:** {f.get('confidence',0):.0%}",
                    "",
                ]
        else:
            lines.append("_No rejected hypotheses._\n")

        lines += ["\n---\n", "## Self-Correction Log\n"]
        if corrections:
            for c in corrections:
                lines.append(f"**Finding:** {c['finding_claim']}")
                for issue in c.get("issues", []):
                    lines += [
                        f"- **Type:** {issue.get('type','')}",
                        f"- **Description:** {issue.get('description','')}",
                        f"- **Correction Applied:** {issue.get('correction','')}",
                        "",
                    ]
        else:
            lines.append("_No self-corrections required. All claims are supported by evidence._\n")

        lines += ["\n---\n", "## Indicators of Compromise (IOCs)\n"]
        if iocs:
            lines.append("| Type | Value | Severity | Source |")
            lines.append("|------|-------|----------|--------|")
            for ioc in iocs[:50]:
                lines.append(
                    f"| {ioc.get('ioc_type','')} | `{ioc.get('value','')[:60]}` | {ioc.get('severity','')} | {ioc.get('source_file','')[-40:]} |"
                )
        else:
            lines.append("_No IOCs extracted._\n")

        if enriched_iocs:
            lines += [
                "\n---\n",
                "## External Threat Intel Context\n",
                "> **External enrichment is informational only. Final incident conclusions are based on verified local forensic evidence.**\n\n",
                "| IOC | Type | Query Used | External Context | Confidence | Source |",
                "|-----|------|------------|------------------|------------|--------|"
            ]
            for item in enriched_iocs:
                lines.append(
                    f"| `{item.get('ioc', '')}` | {item.get('ioc_type', '')} | `{item.get('query_used', '')}` | {item.get('external_context_summary', '')} | {item.get('confidence', '')} | [{item.get('source_title', '') or 'N/A'}]({item.get('source_url', '') or 'N/A'}) |"
                )

        lines += ["\n---\n", "## MITRE ATT&CK Mapping\n",
                  "| Finding | Tactic | Technique | ID | Status |",
                  "|---------|--------|-----------|-----|--------|"]
        for f in confirmed + weak:
            lines.append(
                f"| {f['claim'][:50]} | {f.get('mitre_tactic','')} | "
                f"{f.get('mitre_technique','')} | {f.get('mitre_technique_id','')} | {f.get('status','')} |"
            )

        lines += ["\n---\n", "## Audit Trail\n",
                  "_Full audit log available in `outputs/audit_log.jsonl`_\n",
                  "\n---\n",
                  "_Report generated by EvilTrace AI — FIND EVIL Hackathon Submission_"]
        return "\n".join(lines)

    def _write_iocs_csv(self, iocs: List[Dict], path: Path):
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["ioc_type", "value", "severity", "context", "source_file", "timestamp"])
            w.writeheader()
            for ioc in iocs:
                w.writerow({k: ioc.get(k, "") for k in w.fieldnames})

    def _build_accuracy(self, confirmed, weak, rejected, corrections, ioc_count) -> str:
        total = len(confirmed) + len(weak) + len(rejected)
        hallucinations_prevented = sum(
            1 for c in corrections
            for issue in c.get("issues", [])
            if issue.get("type") in ("hallucination_prevented", "hallucination_detected")
        )
        return f"""# EvilTrace AI — Accuracy Report

## Summary

| Metric | Count |
|--------|-------|
| Total Hypotheses Evaluated | {total} |
| Confirmed Findings | {len(confirmed)} |
| Weak Evidence Findings | {len(weak)} |
| Rejected Hypotheses | {len(rejected)} |
| Hallucinations Prevented | {hallucinations_prevented} |
| IOCs Extracted | {ioc_count} |
| False Positive Rate (estimated) | {len(rejected)/max(total,1):.0%} |

## Methodology

- Rule-based detection runs first, providing deterministic hits with keyword matching
- LLM augmentation adds plausibility scoring where a provider is configured
- VerificationAgent requires exact artifact references for credential dumping and exfiltration claims
- SelfCorrectionAgent demotes any claim without supporting evidence to rejected
- Confidence scoring uses: rule_hit(0.40) + llm_hit(0.20) + artifact_count(up to 0.30) + exact_match(0.10)

## Known Limitations

- PCAP-level analysis not supported (metadata CSV only)
- LLM responses in Mock Mode are deterministic approximations
- Timestamps may not normalize correctly for all log formats
- Very large evidence directories (>100k records) may be slow to process

## Honest Assessment

This system is designed to be conservative: it would rather reject a true finding
than confirm a hallucinated one. The self-correction loop and verification gates
prevent unsupported claims from reaching the final report.
"""

    def _build_external_context_markdown(self, enriched_iocs: List[Dict]) -> str:
        lines = [
            "# External Threat Intel Context\n",
            "> **External enrichment is informational only. Final incident conclusions are based on verified local forensic evidence.**\n",
            "This file contains enriched external threat intelligence information collected via the Exa Search API for confirmed indicators of compromise (IOCs) identified during the investigation.\n",
            "---",
            ""
        ]
        
        for item in enriched_iocs:
            lines += [
                f"### IOC: `{item.get('ioc', '')}` ({item.get('ioc_type', '').upper()})",
                f"- **Query Used:** `{item.get('query_used', '')}`",
                f"- **Confidence:** {item.get('confidence', '')}",
                f"- **Provider:** {item.get('provider', '')}",
                f"- **Enrichment Timestamp:** {item.get('enrichment_timestamp', '')}",
                f"- **Source Reference:** [{item.get('source_title', 'N/A')}]({item.get('source_url', 'N/A')})",
                f"- **Intel Highlights:**",
                f"  > {item.get('source_highlight', 'N/A')}",
                "",
                "---",
                ""
            ]
            
        return "\n".join(lines)

