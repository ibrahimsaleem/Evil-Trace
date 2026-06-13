#!/usr/bin/env python3
"""EvilTrace AI — CLI entry point."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
import json
import time
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box

from providers.mock import MockProvider
from providers.gemini import GeminiProvider
from providers.openrouter import OpenRouterProvider
from providers.ollama import OllamaProvider
from agents.audit_logger import AuditLoggerAgent
from agents.collector import EvidenceCollectorAgent
from agents.tool_runner import ToolRunnerAgent
from agents.hypothesis import HypothesisAgent
from agents.verifier import VerificationAgent
from agents.self_corrector import SelfCorrectionAgent
from agents.reporter import ReportWriterAgent
from utils.ioc_extractor import extract_iocs
from utils.timeline import build_timeline
from utils.database import query_all_findings, query_all_iocs

console = Console()


def get_provider(provider_name: str, model: str = "", api_key: str = "", endpoint: str = ""):
    name = provider_name.lower()
    if name == "gemini":
        return GeminiProvider(api_key=api_key, model=model or "gemini-2.5-flash")
    if name == "openrouter":
        return OpenRouterProvider(api_key=api_key, model=model or "openai/gpt-4o-mini")
    if name == "ollama":
        return OllamaProvider(endpoint=endpoint or "http://localhost:11434", model=model or "llama3")
    return MockProvider()


def run_investigation(
    evidence_dir: Path,
    output_path: Path,
    provider_name: str = "mock",
    model: str = "",
    api_key: str = "",
    endpoint: str = "",
    verbose: bool = True,
    enable_exa: bool = False,
    exa_key: str = "",
    enrich_weak: bool = False,
) -> dict:
    output_dir = output_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    logs = []

    def progress(msg: str):
        logs.append(msg)
        if verbose:
            console.print(f"[dim]{msg}[/dim]")

    provider = get_provider(provider_name, model, api_key, endpoint)
    progress(f"[EvilTrace] Provider: {provider.name}")

    audit = AuditLoggerAgent(output_path=output_dir / "audit_log.jsonl")
    audit.provider = provider.name
    audit.model = model or getattr(provider, "_model", "mock")
    audit.log("EvilTrace", "start", prompt_summary=f"Starting investigation of {evidence_dir}")

    collector = EvidenceCollectorAgent(audit=audit, progress_cb=progress)
    records = collector.run(evidence_dir)

    tool_runner = ToolRunnerAgent(audit=audit, progress_cb=progress)
    tool_results = tool_runner.run(records)

    hyp_agent = HypothesisAgent(provider=provider, audit=audit, progress_cb=progress)
    hypotheses = hyp_agent.run(records, tool_results)

    verifier = VerificationAgent(provider=provider, audit=audit, progress_cb=progress)
    findings = verifier.run(hypotheses, tool_results)

    corrector = SelfCorrectionAgent(provider=provider, audit=audit, progress_cb=progress)
    corrections = corrector.run(findings)

    iocs = extract_iocs(records)
    timeline = build_timeline(records)

    # Exa IOC Enrichment Agent (Optional)
    from agents.ioc_enrichment import IOCEnrichmentAgent
    enrichment_agent = IOCEnrichmentAgent(api_key=exa_key, progress_cb=progress)
    enriched_iocs = enrichment_agent.run(findings, tool_results, enabled=enable_exa, enrich_weak=enrich_weak)

    reporter = ReportWriterAgent(
        provider=provider, audit=audit,
        output_dir=output_dir, progress_cb=progress
    )
    output_files = reporter.run(
        findings, corrections, iocs, timeline,
        str(evidence_dir), provider.name,
        enriched_iocs=enriched_iocs if enable_exa and enrichment_agent.provider.is_available() else None
    )

    fallback_reason = getattr(provider, "_fallback_reason", "")
    if fallback_reason:
        progress(f"[Warning] LLM provider failed, falling back to mock mode. Reason: {fallback_reason}")
        audit.log(
            "EvilTrace", "provider_fallback",
            prompt_summary="Provider Check",
            response_summary=f"Fallback to Mock Mode. Reason: {fallback_reason}",
            status="fallback_triggered",
            error=fallback_reason
        )

    audit.log(
        "EvilTrace", "complete",
        response_summary=f"Investigation complete. {len(findings)} findings, {len(iocs)} IOCs.",
    )

    if str(output_path) != str(output_dir / "report.md"):
        import shutil
        shutil.copy(output_dir / "report.md", output_path)

    return {
        "records": len(records),
        "findings": findings,
        "corrections": corrections,
        "iocs": iocs,
        "timeline": timeline,
        "output_files": output_files,
        "logs": logs,
        "enriched_iocs": locals().get("enriched_iocs", None),
    }


def print_summary(result: dict):
    findings = result["findings"]
    confirmed = [f for f in findings if f["status"] == "confirmed"]
    weak = [f for f in findings if f["status"] == "weak_evidence"]
    rejected = [f for f in findings if f["status"] == "rejected"]

    console.print("\n[bold cyan]=== EvilTrace AI - Investigation Summary ===[/bold cyan]")
    console.print(f"  Evidence Records Analyzed: [bold]{result['records']}[/bold]")
    console.print(f"  Confirmed Findings:        [bold green]{len(confirmed)}[/bold green]")
    console.print(f"  Weak Evidence:             [bold yellow]{len(weak)}[/bold yellow]")
    console.print(f"  Rejected Hypotheses:       [bold red]{len(rejected)}[/bold red]")
    console.print(f"  IOCs Extracted:            [bold]{len(result['iocs'])}[/bold]")
    console.print(f"  Self-Corrections:          [bold]{len(result['corrections'])}[/bold]")

    if confirmed:
        table = Table(title="Confirmed Findings", box=box.SIMPLE_HEAD)
        table.add_column("ID", style="cyan", width=5)
        table.add_column("Claim", style="white", width=60)
        table.add_column("Severity", width=10)
        table.add_column("Confidence", width=10)
        table.add_column("MITRE ID", width=12)
        for f in confirmed:
            sev = f.get("severity", "").upper()
            color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow", "LOW": "green"}.get(sev, "white")
            table.add_row(
                f.get("id", ""),
                f["claim"][:58],
                f"[{color}]{sev}[/{color}]",
                f"{f.get('confidence',0):.0%}",
                f.get("mitre_technique_id", ""),
            )
        console.print(table)

    if rejected:
        console.print("\n[bold red]Rejected Hypotheses:[/bold red]")
        for f in rejected:
            console.print(f"  x [strikethrough]{f['claim'][:70]}[/strikethrough]")
            reason = f.get("reasoning", "")
            if "Credential dumping" in reason or "LSASS" in reason:
                console.print(
                    "    -> [italic red]Credential dumping hypothesis rejected because no supporting "
                    "LSASS dump, Mimikatz, Procdump, MiniDump, sekurlsa, or credential-access artifact was found.[/italic red]"
                )

    console.print("\n[bold]Output Files:[/bold]")
    for k, v in result["output_files"].items():
        console.print(f"  {k}: [dim]{v}[/dim]")


def load_dotenv():
    dotenv_path = Path(__file__).parent.parent / ".env"
    if not dotenv_path.exists():
        dotenv_path = Path(".env")
    if dotenv_path.exists():
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip("'\"")
                    os.environ[key] = val


def main():
    load_dotenv()
    parser = argparse.ArgumentParser(
        description="EvilTrace AI - Autonomous DFIR Incident Response Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --evidence ./sample_evidence --output outputs/report.md
  python main.py --evidence ./evidence_input --output report.md --provider mock
  python main.py --evidence ./evidence_input --output report.md --provider gemini --model gemini-2.5-flash
  python main.py --evidence ./evidence_input --output report.md --provider openrouter --model openai/gpt-4o-mini
  python main.py --evidence ./evidence_input --output report.md --provider ollama --model llama3
        """,
    )
    parser.add_argument("--evidence", required=True, help="Path to evidence directory")
    parser.add_argument("--output", default="outputs/report.md", help="Output report path")
    parser.add_argument("--provider", default="mock", choices=["mock", "gemini", "openrouter", "ollama"])
    parser.add_argument("--model", default="", help="LLM model name")
    parser.add_argument("--api-key", default="", help="API key (use env var instead for security)")
    parser.add_argument("--endpoint", default="", help="Ollama endpoint URL")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    parser.add_argument("--enable-exa", action="store_true", help="Enable Exa IOC threat intelligence enrichment")
    parser.add_argument("--skip-enrichment", action="store_true", help="Force skip threat intelligence enrichment")
    parser.add_argument("--enrich-weak-context", action="store_true", help="Enable Exa threat intelligence enrichment for weak evidence findings")
    args = parser.parse_args()

    evidence_dir = Path(args.evidence)
    if not evidence_dir.exists():
        console.print(f"[red]ERROR: Evidence directory not found: {evidence_dir}[/red]")
        sys.exit(1)

    output_path = Path(args.output)
    api_key = args.api_key or os.environ.get("GEMINI_API_KEY", "") or os.environ.get("OPENROUTER_API_KEY", "")

    console.print("[bold cyan]EvilTrace AI[/bold cyan] - Starting Investigation")
    console.print(f"  Evidence: [dim]{evidence_dir}[/dim]")
    console.print(f"  Provider: [dim]{args.provider}[/dim]")

    enable_exa = args.enable_exa and not args.skip_enrichment
    exa_key = os.environ.get("EXA_API_KEY", "")
    enrich_weak = args.enrich_weak_context

    result = run_investigation(
        evidence_dir=evidence_dir,
        output_path=output_path,
        provider_name=args.provider,
        model=args.model,
        api_key=api_key,
        endpoint=args.endpoint,
        verbose=not args.quiet,
        enable_exa=enable_exa,
        exa_key=exa_key,
        enrich_weak=enrich_weak,
    )
    print_summary(result)


if __name__ == "__main__":
    main()
