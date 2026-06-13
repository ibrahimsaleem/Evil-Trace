import pytest
import os
import sys
import shutil
import json
from pathlib import Path

# Add eviltrace to python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from providers.gemini import GeminiProvider
from providers.mock import MockProvider
from utils.parsers import parse_file
from utils.ioc_extractor import extract_iocs
from main import run_investigation
from agents.verifier import VerificationAgent
from agents.self_corrector import SelfCorrectionAgent


def test_parser():
    # Test parsing a simple CSV record
    csv_content = (
        "timestamp,host,user,event_type,command_line,src_ip,dst_ip,process,file_path\n"
        "2024-03-15T02:13:30,WORKSTATION-01,CORP\\jsmith,4104,powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0A,10.0.1.50,,powershell.exe,\n"
    )
    temp_dir = Path(__file__).parent / "temp_test"
    temp_dir.mkdir(exist_ok=True)
    temp_file = temp_dir / "temp_powershell.csv"
    with open(temp_file, "w", encoding="utf-8") as f:
        f.write(csv_content)

    try:
        records = parse_file(temp_file)
        assert len(records) == 1
        assert records[0]["host"] == "WORKSTATION-01"
        assert records[0]["user"] == "CORP\\jsmith"
        assert "encodedcommand" in records[0]["command_line"].lower()
    finally:
        if temp_dir.exists():
            shutil.rmtree(temp_dir)


def test_ioc_extractor():
    # Test extracting IOCs from records
    records = [
        {
            "raw_record": '{"DestinationIp": "203.0.113.88", "DestinationHostname": "c2.evil-domain.xyz"}',
            "source_file": "zeek.log",
            "timestamp": "2024-03-15T02:13:30",
            "dst_ip": "203.0.113.88",
            "domain": "c2.evil-domain.xyz"
        }
    ]
    iocs = extract_iocs(records)
    ioc_values = [ioc["value"] for ioc in iocs]
    assert "203.0.113.88" in ioc_values
    assert "c2.evil-domain.xyz" in ioc_values


def test_mock_investigation():
    # Run investigation in mock mode
    evidence_dir = Path(__file__).parent.parent / "sample_evidence"
    output_path = Path(__file__).parent / "temp_outputs" / "report.md"
    
    result = run_investigation(
        evidence_dir=evidence_dir,
        output_path=output_path,
        provider_name="mock",
        verbose=False
    )
    
    assert result["records"] > 0
    assert len(result["findings"]) > 0
    
    # Cleanup
    temp_out = Path(__file__).parent / "temp_outputs"
    if temp_out.exists():
        shutil.rmtree(temp_out)


def test_credential_dumping_rejection():
    # Verify credential dumping is rejected without exact artifact
    hypotheses = [
        {
            "id": "H003",
            "claim": "Credential dumping attempt via LSASS memory access or Mimikatz-family tooling",
            "category": "credential_dumping",
            "confidence": 0.6,
            "origin": "rule",
            "rule_hit": True
        }
    ]
    
    # Hits containing only process enumeration (no mimikatz/procdump)
    tool_results = {
        "credential_dumping": [
            {
                "process": "powershell.exe",
                "command_line": "Get-Process | Where-Object {$_.Name -eq 'lsass'}",
                "raw_record": "Get-Process | Where-Object {$_.Name -eq 'lsass'}",
                "source_file": "powershell_events.csv",
                "line_number": 7,
                "timestamp": "2024-03-15T02:14:50"
            }
        ]
    }
    
    provider = MockProvider()
    from agents.audit_logger import AuditLoggerAgent
    audit = AuditLoggerAgent(output_path=Path(__file__).parent / "temp_audit.jsonl")
    
    verifier = VerificationAgent(provider=provider, audit=audit)
    verified = verifier.run(hypotheses, tool_results)
    
    assert verified[0]["status"] == "rejected"
    assert "Credential dumping hypothesis rejected because no supporting LSASS dump, Mimikatz, Procdump, MiniDump, sekurlsa, or credential-access artifact was found." in verified[0]["reasoning"]
    
    corrector = SelfCorrectionAgent(provider=provider, audit=audit)
    corrections = corrector.run(verified)
    assert len(corrections) == 1
    assert corrections[0]["issues"][0]["type"] == "hallucination_prevented"
    
    # Cleanup temp audit file
    temp_audit = Path(__file__).parent / "temp_audit.jsonl"
    if temp_audit.exists():
        os.remove(temp_audit)


def test_gemini_init():
    # Test initialization and api key masking
    provider = GeminiProvider(api_key="SECRET_KEY_12345", model="gemini-2.5-flash")
    assert provider.name == "gemini"
    
    # Test sanitization function
    sanitized = provider._sanitize("Error connecting using SECRET_KEY_12345 to API")
    assert "SECRET_KEY_12345" not in sanitized
    assert "***" in sanitized


def test_output_generation():
    # Verify all 6 output files are written
    evidence_dir = Path(__file__).parent.parent / "sample_evidence"
    output_dir = Path(__file__).parent / "temp_outputs"
    output_path = output_dir / "report.md"
    
    run_investigation(
        evidence_dir=evidence_dir,
        output_path=output_path,
        provider_name="mock",
        verbose=False
    )
    
    assert (output_dir / "report.md").exists()
    assert (output_dir / "findings.json").exists()
    assert (output_dir / "audit_log.jsonl").exists()
    assert (output_dir / "timeline.json").exists()
    assert (output_dir / "iocs.csv").exists()
    assert (output_dir / "accuracy_summary.md").exists()
    
    # Cleanup
    if output_dir.exists():
        shutil.rmtree(output_dir)


def test_exa_skip_without_key():
    from agents.ioc_enrichment import IOCEnrichmentAgent
    agent = IOCEnrichmentAgent(api_key="")
    # Should skip immediately returning empty list
    results = agent.run([], {}, enabled=True)
    assert results == []


def test_exa_enrich_confirmed_only_and_no_status_change():
    from agents.ioc_enrichment import IOCEnrichmentAgent
    
    findings = [
        {
            "id": "F001",
            "claim": "Suspicious execution",
            "category": "suspicious_powershell",
            "status": "confirmed"
        },
        {
            "id": "F002",
            "claim": "Credential dumping",
            "category": "credential_dumping",
            "status": "rejected"
        },
        {
            "id": "F003",
            "claim": "Weak Exfiltration",
            "category": "exfiltration_indicators",
            "status": "weak_evidence"
        }
    ]
    
    tool_results = {
        "suspicious_powershell": [
            {
                "timestamp": "2024-03-15T02:13:30",
                "source_file": "powershell_events.csv",
                "raw_record": "powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0A",
                "command_line": "powershell.exe -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0A"
            }
        ],
        "credential_dumping": [
            {
                "timestamp": "2024-03-15T02:14:50",
                "source_file": "powershell_events.csv",
                "raw_record": "Get-Process | Where-Object {$_.Name -eq 'lsass'}",
                "command_line": "Get-Process | Where-Object {$_.Name -eq 'lsass'}"
            }
        ],
        "exfiltration_indicators": [
            {
                "timestamp": "2024-03-15T02:15:10",
                "source_file": "powershell_events.csv",
                "raw_record": "upload test.zip to 198.51.100.22",
                "command_line": "upload test.zip to 198.51.100.22"
            }
        ]
    }
    
    agent = IOCEnrichmentAgent(api_key="mock_key")
    
    # Mock the enrich_ioc method to return dummy threat-intel info
    def dummy_enrich(ioc, ioc_type):
        return {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "query_used": f"threat intelligence malicious {ioc}",
            "external_context_summary": "Known threat actor IP",
            "source_title": "ThreatIntel DB",
            "source_url": "https://threatintel.test",
            "source_highlight": "Matches IP used in campaign X",
            "confidence": "supportive",
            "enrichment_timestamp": "2024-03-15T02:16:00",
            "provider": "exa"
        }
    agent.provider.enrich_ioc = dummy_enrich
    
    # 1. By default, should only enrich confirmed findings, ignoring weak and rejected findings
    enriched_default = agent.run(findings, tool_results, enabled=True, enrich_weak=False)
    
    # Assert we only got one item (since F001 is confirmed, F002 is rejected, F003 is weak)
    assert len(enriched_default) == 1
    assert enriched_default[0]["finding_status"] == "confirmed"
    
    # 2. With enrich_weak=True, should enrich both confirmed and weak findings
    enriched_with_weak = agent.run(findings, tool_results, enabled=True, enrich_weak=True)
    assert len(enriched_with_weak) == 2
    
    statuses = [item["finding_status"] for item in enriched_with_weak]
    assert "confirmed" in statuses
    assert "weak_evidence" in statuses
    
    # Confirm finding status is not changed by enrichment
    assert findings[0]["status"] == "confirmed"
    assert findings[1]["status"] == "rejected"
    assert findings[2]["status"] == "weak_evidence"


def test_exa_key_security():
    from providers.exa import ExaProvider
    # API Key must never appear in logged exception texts or reports
    key = "EXA_SECRET_KEY_99999"
    provider = ExaProvider(api_key=key)
    
    # Verify key is masked by sanitization
    sanitized = provider._sanitize(f"Failed connection to api.exa.ai using key={key}")
    assert key not in sanitized
    assert "***" in sanitized

