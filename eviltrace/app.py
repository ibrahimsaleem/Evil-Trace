#!/usr/bin/env python3
"""EvilTrace AI — Streamlit UI."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import time
from pathlib import Path
import streamlit as st
import pandas as pd

from main import run_investigation, load_dotenv
load_dotenv()

st.set_page_config(
    page_title="EvilTrace AI — DFIR Agent",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.main-header { font-size: 2.2rem; font-weight: 800; color: #e63946; margin-bottom: 0; }
.sub-header { font-size: 1rem; color: #6c757d; margin-bottom: 1.5rem; }
.status-confirmed { color: #28a745; font-weight: 700; }
.status-weak { color: #fd7e14; font-weight: 700; }
.status-rejected { color: #dc3545; font-weight: 700; text-decoration: line-through; }
.correction-box { background: #fff3cd; border-left: 4px solid #ffc107; padding: 0.5rem 1rem; margin: 0.5rem 0; border-radius: 4px; }
.metric-box { text-align: center; padding: 1rem; border-radius: 8px; }
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## 🔍 EvilTrace AI")
    st.markdown("*Autonomous DFIR Incident Response Agent*")
    st.markdown("---")

    st.markdown("### Evidence Source")
    evidence_mode = st.radio(
        "Input mode",
        ["Sample Evidence (Demo)", "Evidence Folder Path", "Upload Files"],
        index=0,
    )

    evidence_dir = None
    uploaded_files = []

    if evidence_mode == "Sample Evidence (Demo)":
        evidence_dir = Path(__file__).parent / "sample_evidence"
        st.success(f"Using: `sample_evidence/`")
    elif evidence_mode == "Evidence Folder Path":
        folder_input = st.text_input(
            "Evidence folder path",
            placeholder="./evidence_input",
            help="Enter an absolute or relative path to your evidence directory",
        )
        if folder_input:
            p = Path(folder_input)
            if p.exists():
                evidence_dir = p
                st.success(f"Found: `{p}`")
            else:
                st.error(f"Path not found: `{folder_input}`")
    else:
        uploaded_files = st.file_uploader(
            "Upload evidence files",
            accept_multiple_files=True,
            type=["json", "csv", "log", "txt"],
            help="Upload Sysmon JSON, Zeek logs, PowerShell CSV, or auth logs",
        )
        if uploaded_files:
            upload_dir = Path("outputs/uploaded_evidence")
            upload_dir.mkdir(parents=True, exist_ok=True)
            for uf in uploaded_files:
                with open(upload_dir / uf.name, "wb") as f:
                    f.write(uf.getbuffer())
            evidence_dir = upload_dir
            st.success(f"Saved {len(uploaded_files)} file(s) to `outputs/uploaded_evidence/`")

    st.markdown("---")
    st.markdown("### LLM Provider")
    provider_name = st.selectbox(
        "Provider",
        ["mock", "gemini", "openrouter", "ollama"],
        index=0,
        help="Mock mode always works without any API key",
    )

    model_name = ""
    api_key_input = ""
    ollama_endpoint = ""

    if provider_name == "gemini":
        api_key_input = st.text_input(
            "Gemini API Key", type="password",
            help="Or set GEMINI_API_KEY environment variable",
            placeholder="AIza...",
        )
        model_name = st.text_input("Model", value="gemini-2.5-flash")
    elif provider_name == "openrouter":
        api_key_input = st.text_input(
            "OpenRouter API Key", type="password",
            help="Or set OPENROUTER_API_KEY environment variable",
            placeholder="sk-or-...",
        )
        model_name = st.text_input("Model", value="openai/gpt-4o-mini")
    elif provider_name == "ollama":
        ollama_endpoint = st.text_input("Ollama Endpoint", value="http://localhost:11434")
        model_name = st.text_input("Model", value="llama3")
    else:
        st.info("Mock Mode — deterministic, no API key required")

    st.markdown("---")
    st.markdown("### Exa IOC Enrichment (Optional)")
    enable_exa = st.checkbox(
        "Enable Exa IOC Enrichment",
        value=False,
        help="Query Exa Search API for threat-intel context on confirmed IOCs"
    )
    exa_key_input = ""
    enrich_weak = False
    if enable_exa:
        exa_key_input = st.text_input(
            "Exa API Key", type="password",
            value=os.environ.get("EXA_API_KEY", ""),
            help="Or set EXA_API_KEY environment variable",
            placeholder="exa-..."
        )
        enrich_weak = st.checkbox(
            "Enrich Weak Evidence Context",
            value=False,
            help="Query Exa Search API for IOCs in weak evidence findings as well"
        )

    st.markdown("---")
    st.markdown("### Output")
    output_dir = st.text_input("Output directory", value="outputs")

    run_btn = st.button("🚀 Run Investigation", type="primary", use_container_width=True)


st.markdown('<div class="main-header">🔍 EvilTrace AI</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">Autonomous DFIR Incident Response Agent — FIND EVIL Hackathon</div>',
    unsafe_allow_html=True,
)

if "results" not in st.session_state:
    st.session_state.results = None
if "running" not in st.session_state:
    st.session_state.running = False


if run_btn:
    if evidence_dir is None:
        st.error("Please select an evidence source.")
        st.stop()
    if not evidence_dir.exists():
        st.error(f"Evidence directory does not exist: `{evidence_dir}`")
        st.stop()

    st.session_state.running = True
    progress_placeholder = st.empty()
    log_placeholder = st.empty()

    with st.spinner("Running investigation..."):
        out_path = Path(output_dir) / "report.md"
        log_lines = []

        progress_bar = progress_placeholder.progress(0, text="Starting investigation...")

        def progress_cb(msg):
            log_lines.append(msg)
            progress_placeholder.progress(
                min(len(log_lines) / 25.0, 0.95),
                text=msg[:80] if msg else "Running..."
            )
            log_placeholder.code("\n".join(log_lines[-15:]), language=None)

        result = run_investigation(
            evidence_dir=evidence_dir,
            output_path=out_path,
            provider_name=provider_name,
            model=model_name,
            api_key=api_key_input,
            endpoint=ollama_endpoint,
            verbose=False,
            enable_exa=enable_exa,
            exa_key=exa_key_input or os.environ.get("EXA_API_KEY", ""),
            enrich_weak=enrich_weak,
        )
        st.session_state.results = result

        progress_placeholder.progress(1.0, text="Investigation complete!")
        log_placeholder.empty()
        st.success(f"Investigation complete! {len(result['findings'])} hypotheses evaluated.")
        st.session_state.running = False


if st.session_state.results:
    r = st.session_state.results
    findings = r["findings"]
    corrections = r["corrections"]
    iocs = r["iocs"]
    timeline = r["timeline"]

    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    weak = [f for f in findings if f.get("status") == "weak_evidence"]
    rejected = [f for f in findings if f.get("status") == "rejected"]

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("Evidence Records", r["records"])
    with col2:
        st.metric("Confirmed Findings", len(confirmed), delta=None)
    with col3:
        st.metric("Weak Evidence", len(weak))
    with col4:
        st.metric("Rejected", len(rejected))
    with col5:
        st.metric("IOCs Found", len(iocs))

    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
        "🔴 Findings",
        "❌ Rejected",
        "🔧 Self-Corrections",
        "⏱️ Timeline",
        "🌐 IOCs",
        "⚔️ MITRE Map",
        "📋 Audit Log",
    ])

    with tab1:
        st.subheader("Confirmed & Weak Evidence Findings")
        
        findings_table_data = [
            {
                "ID": f.get("id", ""),
                "Claim": f.get("claim", ""),
                "Status": "✅ Confirmed" if f.get("status") == "confirmed" else "⚠️ Weak Evidence",
                "Severity": f.get("severity", "").upper(),
                "Confidence": f"{f.get('confidence', 0):.0%}",
                "MITRE ID": f.get("mitre_technique_id", ""),
                "Source File": f.get("source_file", ""),
                "Line": f.get("line_number", ""),
                "Detection Source": f.get("detection_source", "rules"),
            }
            for f in confirmed + weak
        ]
        if findings_table_data:
            st.dataframe(pd.DataFrame(findings_table_data), use_container_width=True)
            st.markdown("---")

        for f in confirmed + weak:
            status = f.get("status", "")
            sev = f.get("severity", "")
            conf = f.get("confidence", 0)
            color = "green" if status == "confirmed" else "orange"
            label = "✅ CONFIRMED" if status == "confirmed" else "⚠️ WEAK EVIDENCE"
            with st.expander(f"[{f.get('mitre_technique_id','')}] {f['claim'][:80]}"):
                col_a, col_b, col_c = st.columns(3)
                with col_a:
                    st.markdown(f"**Status:** :{color}[{label}]")
                    st.markdown(f"**Severity:** `{f.get('severity','').upper()}`")
                    st.markdown(f"**Confidence:** `{conf:.0%}`")
                with col_b:
                    st.markdown(f"**MITRE Tactic:** `{f.get('mitre_tactic','')}`")
                    st.markdown(f"**Technique:** `{f.get('mitre_technique','')}`")
                    st.markdown(f"**Technique ID:** `{f.get('mitre_technique_id','')}`")
                with col_c:
                    st.markdown(f"**Source File:** `{f.get('source_file','')}`")
                    st.markdown(f"**Line:** `{f.get('line_number','')}`")
                    st.markdown(f"**Timestamp:** `{f.get('timestamp','')}`")
                if f.get("supporting_artifact"):
                    st.markdown("**Supporting Artifact:**")
                    st.code(f.get("supporting_artifact","")[:300], language=None)
                st.markdown(f"**Reasoning:** {f.get('reasoning','')[:400]}")
                st.markdown(f"**Origin:** `{f.get('origin','')}`")

        if not confirmed and not weak:
            st.info("No findings confirmed or flagged as weak evidence.")

    with tab2:
        st.subheader("Rejected Hypotheses")
        st.info(
            "These hypotheses were proposed but rejected due to insufficient evidence. "
            "They are shown here for transparency — not included in the final report."
        )
        for f in rejected:
            with st.expander(f"❌ ~~{f['claim'][:80]}~~"):
                st.markdown(f"**Confidence:** `{f.get('confidence',0):.0%}`")
                st.markdown(f"**Rejection Reason:**")
                reasoning = f.get("reasoning", "")
                if "Credential dumping" in reasoning or "LSASS" in reasoning:
                    st.error(
                        "Credential dumping hypothesis rejected because no supporting LSASS, Mimikatz, "
                        "memory dump, or credential-access artifact was found."
                    )
                elif "Exfiltration" in reasoning or "exfil" in reasoning.lower():
                    st.warning(
                        "Exfiltration hypothesis rejected: No confirmed transfer-size or destination "
                        "evidence found. Cannot confirm without upload/FTP/SCP artifact."
                    )
                elif "beaconing" in reasoning.lower() or "C2" in reasoning:
                    st.warning("C2 beaconing hypothesis rejected: Insufficient repeated-connection evidence.")
                else:
                    st.markdown(reasoning[:400])
                st.markdown(f"**MITRE:** `{f.get('mitre_technique_id','')}` — {f.get('mitre_technique','')}")

    with tab3:
        st.subheader("Self-Correction Log")
        st.info(
            "The SelfCorrectionAgent scanned all findings for hallucinations, unsupported claims, "
            "and confidence mismatches. All corrections are listed here."
        )
        if corrections:
            for c in corrections:
                for issue in c.get("issues", []):
                    st.markdown(
                        f'<div class="correction-box">'
                        f'<b>Finding:</b> {c["finding_claim"][:80]}<br>'
                        f'<b>Type:</b> <code>{issue.get("type","")}</code><br>'
                        f'<b>Description:</b> {issue.get("description","")}<br>'
                        f'<b>Correction Applied:</b> {issue.get("correction","")}'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
        else:
            st.success("No self-corrections required. All claims are supported by evidence.")

    with tab4:
        st.subheader("Investigation Timeline")
        if timeline:
            tl_df = pd.DataFrame(timeline[:500])
            cols = [c for c in ["timestamp", "host", "user", "process", "event_type", "command_line", "src_ip", "dst_ip"] if c in tl_df.columns]
            st.dataframe(tl_df[cols], use_container_width=True, height=400)
            st.caption(f"Showing {min(len(timeline),500)} of {len(timeline)} events (sorted by timestamp)")
        else:
            st.info("No timeline events with timestamps found in evidence.")

    with tab5:
        st.subheader("Indicators of Compromise")
        if iocs:
            ioc_df = pd.DataFrame(iocs)
            ioc_type_filter = st.multiselect(
                "Filter by IOC type",
                options=list(ioc_df["ioc_type"].unique()),
                default=list(ioc_df["ioc_type"].unique()),
            )
            filtered = ioc_df[ioc_df["ioc_type"].isin(ioc_type_filter)] if ioc_type_filter else ioc_df
            st.dataframe(filtered[["ioc_type", "value", "severity", "source_file", "timestamp"]], use_container_width=True)

            # Exa Enriched IOCs section
            enriched_iocs = r.get("enriched_iocs", None)
            if enriched_iocs:
                st.markdown("---")
                st.subheader("🌐 External Threat Intel Context (Exa)")
                st.warning("External enrichment is informational only. Final incident conclusions are based on verified local forensic evidence.")
                
                enriched_df = pd.DataFrame(enriched_iocs)
                cols_to_show = [
                    "ioc", "ioc_type", "confidence", "external_context_summary", 
                    "source_title", "source_url", "source_highlight"
                ]
                cols_present = [c for c in cols_to_show if c in enriched_df.columns]
                st.dataframe(enriched_df[cols_present], use_container_width=True)
        else:
            st.info("No IOCs extracted from evidence.")

    with tab6:
        st.subheader("MITRE ATT&CK Mapping")
        mitre_data = [
            {
                "Claim": f["claim"][:60],
                "Status": f["status"],
                "Tactic": f.get("mitre_tactic", ""),
                "Technique": f.get("mitre_technique", ""),
                "ID": f.get("mitre_technique_id", ""),
                "Confidence": f"{f.get('confidence',0):.0%}",
            }
            for f in findings
            if f.get("mitre_technique_id")
        ]
        if mitre_data:
            mitre_df = pd.DataFrame(mitre_data)
            st.dataframe(mitre_df, use_container_width=True)
        else:
            st.info("No MITRE mappings available.")

    with tab7:
        st.subheader("Audit Trail")
        audit_path = Path(output_dir) / "audit_log.jsonl"
        if audit_path.exists():
            entries = []
            with open(audit_path, encoding="utf-8") as f:
                for line in f:
                    try:
                        entries.append(json.loads(line.strip()))
                    except Exception:
                        pass
            if entries:
                audit_df = pd.DataFrame(entries)
                display_cols = [c for c in ["event_timestamp", "agent", "action", "step", "tool_call", "provider", "model", "status", "error", "response_summary", "duration_ms", "cost_estimate"] if c in audit_df.columns]
                st.dataframe(audit_df[display_cols], use_container_width=True, height=400)
                st.caption(f"{len(entries)} audit entries")
        else:
            st.info("No audit log found yet. Run an investigation first.")

    st.markdown("---")
    st.subheader("Download Outputs")
    col_dl1, col_dl2, col_dl3, col_dl4 = st.columns(4)

    report_path = Path(output_dir) / "report.md"
    findings_path = Path(output_dir) / "findings.json"
    audit_path = Path(output_dir) / "audit_log.jsonl"
    iocs_path = Path(output_dir) / "iocs.csv"

    with col_dl1:
        if report_path.exists():
            with open(report_path, encoding="utf-8") as f:
                st.download_button("📄 Download Report (MD)", f.read(), "eviltrace_report.md", "text/markdown")
    with col_dl2:
        if findings_path.exists():
            with open(findings_path, encoding="utf-8") as f:
                st.download_button("📊 Download Findings (JSON)", f.read(), "findings.json", "application/json")
    with col_dl3:
        if audit_path.exists():
            with open(audit_path, encoding="utf-8") as f:
                st.download_button("📋 Download Audit Log (JSONL)", f.read(), "audit_log.jsonl", "text/plain")
    with col_dl4:
        if iocs_path.exists():
            with open(iocs_path, encoding="utf-8") as f:
                st.download_button("🌐 Download IOCs (CSV)", f.read(), "iocs.csv", "text/csv")

else:
    st.markdown("---")
    st.info(
        "👈 Select evidence source and click **Run Investigation** to start.\n\n"
        "- **Sample Evidence (Demo)**: Uses built-in realistic synthetic logs\n"
        "- **Evidence Folder Path**: Point to your own DFIR evidence directory\n"
        "- **Upload Files**: Upload Sysmon JSON, Zeek logs, PowerShell CSV, auth logs\n\n"
        "No API key required — Mock Mode works out of the box."
    )

    with st.expander("Supported Evidence Types"):
        st.markdown("""
| Type | Format | Fields Extracted |
|------|--------|-----------------|
| Sysmon | JSON | process, commandline, network, file, hash |
| Zeek | TSV .log | src/dst IP, proto, service, bytes |
| PowerShell | CSV | commandline, scriptblock, user, host |
| Linux Auth | syslog | user, process, source IP, action |
| Windows Events | JSON/CSV | eventid, user, host, message |
| Generic | JSON/CSV/TXT | best-effort field extraction |
        """)

    with st.expander("Provider Setup Guide"):
        st.markdown("""
**Mock Mode** (default): Works immediately, no configuration needed.

**Gemini**: Enter your API key in the sidebar, or set `GEMINI_API_KEY` env var.

**OpenRouter**: Enter your API key in the sidebar, or set `OPENROUTER_API_KEY` env var.
Supports hundreds of models including GPT-4o, Claude 3.5, Mixtral.

**Ollama**: Run locally with `ollama serve`. Supports llama3, mistral, deepseek, etc.
Set the endpoint if running on a different host.
        """)
