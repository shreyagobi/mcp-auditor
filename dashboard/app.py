"""
dashboard/app.py — Streamlit dashboard (Week 5 stretch).

One-screen demo of the full pipeline: pick a test server, run the
Semantic Analyzer, see a severity-scored findings table, optionally run
a drift check against a stored baseline. This is a demo/presentation
layer over the existing agents — it adds no new detection logic, it
just makes the pipeline something you can point a camera at instead of
a terminal scroll.

Run:
    pip install streamlit --break-system-packages
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agents"))

from drift_monitor import check_drift, take_baseline  # noqa: E402
from reporting import generate_report  # noqa: E402
from semantic_analyzer import analyze_server  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SERVERS = {
    "clean_server.py": "Clean baseline (negative control)",
    "tool_poisoning_server.py": "Tool poisoning (MCP03) — obvious + paraphrased",
    "permission_overreach_server.py": "Scope creep (MCP02) — schema mismatch + typosquat",
    "token_mismanagement_server.py": "Token mismanagement (MCP01)",
    "rug_pull_server.py": "Rug-pull demo (toggle RUG_PULL env var, then drift-check)",
    "holdout_server.py": "Held-out generalization check (never used to tune prompts)",
}

SEVERITY_COLOR = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}

st.set_page_config(page_title="MCP Security Auditor", layout="wide")
st.title("MCP Security Auditor")
st.caption(
    "RAG + local LLM vulnerability scanner for Model Context Protocol servers. "
    "All inference runs locally via Ollama — nothing about the target server "
    "leaves this machine."
)

with st.sidebar:
    st.header("Target server")
    choice = st.selectbox(
        "Pick a test-bed server",
        options=list(SERVERS.keys()),
        format_func=lambda k: f"{k} — {SERVERS[k]}",
    )
    run_button = st.button("Run audit", type="primary")
    st.divider()
    st.caption(
        "Drift monitor (rug_pull_server.py only): take a baseline, "
        "flip `RUG_PULL=1` in this shell's environment, then check drift."
    )
    col1, col2 = st.columns(2)
    baseline_button = col1.button("Take baseline")
    drift_button = col2.button("Check drift")

if run_button:
    server_path = f"servers/{choice}"
    cmd = [sys.executable, str(PROJECT_ROOT / server_path)]

    with st.spinner(f"Auditing {choice} (recon → RAG retrieval → local LLM judgment)..."):
        analysis = analyze_server(cmd)
        report = generate_report(analysis)

    st.subheader(f"Results: {report['server_name']}")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Tools scanned", report["total_tools_scanned"])
    m2.metric("Flagged", report["flagged_count"])
    m3.metric("Clean", report["clean_count"])
    m4.metric("KB backend", report["kb_backend"])

    if report["findings"]:
        st.subheader("Findings")
        for f in report["findings"]:
            badge = SEVERITY_COLOR.get(f["severity"], "⚪")
            with st.expander(
                f"{badge} {f['severity'].upper()} — `{f['tool_name']}` "
                f"({f['owasp_code']})"
            ):
                st.write(f"**Category:** {f['owasp_category']}")
                st.write(f"**Confidence:** {f['confidence']}")
                st.write(f"**Reasoning:** {f['reasoning']}")
    else:
        st.success("No vulnerabilities flagged.")

    with st.expander("Raw per-tool output (debug)"):
        st.json(analysis["findings"])

if baseline_button:
    cmd = [sys.executable, str(PROJECT_ROOT / "servers" / "rug_pull_server.py")]
    with st.spinner("Taking baseline..."):
        snap = take_baseline(cmd)
    st.success(f"Baseline stored for '{snap['server_name']}' ({len(snap['tools'])} tools).")

if drift_button:
    cmd = [sys.executable, str(PROJECT_ROOT / "servers" / "rug_pull_server.py")]
    with st.spinner("Checking drift..."):
        try:
            result = check_drift(cmd)
        except FileNotFoundError as e:
            st.error(str(e))
            result = None

    if result:
        if not result["drift_detected"]:
            st.info("No drift detected — matches baseline.")
        else:
            st.warning("⚠️ Drift detected since baseline!")
            for e in result["events"]:
                st.write(f"**{e['change_type']}** — `{e['tool_name']}`")
                if e["old_description"]:
                    st.caption(f"OLD: {e['old_description'][:150]}")
                if e["new_description"]:
                    st.caption(f"NEW: {e['new_description'][:150]}")
            if result["reanalysis_of_changed_tools"]:
                st.subheader("Re-analysis of changed tools")
                for f in result["reanalysis_of_changed_tools"]:
                    badge = "🚩" if f["flagged"] else "✅"
                    st.write(f"{badge} `{f['tool_name']}` — {f['owasp_code']}: {f['reasoning']}")
