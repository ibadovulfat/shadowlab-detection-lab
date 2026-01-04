
import os
import time
import threading
from pathlib import Path
import streamlit as st
import pandas as pd
import monitor_core

PLOTLY_AVAILABLE = False
try:
    import plotly.express as px
    PLOTLY_AVAILABLE = True
except ImportError:
    px = None

PYVIS_AVAILABLE = False
try:
    from pyvis.network import Network
    PYVIS_AVAILABLE = True
except ImportError:
    Network = None

from threat_intelligence import check_ip
from mitre import get_attack_technique
import database as db
import yaml

def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

config = load_config()

APP_TITLE = "ShadowLab Defender Web Simulator"
AUTHOR_LINK = "https://www.linkedin.com/in/ibadovulfat/"
OUT_DIR = Path("shadowlab_out")
OUT_DIR.mkdir(exist_ok=True, parents=True)

st.set_page_config(page_title="ShadowLab Defender Simulator", layout="wide")
db.init_db()

if not PLOTLY_AVAILABLE:
    st.warning("Plotly not installed. Please install it for interactive charts: pip install plotly")
if not PYVIS_AVAILABLE:
    st.warning("Pyvis not installed. Please install it for network graphs: pip install pyvis")

# Header
st.image("static/shadowlab_banner.png", use_column_width=True)
st.markdown(f"### {APP_TITLE}")
st.markdown(f"**Author:** [Ulfat Ibadov]({AUTHOR_LINK}) · Ethical, lab-only telemetry & analysis. No bypass, no exploit.")

# Sidebar controls
with st.sidebar:
    st.image("static/ulfat_logo_128.png")
    st.header("Controls")
    duration = st.number_input("Run duration (seconds)", min_value=10, max_value=600, value=config.get("duration", 90), step=10)
    interval = st.number_input("Sampling interval (seconds)", min_value=0.2, max_value=5.0, value=config.get("interval", 1.0), step=0.2, format="%.1f")
    st.caption("Use small intervals for smoother charts. Be mindful of CPU usage.")
    run_button = st.button("Start Monitor")
    use_openai = st.checkbox("Enable OpenAI analysis", value=False)
    st.caption("Set OPENAI_API_KEY in your environment to enable.")
    st.markdown("---")
    
    st.subheader("Report Customization")
    report_sections = st.multiselect(
        "Select sections for PDF report",
        ["Telemetry", "Events Summary", "Detection Score", "Threat Intelligence", "Process Analysis", "Network Graph"],
        default=["Telemetry", "Events Summary", "Detection Score"]
    )
    st.markdown("---")
    st.header("About")
    
    st.subheader("Scenario Profiles")
    scenario = st.selectbox("Select profile", ["balanced","cpu-heavy","network-heavy","file-heavy","memory-heavy"])
    scenario_dur = st.number_input("Scenario duration (s)", min_value=5, max_value=300, value=30, step=5)
    gen_button = st.button("Run Scenario (lab-only)")
    st.caption("Safe load generator: CPU bursts, temp file churn, and loopback connects (no external network).")

    st.info("This tool is for research & education. It collects local telemetry and reads Windows event logs (if available). "
            "It computes a transparent 'detection likelihood' score via heuristics and an optional ML model.")


# Scenario runner (optional)
# Dynamically load ScenarioRunner
scenario_runner = None
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("scenario_profiles", "plugins/scenario_profiles.py")
    scenario_profiles_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scenario_profiles_module)
    ScenarioRunner = scenario_profiles_module.ScenarioRunner
    scenario_runner = ScenarioRunner()
except Exception as e:
    st.error(f"Could not load scenario_profiles: {e}")

if scenario_runner and "gen_button" not in st.session_state:
    st.session_state.gen_button = False
if scenario_runner and gen_button:
    st.session_state.gen_button = True
    scenario_runner.start(scenario, int(scenario_dur))
    st.success(f"Scenario '{scenario}' started for {int(scenario_dur)}s (lab-only).")

# Layout
tab_main, tab_procs, tab_history, tab_net = st.tabs(["Main Dashboard", "Process Analysis", "Historical Data", "Network Graph"])

with tab_main:
    col_tele, col_events, col_score, col_threat = st.columns([1.2, 1.2, 1.0, 1.0])

    # Data holders in session state
    if "telemetry" not in st.session_state:
        st.session_state.telemetry = []
    if "timeline_scores" not in st.session_state:
        st.session_state.timeline_scores = []
    if "event_summaries" not in st.session_state:
        st.session_state.event_summaries = None


    # Dynamically load DetectionScorer and explain_detection
    detection_scorer_class = None
    explain_detection_func = None
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("ai_engine", "plugins/detection_models/ai_engine.py")
        ai_engine_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ai_engine_module)
        detection_scorer_class = ai_engine_module.DetectionScorer
    
        spec = importlib.util.spec_from_file_location("ai_analysis", "plugins/detection_models/ai_analysis.py")
        ai_analysis_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ai_analysis_module)
        explain_detection_func = ai_analysis_module.explain_detection
    
    except Exception as e:
        st.error(f"Could not load AI detection models: {e}")
    
    def run_monitor(duration_s: int, interval_s: float):
        sampler = monitor_core.TelemetrySampler()
        scorer = detection_scorer_class() if detection_scorer_class else None
        if scorer:
            # Read event logs once at start (Windows only)
            raw_def, raw_sys = monitor_core.read_windows_events()
            def_sum = monitor_core.summarize_events(raw_def, config.get("defender_ids")) if raw_def else {"total": 0, "by_id": {}}
            sys_sum = monitor_core.summarize_events(raw_sys, config.get("sysmon_ids")) if raw_sys else {"total": 0, "by_id": {}}
            st.session_state.event_summaries = (def_sum, sys_sum)


            start = time.time()
            while time.time() - start < duration_s:
                row = sampler.sample()
                st.session_state.telemetry.append(row)
                # incremental heuristic scoring
                sc = scorer.heuristic(st.session_state.telemetry, def_sum, sys_sum)
                st.session_state.timeline_scores.append(sc["likelihood"])
                time.sleep(max(0.1, float(interval_s)))

            # Final scoring (blend ML if available)
            final = scorer.final_score(st.session_state.telemetry, def_sum, sys_sum)
        else:
            final = {"likelihood": 0.0, "parts": {}, "notes": ["DetectionScorer not loaded"]}

        # Persist artifacts
        import json
        OUT_DIR.mkdir(exist_ok=True, parents=True)
        # telemetry to CSV
        import csv
        with (OUT_DIR/"telemetry.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ts","cpu","mem_percent","proc_threads","proc_handles","open_files","tcp_conns", "bytes_sent_rate", "bytes_recv_rate", "remote_ips"])
            for r in st.session_state.telemetry:
                w.writerow([r["ts"], r["cpu"], r["mem_percent"], r["proc_threads"], r["proc_handles"] or "", r["open_files"], r["tcp_conns"], r["bytes_sent_rate"], r["bytes_recv_rate"], r.get("remote_ips", [])])
        # events
        (OUT_DIR/"events_defender.json").write_text(json.dumps({"summary": def_sum}, indent=2))
        (OUT_DIR/"events_sysmon.json").write_text(json.dumps({"summary": sys_sum}, indent=2))
        # score
        (OUT_DIR/"score.json").write_text(json.dumps(final, indent=2))

        # Save telemetry to database
        conn = db.create_connection()
        if conn:
            db.insert_telemetry(conn, st.session_state.telemetry)
            conn.close()

    if run_button:
        # clear previous
        st.session_state.telemetry = []
        st.session_state.timeline_scores = []
        st.session_state.event_summaries = None
        with st.spinner("Monitoring..."):
            run_monitor(duration, interval)
        st.success("Run complete. Scroll for results.")

    # --- Telemetry Column
    with col_tele:
        st.subheader("System Telemetry")
        if st.session_state.telemetry:
            df = pd.DataFrame(st.session_state.telemetry)
            st.dataframe(df.tail(15), use_container_width=True)

            if PLOTLY_AVAILABLE:
                # CPU chart
                fig1 = px.line(df, y="cpu", title="CPU % over time")
                st.plotly_chart(fig1, use_container_width=True)

                # Threads chart
                fig2 = px.line(df, y="proc_threads", title="Process threads over time")
                st.plotly_chart(fig2, use_container_width=True)

                # TCP connections chart
                fig3 = px.line(df, y="tcp_conns", title="Established TCP connections")
                st.plotly_chart(fig3, use_container_width=True)

                # Network traffic chart
                fig4 = px.line(df, y=["bytes_sent_rate", "bytes_recv_rate"], title="Network Traffic (bytes/sec)")
                st.plotly_chart(fig4, use_container_width=True)
            else:
                st.caption("Plotly is not available. Please install it to view interactive charts.")
        else:
            st.caption("Press **Start Monitor** to collect telemetry.")

    # --- Events Column
    with col_events:
        st.subheader("Defender & Sysmon Events (summary)")
        if st.session_state.event_summaries:
            def_sum, sys_sum = st.session_state.event_summaries

            st.write("**Windows Defender (Operational)**")
            for event, count in def_sum.get("by_id", {}).items():
                event_id = int(event.split(" ")[1])
                techniques = get_attack_technique(event_id)
                if techniques:
                    st.write(f"- {event}: {count} (ATT&CK: {', '.join(techniques)})")
                else:
                    st.write(f"- {event}: {count}")
            st.write(f"*Total: {def_sum.get('total', 0)}*")


            st.write("**Sysmon (Operational)**")
            for event, count in sys_sum.get("by_id", {}).items():
                event_id = int(event.split(" ")[1])
                techniques = get_attack_technique(event_id)
                if techniques:
                    st.write(f"- {event}: {count} (ATT&CK: {', '.join(techniques)})")
                else:
                    st.write(f"- {event}: {count}")
            st.write(f"*Total: {sys_sum.get('total', 0)}*")

        else:
            st.caption("No Windows events available (you're likely not on Windows or pywin32 is missing).")

    # --- Score Column
    with col_score:
        st.subheader("Detection Likelihood")
        if st.session_state.timeline_scores:
            if PLOTLY_AVAILABLE:
                # timeline score chart
                figS = px.line(y=st.session_state.timeline_scores, title="Likelihood timeline (0..1)")
                st.plotly_chart(figS, use_container_width=True)
            else:
                st.caption("Plotly is not available. Please install it to view interactive charts.")

            # final score
            scorer = detection_scorer_class() if detection_scorer_class else None
            if scorer:
                def_sum2, sys_sum2 = st.session_state.event_summaries if st.session_state.event_summaries else ({}, {})
                final = scorer.final_score(st.session_state.telemetry, def_sum2, sys_sum2)
            else:
                final = {"likelihood": 0.0, "parts": {}, "notes": ["DetectionScorer not loaded"]}

            
            # --- AI Threat Analysis (optional) ---
            st.session_state.use_openai = use_openai
            if st.session_state.use_openai and explain_detection_func:
                st.markdown("### 🧩 AI Threat Analysis")
                # reuse summaries
                ai_text = explain_detection_func(final, def_sum2, sys_sum2)
                st.write(ai_text)
        
            st.metric("Final Likelihood (0..1)", f"{final['likelihood']:.2f}")
            st.write("**Breakdown**")
            st.json(final.get("parts", {}))
            st.write("**Notes**")
            for n in final.get("notes", []):
                st.write("- ", n)

            st.download_button("Download score.json", data=(Path(OUT_DIR/"score.json").read_bytes() if (OUT_DIR/"score.json").exists() else b"{}"), file_name="score.json")
            
            # PDF export
            from report_export import generate_pdf
            pdf_path = generate_pdf(OUT_DIR, author="Ulfat Ibadov", sections=report_sections)
            if pdf_path:
                st.download_button("Download PDF Report", data=pdf_path.read_bytes(), file_name="ShadowLab_Report.pdf")

            st.download_button("Download telemetry.csv", data=(Path(OUT_DIR/"telemetry.csv").read_bytes() if (OUT_DIR/"telemetry.csv").exists() else b""), file_name="telemetry.csv")
        else:
            st.caption("Run the monitor to compute the score.")

    with col_threat:
        st.subheader("Threat Intelligence")
        if "checked_ips" not in st.session_state:
            st.session_state.checked_ips = {}

        if st.session_state.telemetry:
            all_ips = set()
            for r in st.session_state.telemetry:
                all_ips.update(r.get("remote_ips", []))

            for ip in all_ips:
                if ip not in st.session_state.checked_ips:
                    st.session_state.checked_ips[ip] = check_ip(ip)

            for ip, result in st.session_state.checked_ips.items():
                if result:
                    st.write(f"**{ip}**")
                    st.json(result)
        else:
            st.caption("No remote IPs to check yet.")

with tab_procs:
    st.subheader("Running Processes")
    procs_df = pd.DataFrame(monitor_core.get_all_processes())
    st.dataframe(procs_df, use_container_width=True)


with tab_history:
    st.subheader("Historical Telemetry Data")
    conn = db.create_connection()
    if conn:
        history_df = db.get_historical_data(conn)
        conn.close()
        st.dataframe(history_df, use_container_width=True)

with tab_net:
    st.subheader("Network Connection Graph")
    if PYVIS_AVAILABLE:
        net = Network(notebook=True)
        
        local_addrs = set()
        remote_addrs = set()
        
        connections = monitor_core.get_network_connections()
        
        for conn in connections:
            if conn["local_addr"] and conn["remote_addr"]:
                local_addrs.add(conn["local_addr"])
                remote_addrs.add(conn["remote_addr"])
        
        for addr in local_addrs:
            net.add_node(addr, label=addr, color="blue")
            
        for addr in remote_addrs:
            net.add_node(addr, label=addr, color="red")
            
        for conn in connections:
            if conn["local_addr"] and conn["remote_addr"]:
                net.add_edge(conn["local_addr"], conn["remote_addr"])
                
        net.show("network_graph.html")
        st.components.v1.html(open("network_graph.html", "r").read(), height=600)
    else:
        st.caption("Pyvis is not available. Please install it to view interactive network graphs.")


        
st.markdown("---")
st.caption("For research & education only. No real bypass. © 2025 Ulfat Ibadov")
