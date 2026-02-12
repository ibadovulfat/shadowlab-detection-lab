
import os
import time
import threading
from pathlib import Path
import streamlit as st
import pandas as pd
import psutil
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

from threat_intelligence import check_ip, scan_process
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

# Custom CSS for Cleaner Dark Theme
st.markdown("""
<style>
    /* Global font styles */
    .stApp {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    
    /* Metrics and headers */
    h1, h2, h3 {
        color: #e0e0e0; 
    }
    
    /* Buttons */
    .stButton>button {
        border-radius: 4px;
        border: 1px solid #444;
        background-color: #2b2b2b;
        color: #ddd;
    }
    .stButton>button:hover {
        border-color: #0078d4;
        color: #fff;
    }

    /* Process Table styling */
    [data-testid="stDataFrame"] {
        border: 1px solid #333;
    }
    
    /* Success/Error messages */
    .stAlert {
        border-radius: 4px;
    }
</style>
""", unsafe_allow_html=True)

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
tab_main, tab_procs, tab_tree, tab_persistence, tab_deception, tab_ransom, tab_netwar, tab_fleet, tab_history, tab_net = st.tabs(["Main Dashboard", "Process Analysis", "Process Tree", "Persistence", "Deception", "Ransomware", "⚔️ Net Warfare", "Fleet Manager", "Historical Data", "Network Graph"])

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
                try:
                    event_id = int(event.split(" ")[1])
                except:
                    event_id = 0

                techniques = get_attack_technique(event_id)
                if techniques:
                    st.write(f"- {event}: {count} (ATT&CK: {', '.join(techniques)})")
                else:
                    st.write(f"- {event}: {count}")
            st.write(f"*Total: {def_sum.get('total', 0)}*")


            st.write("**Sysmon (Operational)**")
            for event, count in sys_sum.get("by_id", {}).items():
                try:
                    event_id = int(event.split(" ")[1])
                except:
                    event_id = 0
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
    st.subheader("Process Analysis & Scanning")
    
    # VirusTotal Integration
    vt_api_key = st.text_input("VirusTotal API Key", value=config.get("virustotal_api_key", ""), type="password", key="vt_api_key_input")
    
    if "vt_scan_results" not in st.session_state:
        st.session_state.vt_scan_results = {}

    # AI Anomaly Detection
    with st.expander("🧠 AI Anomaly Detection (Statistical)"):
        st.caption("Detects processes acting as outliers (Z-Score > 3) compared to the system baseline.")
        if st.button("Run Anomaly Detection"):
            try:
                import plugins.detection_models.anomaly as anomaly_model
                detector = anomaly_model.StatisticalAnomalyDetector()
                
                # Get fresh data
                current_procs = monitor_core.get_all_processes()
                detector.train(current_procs)
                anomalies = detector.detect(current_procs)
                
                if anomalies:
                    st.warning(f"Detected {len(anomalies)} anomalous processes.")
                    st.dataframe(pd.DataFrame(anomalies)[['pid', 'name', 'cpu_percent', 'memory_percent', 'anomaly_reasons']])
                else:
                    st.success("No statistical anomalies detected based on current baseline.")
            except ImportError:
                st.error("Missing dependencies for AI model (pandas/numpy).")
            except Exception as e:
                st.error(f"AI Check Failed: {e}")


    # Initialize or Refresh Process Snapshot
    if "process_snapshot" not in st.session_state:
        st.session_state.process_snapshot = monitor_core.get_all_processes()

    # Controls: Refresh & Bulk Scan
    col_ctrl1, col_ctrl2 = st.columns([1, 4])
    with col_ctrl1:
        if st.button("🔄 Refresh List"):
            st.session_state.process_snapshot = monitor_core.get_all_processes()
            st.rerun()

    with col_ctrl2:
        col_scan_btn, col_premium = st.columns([2, 2])
        with col_scan_btn:
             scan_all = st.button("🚀 Scan ALL Processes")
        with col_premium:
             is_premium = st.checkbox("I have a Premium API Key (Faster)")

        if scan_all:
            if not vt_api_key:
                st.error("API Key needed")
            else:
                snapshot = st.session_state.process_snapshot or []
                total_procs = len(snapshot)
                
                # Progress UI
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                with st.status("Batch Scanning All Processes...", expanded=True) as status:
                    for i, p in enumerate(snapshot):
                        # Calculate progress
                        pct = (i + 1) / total_procs
                        progress_bar.progress(pct)
                        status_text.text(f"Scanning {i+1}/{total_procs}: {p['name']}")
                        
                        # Check if already scanned to save API calls
                        if p['pid'] not in st.session_state.vt_scan_results:
                            status.write(f"Scanning {p['name']} ({p['pid']})...")
                            res = scan_process(p, vt_api_key)
                            st.session_state.vt_scan_results[p['pid']] = res
                            
                            # Rate limiting
                            if not is_premium:
                                time.sleep(15) 
                        
                    status.update(label="Full Scan Complete!", state="complete", expanded=False)
                st.success("All processes scanned.")
                st.rerun()
    
    # Prepare Dataframe from Snapshot
    procs = st.session_state.process_snapshot
    procs_df = pd.DataFrame(procs)
    
    # If standard columns available, sort by CPU
    if 'cpu_percent' in procs_df.columns:
        procs_df.sort_values(by='cpu_percent', ascending=False, inplace=True)
    
    # Reset index so that selection indices match row position 0..N
    procs_df = procs_df.reset_index(drop=True)

    st.markdown("### Process List")
    st.caption(f"Showing {len(procs_df)} processes (Snapshot). Click 'Refresh' to update.")
    
    # Display table with selection
    # Key is static so table state is preserved unless explicit refresh
    event = st.dataframe(
        procs_df,
        use_container_width=True,
        on_select="rerun",
        selection_mode="single-row",
        key="proc_table_snapshot"
    )

    selected_rows = event.selection.rows
    if selected_rows:
        selected_index = selected_rows[0]
        
        # Safety check
        if selected_index < len(procs_df):
            selected_proc = procs_df.iloc[selected_index]
            pid = int(selected_proc['pid']) # type: ignore
            pname = str(selected_proc['name']) # type: ignore

            with st.container(border=True):
                st.markdown(f"#### Target: `{pname}`")
                c_info, c_scan = st.columns([3, 1])
                
                with c_info:
                    st.write(f"**PID:** {pid} | **CPU:** {selected_proc.get('cpu_percent')}%")
                    st.write(f"**Path:** `{selected_proc.get('exe', 'N/A')}`")

                with c_scan:
                    # Check existing result
                    existing_res = st.session_state.vt_scan_results.get(pid)
                    
                    if existing_res:
                         if "error" in existing_res:
                              st.error("Scan Error")
                         elif existing_res.get("result", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0:
                              st.error("⚠️ Malicious")
                         else:
                              st.success("✅ Clean")
                    
                    # Scan Button
                    btn_label = "Rescan" if existing_res else "Scan Now"
                    if st.button(btn_label, key=f"btn_scan_{pid}"):
                         if not vt_api_key:
                             st.error("Enter API Key above")
                         else:
                             with st.spinner(f"Scanning {pname}..."):
                                 # Use the selected row data directly
                                 proc_dict = selected_proc.to_dict()
                                 scan_res = scan_process(proc_dict, vt_api_key)
                                 st.session_state.vt_scan_results[pid] = scan_res
                                 st.rerun()

                    with st.expander("📦 Internals (Handles & DLLs)"):
                        if st.button("Load Internals", key=f"btn_internals_{pid}"):
                            try:
                                import plugins.internals as proc_internals
                                
                                # Handles
                                handles = proc_internals.get_process_handles(pid)
                                st.markdown(f"**Open Handles ({len(handles)})**")
                                if handles:
                                    st.dataframe(pd.DataFrame(handles), use_container_width=True)
                                else:
                                    st.info("No handles visible (Permission denied?).")
                                    
                                # Libs
                                libs = proc_internals.get_process_libs(pid)
                                st.markdown(f"**Loaded Modules ({len(libs)})**")
                                if libs:
                                    st.dataframe(pd.DataFrame(libs), use_container_width=True)
                                else:
                                    st.info("No modules visible.")
                                    
                            except ImportError:
                                st.error("Internals plugin failed.")
                            except Exception as e:
                                st.error(f"Scan failed: {e}")

                    with st.expander("🧵 String Inspector (Disk Analysis)"):
                        st.caption("Extracts printable text from the binary file. Mimics memory limits.")
                        search_term = st.text_input("Filter Strings (e.g. 'http', 'password')", key=f"str_search_{pid}")
                        
                        if st.button("Extract Strings", key=f"btn_strings_{pid}"):
                            try:
                                import plugins.strings_analyser as sa
                                exe = selected_proc.get('exe')
                                if exe:
                                    with st.spinner(f"Analyzing {os.path.basename(exe)}..."):
                                        all_strings = sa.extract_strings(exe)
                                        
                                        # Display stats
                                        st.write(f"Total Strings Found: {len(all_strings)}")
                                        
                                        # Filter
                                        if search_term:
                                            filtered = [s for s in all_strings if search_term.lower() in s.lower()]
                                            st.write(f"Matches for '{search_term}': {len(filtered)}")
                                            st.dataframe(filtered, use_container_width=True, hide_index=True)
                                        else:
                                            # Show preview of first 100 interesting ones or just head
                                            st.dataframe(all_strings[:500], use_container_width=True, hide_index=True)
                                else:
                                    st.error("No executable path available.")
                            except Exception as e:
                                st.error(f"String analysis failed: {e}")

                    # YARA Scan Button
                    if st.button("🧬 Deep Scan (YARA)", key=f"btn_yara_{pid}"):
                        try:
                            import plugins.yara_scanner as ys
                            if not ys.YARA_AVAILABLE:
                                st.error("YARA not installed. `pip install yara-python`")
                            else:
                                rules = ys.compile_rules()
                                if not rules:
                                    st.warning("No rules found or compile error.")
                                else:
                                    exe_path = selected_proc.get('exe')
                                    if exe_path and os.path.exists(exe_path):
                                        matches = ys.scan_file(exe_path, rules)
                                        if matches:
                                           st.error(f"YARA Matches: {', '.join(matches)}")
                                        else:
                                           st.success("No YARA rule matches found.")
                                    else:
                                        st.warning("Executable path not accessible.")
                        except ImportError:
                             st.error("YARA module import failed.")

                    # Sandbox Trace Button
                    if st.button("🧪 Sandbox Trace (5s)", key=f"btn_trace_{pid}", help="Monitor file/network activity for 5 seconds."):
                        try:
                            import plugins.sandbox as sandbox_tracer
                            st.info(f"Tracing PID {pid} for 5 seconds... Do something in the app/process if possible.")
                            
                            with st.spinner("Tracing active syscalls (Simulated)..."):
                                tracer = sandbox_tracer.ProcessTracer(pid)
                                trace_res = tracer.trace(duration=5)
                                
                                if "error" in trace_res:
                                    st.error(trace_res['error'])
                                else:
                                    events = trace_res.get("events", [])
                                    if events:
                                        st.success(f"Captured {len(events)} events.")
                                        st.dataframe(pd.DataFrame(events), use_container_width=True)
                                    else:
                                        st.info("No activity detected during trace window (Process is idle).")
                        except Exception as e:
                            st.error(f"Trace failed: {e}")


                    # Response Actions
                    st.markdown("---")
                    st.subheader("🛡️ Response Actions")
                    c_resp1, c_resp2, c_resp3 = st.columns(3)
                    
                    with c_resp1:
                        if st.button("⏸️ Suspend", key=f"btn_suspend_{pid}", help="Freeze the process to stop activity but keep in memory."):
                            try:
                                p = psutil.Process(pid)
                                p.suspend()
                                st.success(f"suspended PID {pid}")
                                
                                # Log action
                                conn_log = db.create_connection()
                                db.log_response_action(conn_log, "SUSPEND", pid, pname, "User initiated suspend")
                                conn_log.close()
                                
                            except Exception as e:
                                st.error(f"Failed: {e}")
                    
                    with c_resp2:
                        if st.button("▶️ Resume", key=f"btn_resume_{pid}", help="Unfreeze the process."):
                            try:
                                p = psutil.Process(pid)
                                p.resume()
                                st.success(f"Resumed PID {pid}")
                                
                                # Log action
                                conn_log = db.create_connection()
                                db.log_response_action(conn_log, "RESUME", pid, pname, "User initiated resume")
                                conn_log.close()
                                
                            except Exception as e:
                                st.error(f"Failed: {e}")
                    
                    with c_resp3:
                        if st.button("💀 Kill", key=f"btn_kill_{pid}", type="primary", help="Terminate the process immediately."):
                            try:
                                p = psutil.Process(pid)
                                p.kill()
                                st.success(f"Killed PID {pid}")
                                
                                # Log action
                                conn_log = db.create_connection()
                                db.log_response_action(conn_log, "KILL", pid, pname, "User initiated kill")
                                conn_log.close()
                                
                                # Update snapshot so it disappears
                                if "process_snapshot" in st.session_state:
                                    st.session_state.process_snapshot = [
                                        proc for proc in st.session_state.process_snapshot 
                                        if proc['pid'] != pid
                                    ]
                                time.sleep(1)
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed: {e}")


                # Show detailed JSON if result exists
                if existing_res:
                    with st.expander("Raw Scan Results"):
                        st.json(existing_res)




with tab_tree:
    st.subheader("Process Lineage Tree (Interactive)")
    st.markdown("Visualizing parent-child relationships using PyVis. Zoom and drag to explore.")
    
    if st.button("Generate Process Tree"):
        with st.spinner("Building process tree..."):
             procs = monitor_core.get_all_processes()
             
             try:
                 from pyvis.network import Network
                 import streamlit.components.v1 as components
                 
                 # Initialize network
                 net = Network(height='600px', width='100%', bgcolor='#222222', font_color='white', directed=True)
                 net.force_atlas_2based()
                 
                 # Data prep
                 proc_map = {p['pid']: p for p in procs}
                 
                 # Priority filtering (top CPU + suspicious)
                 interesting_names = ['cmd.exe', 'powershell.exe', 'python', 'bash', 'sh', 'nc', 'netcat']
                 priority_pids = [p['pid'] for p in procs if any(n in p['name'].lower() for n in interesting_names) or p.get('cpu_percent', 0) > 0.1]
                 
                 nodes_to_draw = set(priority_pids)
                 queue = list(priority_pids)
                 while queue:
                     current_pid = queue.pop(0)
                     if current_pid in proc_map:
                         ppid = proc_map[current_pid].get('ppid')
                         if ppid and ppid in proc_map and ppid not in nodes_to_draw:
                             nodes_to_draw.add(ppid)
                             queue.append(ppid)
                 
                 # Build graph
                 for pid in nodes_to_draw:
                     p = proc_map.get(pid)
                     if not p: continue
                     
                     label = f"{p['name']}\n({pid})"
                     title = f"PID: {pid}\nPath: {p.get('exe', 'N/A')}\nCPU: {p.get('cpu_percent')}%"
                     
                     color = '#97c2fc' # default blue
                     if any(n in p['name'].lower() for n in interesting_names):
                         color = '#ff7f7f' # red for suspicious
                     
                     net.add_node(pid, label=label, title=title, color=color, shape='box')
                     
                     ppid = p.get('ppid')
                     if ppid and ppid in nodes_to_draw:
                        net.add_edge(ppid, pid, color='#aaaaaa')
                 
                 # Save and render
                 # Pyvis requires writing to file
                 tmp_path = "process_tree.html"
                 net.save_graph(tmp_path)
                 
                 # Read back and display
                 with open(tmp_path, 'r', encoding='utf-8') as f:
                     html_content = f.read()
                 
                 components.html(html_content, height=600, scrolling=True)
                 st.caption(f"Showing {len(nodes_to_draw)} relevant nodes.")
                 
             except ImportError:
                 st.error("PyVis library not found. Installing... Please refresh page after install finishes.")
             except Exception as e:
                 st.error(f"Error visualizing tree: {e}")



with tab_persistence:
    st.subheader("Persistence Mechanisms")
    st.markdown("Scanning for programs configured to start automatically (LaunchAgents, Daemons, Cron).")

    if st.button("Scan Persistence"):
        try:
             import plugins.persistence as persistence_scanner
             import importlib
             importlib.reload(persistence_scanner) # ensure fresh load during dev
             
             items = persistence_scanner.get_persistence_items()
             
             if not items:
                 st.info("No common persistence mechanisms found (or OS not fully supported).")
             else:
                 st.success(f"Found {len(items)} persistence items.")
                 
                 # Convert to DataFrame for better view
                 p_df = pd.DataFrame(items)
                 st.dataframe(
                     p_df, 
                     column_config={
                         "content_preview": st.column_config.TextColumn("Details/Content", help="Preview of the configuration file")
                     },
                     use_container_width=True
                 )
                 
                 st.markdown("### Analysis")
                 for item in items:
                     # Simple heuristics for highlighting
                     name = item['name'].lower()
                     path = item['path'].lower()
                     if "update" not in name and "helper" not in name and "google" not in name and "adobe" not in name:
                         st.warning(f"⚠️ **Review required**: `{item['name']}` at `{item['path']}`")

        except Exception as e:
            st.error(f"Error loading persistence plugin: {e}")


with tab_deception:
    st.subheader("🕸️ Deception Technology (Honeypot)")
    st.markdown("Place a 'bait' file. If any process reads it, you know you are compromised.")
    
    import plugins.honeypot as honey
    hp = honey.FileHoneypot()
    
    col_d1, col_d2 = st.columns(2)
    
    with col_d1:
        st.markdown(f"**Target File:** `{hp.filepath}`")
        st.info("This file contains fake credentials. No legitimate user should ever open it.")
        
        if st.button("Deploy Bait File"):
            ok, msg = hp.deploy()
            if ok:
                st.success(msg)
                # Store baseline time
                st.session_state.honey_baseline = hp.last_access
            else:
                st.error(f"Deploy failed: {msg}")

        if st.button("Remove Bait"):
            hp.cleanup()
            if "honey_baseline" in st.session_state:
                del st.session_state.honey_baseline
            st.success("Bait removed.")

    with col_d2:
        st.markdown("### Status Monitor")
        
        if hp.filepath.exists():
            st.success("🟢 Active")
            
            # Check for access
            # We need to manually compare against session state baseline because 
            # re-instantiating the class resets its internal 'last_access' to 0
            current_atime = 0
            try:
                current_atime = os.path.getatime(hp.filepath)
            except: 
                pass
            
            baseline = st.session_state.get("honey_baseline", 0)
            
            if baseline > 0 and current_atime > baseline + 0.1:
                st.error("🚨 ALERT: Bait file accessed!")
                st.markdown(f"**Access Time:** {time.ctime(current_atime)}")
                st.caption("A process (or user) read this file. Investigate immediately!")
                
                # Option to acknowledge/reset
                if st.button("Acknowledge Alert (Reset)"):
                    st.session_state.honey_baseline = current_atime
                    st.rerun()
            else:
                st.info("🛡️ No unauthorized access detected.")
                if st.button("Check Now"):
                    st.rerun()
        else:
            st.warning("⚪ Inactive (Not Deployed)")



with tab_ransom:
    st.subheader("🦜 Ransomware Canary (Honeypot Files)")
    st.markdown("Deploys hidden `.docx`, `.xlsx` files. If they are modified/encrypted, it triggers an alert.")
    
    import plugins.canary as r_canary
    
    # We use a simplified check for Streamlit (Polling instead of Async Watchdog for UI stability)
    # Ideally, a background thread would update a status file.
    
    if st.button("Deploy Canary Files"):
        try:
            canary = r_canary.RansomwareCanary(lambda x: print(x))
            files = canary.deploy()
            st.session_state.canary_active = True
            st.session_state.canary_files = files
            st.success(f"Deployed {len(files)} decoy files in `canary_files/`.")
            st.info("Monitoring for unauthorized changes (encryption/deletion)...")
        except Exception as e:
            st.error(f"Deploy failed: {e}")

    if st.session_state.get("canary_active"):
        st.success("🟢 Monitoring Active")
        
        # Check Integrity
        issues = []
        if "canary_files" in st.session_state:
            for fpath in st.session_state.canary_files:
                if not os.path.exists(fpath):
                    issues.append(f"MISSING: {fpath}")
                else:
                    # Check modification time vs deploy time?
                    # Or just check if content is still text
                    try:
                        with open(fpath, 'r') as f:
                            content = f.read()
                        if "This is a honeypot file" not in content:
                             issues.append(f"MODIFIED/ENCRYPTED: {fpath}")
                    except:
                        issues.append(f"ENCRYPTED (Binary): {fpath}")
        
        if issues:
            st.error("🚨 RANSOMWARE ACTIVITY DETECTED!")
            
            # TRIGGER EVIDENCE COLLECTION
            import plugins.evidence as ev
            collector = ev.EvidenceCollector()
            img_path = collector.capture_screenshot("ransomware_alert")
            st.warning(f"📸 Evidence captured: `{img_path}`")
            
            for i in issues:
                st.write(f"- {i}")
            st.button("Trigger Emergency Shutdown", type="primary")
        else:
            st.info("Files are intact.")

    if st.button("Stop Monitoring & Cleanup"):
        if "canary_files" in st.session_state:
            import shutil
            if os.path.exists("canary_files"):
                shutil.rmtree("canary_files")
        st.session_state.canary_active = False
        st.success("Cleaned up.")

with tab_netwar:
    st.subheader("⚔️ Network Warfare (Scanner & Blocker)")
    st.warning("⚠️ **Warning**: Do not use on networks you do not own. Requires `sudo`.")
    
    col_scan, col_attack = st.columns(2)
    
    with col_scan:
        st.markdown("### 📡 Device Discovery")
        subnet = st.text_input("Target Subnet", "192.168.1.0/24")
        if st.button("Scan Network"):
            try:
                import plugins.net_warfare as warfare
                scanner = warfare.NetworkWarfare()
                with st.spinner("Scanning subnet (ARP)..."):
                    devices = scanner.scan_network(subnet)
                    if devices and "error" in devices[0]:
                        st.error(devices[0]["error"])
                    else:
                        st.success(f"Found {len(devices)} devices.")
                        st.dataframe(pd.DataFrame(devices), use_container_width=True)
            except Exception as e:
                st.error(f"Scan failed: {e}")

    with col_attack:
        st.markdown("### 🚫 WiFi Kicker (ARP Block)")
        target_ip = st.text_input("Target IP to Block", "")
        gateway_ip = st.text_input("Gateway IP (Router)", "192.168.1.1")
        
        if st.button("Start Blocking (Cut Internet)", type="primary"):
            if not target_ip:
                st.warning("Enter Target IP.")
            else:
                try:
                    import plugins.net_warfare as warfare
                    # Store instance in session state to stop later? 
                    # Streamlit re-runs script, so persistent thread control is hard without external daemon.
                    # We will simulate the 'Start' command here.
                    attacker = warfare.NetworkWarfare()
                    attacker.start_blocker(target_ip, gateway_ip)
                    st.success(f"Attack started on {target_ip}. (Simulated in background thread)")
                    st.caption("To stop, restart application or use 'Stop' button (if impl).")
                except Exception as e:
                    st.error(f"Attack failed: {e}") 


with tab_fleet:
    st.subheader("🌐 Fleet Command Center (C2 Simulation)")
    st.markdown("Manage multiple endpoints from a single pane of glass. (Simulated Data)")
    
    # Initialize simulated fleet if not exists
    if "fleet_data" not in st.session_state:
        import random
        agents = []
        for i in range(1, 6):
            agents.append({
                "id": f"AGT-{i:03d}",
                "hostname": f"WORKSTATION-{i}",
                "ip": f"192.168.1.{100+i}",
                "os": random.choice(["Windows 11", "macOS 14", "Ubuntu 22.04"]),
                "status": "Online",
                "last_seen": "Just now",
                "risk_score": random.randint(0, 100) if random.random() > 0.7 else 0
            })
        st.session_state.fleet_data = agents

    # Display Fleet Table
    fleet_df = pd.DataFrame(st.session_state.fleet_data)
    
    # Styling logic for dataframe is limited, so we use standard display
    # Highlighting high risk
    def highlight_risk(val):
        color = 'red' if val > 50 else 'green'
        return f'color: {color}'
        
    st.dataframe(
        fleet_df,
        column_config={
            "risk_score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d"),
            "status": st.column_config.TextColumn("Status")
        },
        use_container_width=True,
        on_select="rerun",
        selection_mode="multi-row",
        key="fleet_table"
    )
    
    # Command Interface
    st.markdown("### 📡 Command Control")
    selected_indices = st.session_state.fleet_table.selection.rows
    
    if selected_indices:
        selected_agents = [st.session_state.fleet_data[i] for i in selected_indices]
        ids = [a['id'] for a in selected_agents]
        st.write(f"Targeting: **{', '.join(ids)}**")
        
        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button("🛡️ Run Quick Scan"):
                with st.spinner("Sending scan command..."):
                    time.sleep(1)
                    for idx in selected_indices:
                        st.session_state.fleet_data[idx]['status'] = "Scanning..."
                    st.success(f"Scan command sent to {len(ids)} agents.")
                    st.rerun()
        
        with c2:
            if st.button("🔄 Update Signatures"):
                with st.spinner("Pushing updates..."):
                    time.sleep(1)
                    for idx in selected_indices:
                        st.session_state.fleet_data[idx]['status'] = "Updating"
                    st.success("Update package dispatched.")
                    st.rerun()

        with c3:
            if st.button("⚠️ Network Isolation"):
                with st.spinner("Isolating hosts..."):
                    time.sleep(1)
                    for idx in selected_indices:
                        st.session_state.fleet_data[idx]['status'] = "ISOLATED"
                        st.session_state.fleet_data[idx]['risk_score'] = 0 # Mitigated
                    st.warning("Hosts isolated from network.")
                    st.rerun()
    else:
        st.info("Select agents from the table to execute commands.")
        
    # Stats
    st.markdown("---")
    offline = len([a for a in st.session_state.fleet_data if a['status'] == "Offline"])
    isolated = len([a for a in st.session_state.fleet_data if "ISOLATED" in a['status']])
    active = len(st.session_state.fleet_data) - offline - isolated
    
    m1, m2, m3 = st.columns(3)
    m1.metric("Active Agents", active)
    m2.metric("Offline", offline)
    m3.metric("Isolated (Compromised)", isolated)
    
    if st.button("Reset Simulation"):
         del st.session_state.fleet_data
         st.rerun()

with tab_history:
    st.subheader("Historical Telemetry Data")
    conn = db.create_connection()
    
    # Action Logs
    st.markdown("### 🛡️ Response Action Log")
    try:
        response_df = db.get_response_logs(conn)
        if not response_df.empty:
            st.dataframe(response_df, use_container_width=True)
        else:
            st.info("No response actions recorded yet.")
    except Exception as e:
        st.error(f"Error fetching logs: {e}")

    st.markdown("---")
    st.markdown("### 📈 Telemetry History")
    
    if conn:
        history_df = db.get_historical_data(conn)
        conn.close()
        st.dataframe(history_df, use_container_width=True)

    # Evidence Locker
    st.markdown("---")
    st.subheader("📸 Evidence Locker")
    import plugins.evidence as ev_locker
    locker = ev_locker.EvidenceCollector()
    files = locker.list_evidence()
    
    if files:
        st.success(f"Found {len(files)} evidence captures.")
        # Gallery view
        cols = st.columns(3)
        for idx, fpath in enumerate(files):
            with cols[idx % 3]:
                st.image(fpath, caption=os.path.basename(fpath))
                if st.button(f"Delete", key=f"del_ev_{idx}"):
                    os.remove(fpath)
                    st.rerun()
    else:
        st.info("No evidence collected yet.")

with tab_net:
    st.subheader("Network Connection Graph")
    
    # Packet Sniffer Section
    with st.expander("🕵️ Network Packet Sniffer (Short-term Capture)"):
        st.markdown("Capture live traffic samples to detect C2 beacons or suspicious DNS queries.")
        
        sniffer_dur = st.slider("Capture Duration (s)", 5, 30, 10)
        if st.button("Start Packet Capture"):
            try:
                import plugins.sniffer as net_sniffer
                if not net_sniffer.SCAPY_AVAILABLE:
                    st.error("Scapy not installed. `pip install scapy`")
                    st.warning("Note: Packet sniffing usually requires running as root/admin (`sudo streamlit run app.py`).")
                else:
                    with st.spinner(f"Sniffing network traffic for {sniffer_dur} seconds..."):
                         result = net_sniffer.run_sniffer_session(duration=sniffer_dur)
                         
                         if "error" in result:
                             st.error(f"Sniffer Error: {result['error']}")
                             st.info("Try running with `sudo` if this is a permission error.")
                         else:
                             pkts = result.get("packets", [])
                             st.success(f"Captured {len(pkts)} packets.")
                             
                             if pkts:
                                 # Convert to DF
                                 df_sniff = pd.DataFrame(pkts)
                                 # Format time
                                 df_sniff['time'] = pd.to_datetime(df_sniff['time'], unit='s').dt.strftime('%H:%M:%S')
                                 
                                 st.dataframe(df_sniff[['time', 'src', 'dst', 'proto', 'dns_query', 'length']], use_container_width=True)
                                 
                                 # DNS Analysis
                                 dns_queries = [p['dns_query'] for p in pkts if p['dns_query']]
                                 if dns_queries:
                                     st.markdown("#### DNS Queries Detected")
                                     st.write(dns_queries)
                                     
            except ImportError as e:
                st.error(f"Import Error: {e}")
            except Exception as e:
                st.error(f"Execution Error: {e}")

    st.markdown("---")

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
