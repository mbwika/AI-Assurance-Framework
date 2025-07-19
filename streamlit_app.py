# streamlit_app.py
import streamlit as st
import subprocess
import glob
import pandas as pd
import os
import streamlit.components.v1 as components

st.set_page_config(page_title="GenAI/ML BAS Dashboard", layout="wide")

st.title("GenAI/ML Breach and Attack Simulation (BAS) Dashboard")

# Tabs for dashboard and logs
tab1, tab2 = st.tabs(["Run BAS Pipeline", "View Log Files"])

with tab1:
    # User input form
    with st.form("bas_form"):
        api_endpoint = st.text_input("SeamlessM4T API Endpoint", value="http://localhost:8000/translate/")
        input_text = st.text_area("Input Text for Attack Simulation", value="Hello, how are you today?")
        target_lang = st.text_input("Target Language Code", value="spa")
        target_voice = st.text_input("Target Voice", value="es-BO-SofiaNeural")
        run_btn = st.form_submit_button("Run BAS Pipeline")

    log_placeholder = st.empty()
    if run_btn:
        st.info("Running BAS pipeline. This may take a few moments...")
        # Run the pipeline with user inputs
        cmd = [
            "python", "test_harness/run_pipeline.py",
            "--api", api_endpoint,
            "--input", input_text,
            "--lang", target_lang,
            "--voice", target_voice
        ]
        with st.spinner("Executing pipeline..."):
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            logs = ""
            if process.stdout is not None:
                for line in process.stdout:
                    logs += line
                    log_placeholder.code(logs, language="bash")
                process.stdout.close()
            process.wait()
            if process.returncode != 0:
                st.error("Pipeline finished with errors. See logs above.")

    # Display dashboard report if available
    report_path = "data/logs/report.html"
    if os.path.exists(report_path):
        st.header("Dashboard Report")
        components.html(open(report_path).read(), height=800, scrolling=True)
    else:
        st.info("Dashboard report will appear here after running the pipeline.")

    st.caption("© 2025 GenAI/ML Security Audit")

with tab2:
    st.header("Attack Logs and Results")
    log_files = sorted(glob.glob("data/logs/misbehavior_log_*.csv"))
    if not log_files:
        st.warning("No log files found. Run the pipeline to generate logs.")
    else:
        for log_file in log_files:
            st.subheader(f"Log: {os.path.basename(log_file)}")
            df = pd.read_csv(log_file)
            st.dataframe(df)
            # Show summary stats
            misbehaviors = df['misbehavior_detected'].astype(str).str.lower() == 'true'
            trigger_rate = (misbehaviors.sum() / len(df)) * 100 if len(df) else 0
            st.metric("Trigger Rate (%)", f"{trigger_rate:.2f}")