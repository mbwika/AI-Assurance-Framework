# speech_attack_sim/validation/report_generator.py
import pandas as pd
import os
from datetime import datetime

TRIGGER_RATE_COL = 'trigger_rate (%)'

def generate_html_report(log_files, output_file="data/logs/report.html"):
    # Generates a single grouped bar chart for all vulnerabilities
    import plotly.graph_objects as go
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    # Map log file names to user-friendly attack names
    attack_titles = {
        'log_sensitive_info_disclosure.csv': 'Sensitive Information Disclosure',
        'log_supply_chain.csv': 'Supply Chain',
        'log_data_model_poisoning.csv': 'Data Model Poisoning',
        'log_improper_output_handling.csv': 'Improper Output Handling',
        'log_excessive_agency.csv': 'Excessive Agency',
        'log_system_prompt_leakage.csv': 'System Prompt Leakage',
        'log_vector_embedding_weakness.csv': 'Vector & Embedding Weaknesses',
        'log_misinformation.csv': 'Misinformation',
        'log_unbounded_consumption.csv': 'Unbounded Consumption',
        'log_prompt_injection.csv': 'Prompt Injection',
    }
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b', '#e377c2', '#7f7f7f', '#bcbd22', '#17becf']

    # Collect summary data for each log file
    x_labels = []
    rates = []
    legend_names = []
    for idx, file in enumerate(log_files):
        if not os.path.exists(file):
            continue
        df = pd.read_csv(file)
        df['misbehavior_detected'] = df['misbehavior_detected'].astype(str).str.lower() == 'true'
        rate = (df['misbehavior_detected'].sum() / len(df)) * 100 if len(df) else 0
        attack_name = attack_titles.get(os.path.basename(file), os.path.basename(file))
        x_labels.append(f"{attack_name}<br>Tests: {len(df)}")
        rates.append(rate)
        legend_names.append(attack_name)

    # Create a single bar chart
    fig = go.Figure()
    for idx, (x, y, name) in enumerate(zip(x_labels, rates, legend_names)):
        fig.add_trace(go.Bar(
            x=[f"<b>{x}</b>"],
            y=[y],
            name=f"<b>{name}</b>",
            marker_color=colors[idx % len(colors)],
            text=[f"{y:.2f}%"],
            textposition='outside',
            showlegend=True
        ))

    fig.update_layout(
        title_text="<b>OWASP 2025 Top 10 GenAI/ML BAS Trigger Rate Graph</b>",
        title_font_size=28,
        title_x=0.5,
        xaxis_title="<b>Vulnerability Type (Tests Run)</b>",
        yaxis_title="<b>Trigger Rate (%)</b>",
        xaxis_title_font={'size': 18},
        yaxis_title_font={'size': 18},
        yaxis_range=[0, 100],
        template="plotly_white",
        margin={'t': 80, 'l': 40, 'r': 40, 'b': 40},
        plot_bgcolor="#f0f0f0",
        paper_bgcolor="#ffffff",
        legend_title_text="<b>Top 10 GenAI/ML Vulnerabilities</b>",
        legend_font={'size': 16}
    )
    fig.write_html(output_file)
    print(f"✅ Dashboard report saved to: {output_file}")

if __name__ == '__main__':
    import sys
    import glob
    if len(sys.argv) > 2:
        logs = sys.argv[1:-1]
        output_file = sys.argv[-1]
    else:
        logs = glob.glob("data/logs/log_*.csv")
        output_file = "data/logs/report.html"
    generate_html_report(logs, output_file)