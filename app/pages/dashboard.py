"""
pages/dashboard.py — LLM Evaluation Dashboard

Shows evaluation score trends, per-finding breakdown,
and model comparison charts from the SQLite eval database.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import sys
from pathlib import Path
import html as html_lib

sys.path.insert(0, str(Path(__file__).parent.parent))
from eval import get_eval_history, get_summary_stats, run_eval

st.set_page_config(
    page_title="VulnGraph — Eval Dashboard",
    page_icon="📊",
    layout="wide"
)

# CSS — match main dashboard theme
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600&display=swap');
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
    background-color: #0d1117;
    color: #c9d1d9;
}
.stApp { background: #0d1117; }
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
[data-testid="stMetric"] {
    background: #0d1117;
    border: 1px solid #1e2d40;
    border-radius: 8px;
    padding: 16px;
}
[data-testid="stMetric"] label { color: #8b949e !important; font-size: 11px !important; font-weight:500}
[data-testid="stMetric"] [data-testid="stMetricValue"] { color: #e6edf3 !important; font-family: 'JetBrains Mono', monospace; font-size: 26px !important; font-weight: 600; }
            
.stButton > button:hover { background: #2a5c4e; box-shadow: none; transform: none; }
.sidebar-section {
    font-size: 11px;
    font-weight: 600;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin: 16px 0 8px 0;
}
[data-testid="stTabs"] [data-baseweb="tab-highlight"] { background-color: #4fc3a1; }
[data-testid="stTabs"] [data-baseweb="tab"] { color: #8b949e; }
[data-testid="stTabs"] [aria-selected="true"] { color: #e6edf3 !important; }
</style>
""", unsafe_allow_html=True)


st.markdown("""
<div style='padding:4px 0 20px 0;'>
    <div style='font-family:Inter,sans-serif;font-size:24px;font-weight:600;
                color:#e6edf3;letter-spacing:-0.3px;'>
        Eval Dashboard
    </div>
    <div style='font-size:12px;color:#8b949e;margin-top:2px;'>
        LLM explanation quality metrics
    </div>
</div>
""", unsafe_allow_html=True)

# ── Run eval button ───────────────────────────────────────────────────────────
col_btn, col_info = st.columns([1, 3])
with col_btn:
    if st.button("Run Evaluation", use_container_width=True):
        with st.spinner("Running evaluation harness..."):
            summary = run_eval(verbose=False)
        if summary:
            st.success(f"Done — {summary['passed']}/{summary['total_evaluated']} passed")
            st.rerun()
        else:
            st.warning("No findings to evaluate. Run a scan and generate explanations first.")

with col_info:
    st.markdown("""
    <div style='font-size:11px;color:#8b949e;padding:8px 0;'>
        Relevancy (50%) · Faithfulness (30%) · CWE Accuracy (20%) · Pass threshold: 0.60
    </div>
    """, unsafe_allow_html=True)

st.markdown("<hr style='border-color:#1e2d40;margin:8px 0 20px 0;'>", unsafe_allow_html=True)

# ── Summary stats ─────────────────────────────────────────────────────────────
stats = get_summary_stats()

if not stats:
    st.markdown("""
    <div style='text-align:center;padding:60px;color:#8b949e;font-size:13px;'>
        No evaluation data yet. Click Run Evaluation to start.
    </div>
    """, unsafe_allow_html=True)
    st.stop()

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Pass Rate", f"{stats['pass_rate']}%")
c2.metric("Avg Overall", f"{stats['avg_overall']:.3f}")
c3.metric("Avg Relevancy", f"{stats['avg_relevancy']:.3f}")
c4.metric("Avg Faithfulness", f"{stats['avg_faithfulness']:.3f}")
c5.metric("Total Evals", stats['total_evaluations'])

st.markdown("<hr style='border-color:#1e2d40;margin:20px 0;'>", unsafe_allow_html=True)

# ── Charts ────────────────────────────────────────────────────────────────────
history = get_eval_history(limit=100)
if not history:
    st.info("No detailed history available.")
    st.stop()

df = pd.DataFrame(history)
df["run_timestamp"] = pd.to_datetime(df["run_timestamp"])
df["passed_label"] = df["passed"].map({True: "Pass", False: "Fail"})

chart_col, table_col = st.columns([2, 1])

with chart_col:
    # Score trends over time
    st.markdown('<div class= "sidebar-section">Score Trends</div>'
    , unsafe_allow_html=True)

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df["run_timestamp"], y=df["relevancy_score"],
        name="Relevancy", line=dict(color="#4fc3a1", width=2),
        mode="lines+markers"
    ))
    fig.add_trace(go.Scatter(
        x=df["run_timestamp"], y=df["faithfulness_score"],
        name="Faithfulness", line=dict(color="#4a90d9", width=2),
        mode="lines+markers"
    ))
    fig.add_trace(go.Scatter(
        x=df["run_timestamp"], y=df["overall_score"],
        name="Overall", line=dict(color="#ff8c00", width=2, dash="dash"),
        mode="lines+markers"
    ))
    # Pass threshold line
    fig.add_hline(
        y=0.6, line_dash="dot", line_color="#ff4444",
        annotation_text="Pass threshold (0.60)",
        annotation_position="bottom right"
    )
    fig.update_layout(
        paper_bgcolor="#0d1117",
        plot_bgcolor="#0d1117",
        font=dict(color="#c9d1d9", family="JetBrains Mono"),
        xaxis=dict(gridcolor="#1e2d40", title=""),
        yaxis=dict(gridcolor="#1e2d40", title="Score", range=[0, 1]),
        legend=dict(bgcolor="#0d1117", bordercolor="#1e2d40"),
        margin=dict(l=0, r=0, t=10, b=0),
        height=300
    )
    st.plotly_chart(fig, use_container_width=True)

    # Per-finding breakdown bar chart
    st.markdown('<div class="sidebar-section">Per-Finding Overall Score</div>'
    , unsafe_allow_html=True)

    latest_run = df.groupby("finding_id").last().reset_index()
    fig2 = px.bar(
        latest_run,
        x="finding_id",
        y="overall_score",
        color="passed_label",
        color_discrete_map={"Pass": "#4fc3a1", "Fail": "#ff4444"},
        labels={"overall_score": "Score", "finding_id": "Finding", "passed_label": "Status"}
    )
    fig2.add_hline(y=0.6, line_dash="dot", line_color="#ff4444")
    fig2.update_layout(
        paper_bgcolor="#010409",
        plot_bgcolor="#010409",
        font=dict(color="#c9d1d9", family="Inter"),
        xaxis=dict(gridcolor="#21262d",title=""),
        yaxis=dict(gridcolor="#21262d", range=[0, 1]),
        legend=dict(bgcolor="#010409", bordercolor="#21262d"),
        margin=dict(l=0, r=0, t=10, b=0),
        height=280
    )
    st.plotly_chart(fig2, use_container_width=True)

with table_col:
    # Model comparison
    st.markdown('<div  class= "sidebar-section">Model Comparison</div>'
    , unsafe_allow_html=True)

    if "llm_model" in df.columns:
        model_stats = df.groupby("llm_model").agg(
            avg_overall=("overall_score", "mean"),
            avg_relevancy=("relevancy_score", "mean"),
            pass_rate=("passed", lambda x: round(x.mean() * 100, 1)),
            count=("finding_id", "count")
        ).round(3).reset_index()

        for _, row in model_stats.iterrows():
            model_name = html_lib.escape(str(row['llm_model']))
            color = "#4fc3a1" if row["pass_rate"] >= 50 else "#ff4444"
            st.markdown(f"""
            <div style='background:#010409;border:1px solid #21262d;
                        border-radius:6px;padding:10px 12px;margin-bottom:8px;'>
                <div style='font-family:JetBrains Mono;font-size:11px;color:{color};font-weight:600;margin-bottom:6px;'>
                    {model_name}
                </div>
                <div style='font-size:11px;color:#8b949e;line-height:1.9;'>
                    Pass Rate: {row['pass_rate']}%<br>
                    Avg Overall: {row['avg_overall']:.3f}<br>
                    Avg Relevancy: {row['avg_relevancy']:.3f}<br>
                    Evaluations: {row['count']}
                </div>
            </div>
            """, unsafe_allow_html=True)

    # Recent results table
    st.markdown('<div class="sidebar-section">Recent Results</div>'
    , unsafe_allow_html=True)

    display_df = df[["finding_id", "overall_score", "passed_label"]].head(10).copy()
    display_df.columns = ["Finding", "Score", "Status"]
    display_df["Score"] = display_df["Score"].round(3)
    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        height=300
    )