"""Professional Enterprise SOC Incident Prioritization & Alert Triage Dashboard.
Redesigned with modern Command-Center aesthetic, high-contrast dark telemetry, and clean visual hierarchy.
Group 26PB82 — Team Alpha (RUAS CSE 2023)
"""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd
import random
import streamlit as st
from datetime import datetime, UTC, timedelta

from alert_triage.config import load_config
from alert_triage.data_gen import LiveGenerator
from alert_triage.evaluation import evaluate
from alert_triage.pipeline import ModelBundle
from alert_triage.provenance import build_graph, entity_subgraph
from alert_triage.realtime import LiveEngine
from alert_triage.store import Store
from alert_triage.triage import analyst_queue, build_incidents

# Page setup
st.set_page_config(
    page_title="SENTINEL // Cyber Incident Triage & Threat Prioritization",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

cfg = load_config()


def inject_simulated_alerts(count: int = 150, db_target: str = "live.db") -> int:
    """Generate and score simulated streaming SOC events directly into the database."""
    model_path = ROOT / "models" / "default.joblib"
    if not model_path.exists():
        return 0
    bundle = ModelBundle.load(model_path)
    out_dir = ROOT / "output"
    target_store = Store(out_dir / db_target)
    engine = LiveEngine(bundle, target_store)
    gen = LiveGenerator(campaign_every_s=10, scanner_every_s=25)
    now = datetime.now(UTC).replace(tzinfo=None)
    
    all_recs = []
    steps = max(1, count // 10)
    for s in range(steps):
        t = now + timedelta(seconds=s * 2)
        all_recs.extend(gen.tick(t, rate=4.0))
        if len(all_recs) >= count:
            break
            
    fresh = engine.process(all_recs[:count])
    target_store.close()
    return len(fresh)

# Professional SOC Severity Palette
COLORS = {
    "Critical": "#EF4444",  # Ruby Crimson
    "High": "#F97316",      # Vivid Tangerine
    "Medium": "#FBBF24",    # Warning Amber
    "Low": "#10B981",       # Emerald Safe
}
ORDER = ["Critical", "High", "Medium", "Low"]

# Injection of Enterprise SOC UI/UX Design System
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

    /* Global Typography & Palette */
    html, body, [class*="css"] {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    code, pre, .mono-font {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Background and Canvas */
    .stApp {
        background-color: #070B14;
        color: #E2E8F0;
    }
    
    /* Top Banner / Command Header */
    .command-header {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.8) 0%, rgba(30, 41, 59, 0.4) 100%);
        border: 1px solid rgba(148, 163, 184, 0.12);
        backdrop-filter: blur(12px);
        border-radius: 14px;
        padding: 20px 24px;
        margin-bottom: 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 4px 24px -1px rgba(0, 0, 0, 0.5);
    }
    
    .brand-title {
        font-size: 1.45rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        background: linear-gradient(90deg, #F8FAFC 0%, #94A3B8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    .brand-subtitle {
        font-size: 0.82rem;
        color: #64748B;
        font-weight: 500;
        margin-top: 4px;
    }

    .status-badge-container {
        display: flex;
        align-items: center;
        gap: 12px;
    }

    .live-status-pill {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        background: rgba(16, 185, 129, 0.12);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.3);
    }

    .live-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background-color: #10B981;
        box-shadow: 0 0 10px #10B981;
        animation: pulse-green 2s infinite;
    }

    @keyframes pulse-green {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    .tenant-pill {
        display: inline-block;
        padding: 6px 12px;
        border-radius: 8px;
        font-size: 0.75rem;
        font-weight: 600;
        color: #94A3B8;
        background: rgba(30, 41, 59, 0.6);
        border: 1px solid rgba(148, 163, 184, 0.15);
    }

    /* Telemetry KPI Cards */
    .kpi-container {
        display: grid;
        grid-template-columns: repeat(6, 1fr);
        gap: 14px;
        margin-bottom: 24px;
    }

    .kpi-card-v2 {
        background: #0E1626;
        border: 1px solid rgba(148, 163, 184, 0.1);
        border-radius: 12px;
        padding: 16px 18px;
        position: relative;
        overflow: hidden;
        transition: transform 0.2s ease, border-color 0.2s ease;
    }

    .kpi-card-v2:hover {
        border-color: rgba(56, 189, 248, 0.3);
        transform: translateY(-2px);
    }

    .kpi-card-v2::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent, rgba(56, 189, 248, 0.5), transparent);
    }

    .kpi-label-v2 {
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: #64748B;
        margin-bottom: 8px;
    }

    .kpi-value-v2 {
        font-size: 1.75rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
        color: #F8FAFC;
        line-height: 1.1;
    }

    .kpi-sub-v2 {
        font-size: 0.75rem;
        color: #94A3B8;
        margin-top: 6px;
        font-weight: 500;
    }

    /* Severity Badges & Reason Tags */
    .badge-crit {
        background: rgba(239, 68, 68, 0.15);
        color: #F87171;
        border: 1px solid rgba(239, 68, 68, 0.35);
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.04em;
    }

    .badge-high {
        background: rgba(249, 115, 22, 0.15);
        color: #FB923C;
        border: 1px solid rgba(249, 115, 22, 0.35);
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.04em;
    }

    .badge-med {
        background: rgba(234, 179, 8, 0.15);
        color: #FACC15;
        border: 1px solid rgba(234, 179, 8, 0.35);
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.04em;
    }

    .badge-low {
        background: rgba(16, 185, 129, 0.15);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.35);
        padding: 4px 10px;
        border-radius: 6px;
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.04em;
    }

    .reason-chip {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        background: rgba(30, 41, 59, 0.8);
        border: 1px solid rgba(56, 189, 248, 0.25);
        color: #38BDF8;
        padding: 4px 12px;
        border-radius: 6px;
        font-size: 0.76rem;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        margin: 3px 4px 3px 0;
    }

    .reason-chip.alert-chip {
        border-color: rgba(239, 68, 68, 0.4);
        color: #FCA5A5;
        background: rgba(239, 68, 68, 0.1);
    }

    .reason-chip.hub-chip {
        border-color: rgba(168, 85, 247, 0.4);
        color: #D8B4FE;
        background: rgba(168, 85, 247, 0.1);
    }

    /* Card Panels & Containers */
    .content-panel {
        background: #0E1626;
        border: 1px solid rgba(148, 163, 184, 0.1);
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 20px;
    }

    /* Tabs Styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
        border-bottom: 1px solid rgba(148, 163, 184, 0.15);
        padding-bottom: 4px;
        margin-bottom: 20px;
    }

    .stTabs [data-baseweb="tab"] {
        height: 42px;
        background-color: transparent;
        border-radius: 8px 8px 0 0;
        color: #94A3B8;
        font-size: 0.85rem;
        font-weight: 600;
        letter-spacing: 0.02em;
        padding: 0 18px;
        border: none;
    }

    .stTabs [aria-selected="true"] {
        background-color: rgba(56, 189, 248, 0.08) !important;
        color: #38BDF8 !important;
        border-bottom: 2px solid #38BDF8 !important;
    }

    /* Sidebar Refinements */
    [data-testid="stSidebar"] {
        background-color: #0A0F1D;
        border-right: 1px solid rgba(148, 163, 184, 0.1);
    }
    
    .sidebar-section-title {
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        color: #64748B;
        margin-top: 20px;
        margin-bottom: 8px;
    }

    /* Streamlit overrides for high visual clarity */
    .stDataFrame {
        border: 1px solid rgba(148, 163, 184, 0.1) !important;
        border-radius: 10px !important;
        overflow: hidden !important;
    }
</style>
""", unsafe_allow_html=True)

# ---------------- SIDEBAR CONTROLS ----------------
out_dir = ROOT / "output"
dbs = sorted(out_dir.glob("*.db")) if out_dir.exists() else []

if not dbs:
    st.error("No triage telemetry found in output/. Run `python main.py demo` or `python main.py live` first.")
    st.stop()

with st.sidebar:
    st.markdown('<div class="brand-title">🛡️ SENTINEL</div>', unsafe_allow_html=True)
    st.caption("AI Cyber Triage System · Group 26PB82")
    st.markdown("---")

    st.markdown('<div class="sidebar-section-title">Telemetry Ingestion Source</div>', unsafe_allow_html=True)
    db_names = [d.name for d in dbs]
    default_idx = db_names.index("live.db") if "live.db" in db_names else 0
    db_name = st.selectbox("Active Database", db_names, index=default_idx, label_visibility="collapsed")

    st.markdown('<div class="sidebar-section-title">Operational Triage Filters</div>', unsafe_allow_html=True)
    levels = st.multiselect("Severity Thresholds", ORDER, default=ORDER)
    hide_dups = st.checkbox("Suppress Redundant Duplicates", value=True)
    limit = st.slider("Max Events Buffer", min_value=500, max_value=100000, value=20000, step=500)

    st.markdown('<div class="sidebar-section-title">Streaming Ingestion Controls</div>', unsafe_allow_html=True)
    auto = st.checkbox("Real-Time Auto Refresh", value=(db_name == "live.db"))
    every = st.slider("Polling Frequency (seconds)", min_value=2, max_value=30, value=3)

    st.markdown('<div class="sidebar-section-title">Live Simulator Controls</div>', unsafe_allow_html=True)
    if st.button("⚡ Inject 100 Live Events", use_container_width=True, help="Generate and score 100 fresh realistic SOC events with attack campaigns"):
        with st.spinner("Scoring simulated telemetry..."):
            added = inject_simulated_alerts(count=100, db_target=db_name)
        st.toast(f"Injected {added} live simulated events!", icon="⚡")
        st.rerun()

    sim_continuous = st.toggle("Continuous Stream Simulator", value=False, help="Continuously injects fresh simulated attack bursts on every auto-refresh cycle.")

    st.markdown("---")
    with st.expander("Engine Scoring Parameters"):
        w = cfg.get("weights", {})
        st.write(f"• Severity Weight ($w_1$): `{w.get('severity', 0.10)}`")
        st.write(f"• Context Weight ($w_2$): `{w.get('context', 0.20)}`")
        st.write(f"• Temporal Velocity ($w_3$): `{w.get('temporal', 0.10)}`")
        st.write(f"• ML Model Confidence ($w_4$): `{w.get('ml', 0.60)}`")

# ---------------- DATA FETCHING ----------------
store = Store(out_dir / db_name)
df = store.read(limit=limit)
store.close()

if df.empty:
    st.markdown(f"""
    <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 12px; padding: 24px; margin-top: 20px;">
        <div style="font-size: 1.2rem; font-weight: 700; color: #38BDF8; margin-bottom: 8px;">
            📡 Real-Time Engine Waiting for Telemetry Stream
        </div>
        <div style="color: #94A3B8; font-size: 0.9rem; line-height: 1.6;">
            The active database <code>{db_name}</code> is currently empty. You can instantly simulate live enterprise security telemetry or switch to the pre-triaged historical dataset:
        </div>
        <div style="margin-top: 18px; display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
            <div style="background: rgba(30, 41, 59, 0.5); padding: 16px; border-radius: 8px; border: 1px solid rgba(148, 163, 184, 0.15);">
                <div style="font-weight: 700; color: #F8FAFC; margin-bottom: 4px;">⚡ Instant Live Simulation</div>
                <div style="font-size: 0.8rem; color: #94A3B8;">Inject multi-stage attacks, port scans, and background benign noise directly into <code>{db_name}</code>.</div>
            </div>
            <div style="background: rgba(30, 41, 59, 0.5); padding: 16px; border-radius: 8px; border: 1px solid rgba(148, 163, 184, 0.15);">
                <div style="font-weight: 700; color: #F8FAFC; margin-bottom: 4px;">📂 Switch to Historical Batch</div>
                <div style="font-size: 0.8rem; color: #94A3B8;">Change "Active Database" in the sidebar to <b><code>batch.db</code></b> (contains 60,000 pre-triaged alerts).</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    st.write("")
    if st.button("🚀 Populate 250 Live Simulated Events Now", key="seed_btn", use_container_width=True):
        with st.spinner("Generating and scoring live events..."):
            added = inject_simulated_alerts(count=250, db_target=db_name)
        st.success(f"Successfully generated and scored {added} events into {db_name}!")
        st.rerun()

    if auto:
        time.sleep(every)
        st.rerun()
    st.stop()

view = df[df["priority"].isin(levels)]
if hide_dups:
    view = view[view["is_duplicate"] == 0]
queue = analyst_queue(df)

# ---------------- COMMAND CENTER HEADER ----------------
is_live_source = (db_name == "live.db")
status_label = "LIVE ENGINE MONITORING" if is_live_source else "HISTORICAL REPLAY BATCH"

st.markdown(f"""
<div class="command-header">
    <div>
        <div class="brand-title">AI Cyber Incident Prioritization & Risk-Aware Alert Triage</div>
        <div class="brand-subtitle">Heterogeneous Provenance Graphing · Parallel Heuristic & Machine Learning Defense Engine</div>
    </div>
    <div class="status-badge-container">
        <div class="tenant-pill">TENANT: RUAS-CSE-26PB82</div>
        <div class="live-status-pill">
            <span class="live-dot"></span>
            {status_label}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ---------------- KPI TELEMETRY METRIC CARDS ----------------
total_raw = len(df)
total_dedup = len(queue)
arr_pct = (1.0 - (total_dedup / total_raw)) * 100.0 if total_raw > 0 else 0.0
crit_count = int((queue["priority"] == "Critical").sum())
high_count = int((queue["priority"] == "High").sum())
hi_total = (df["risk_score"] >= cfg["thresholds"]["high"]).sum()
workload_reduction = (1.0 - (hi_total / total_raw)) * 100.0 if total_raw > 0 else 0.0
avg_risk = df["risk_score"].mean()

col1, col2, col3, col4, col5, col6 = st.columns(6)

with col1:
    st.markdown(f"""
    <div class="kpi-card-v2">
        <div class="kpi-label-v2">Ingested Stream</div>
        <div class="kpi-value-v2">{total_raw:,}</div>
        <div class="kpi-sub-v2">Raw telemetry events</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="kpi-card-v2">
        <div class="kpi-label-v2">De-duplicated</div>
        <div class="kpi-value-v2" style="color: #38BDF8;">{total_dedup:,}</div>
        <div class="kpi-sub-v2" style="color: #38BDF8;">-{arr_pct:.1f}% noise suppressed</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="kpi-card-v2">
        <div class="kpi-label-v2">Critical Threats</div>
        <div class="kpi-value-v2" style="color: #EF4444;">{crit_count:,}</div>
        <div class="kpi-sub-v2" style="color: #EF4444;">Immediate isolation SLA</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="kpi-card-v2">
        <div class="kpi-label-v2">High Priority</div>
        <div class="kpi-value-v2" style="color: #F97316;">{high_count:,}</div>
        <div class="kpi-sub-v2" style="color: #F97316;">Forensic review required</div>
    </div>
    """, unsafe_allow_html=True)

with col5:
    st.markdown(f"""
    <div class="kpi-card-v2">
        <div class="kpi-label-v2">Workload Cut</div>
        <div class="kpi-value-v2" style="color: #10B981;">{workload_reduction:.1f}%</div>
        <div class="kpi-sub-v2" style="color: #10B981;">Filtered non-actionable</div>
    </div>
    """, unsafe_allow_html=True)

with col6:
    st.markdown(f"""
    <div class="kpi-card-v2">
        <div class="kpi-label-v2">Mean Risk Score</div>
        <div class="kpi-value-v2" style="color: #A855F7;">{avg_risk:.1f}</div>
        <div class="kpi-sub-v2">Normalized scale (0-100)</div>
    </div>
    """, unsafe_allow_html=True)

st.write("")

# ---------------- NAVIGATION TABS ----------------
tab_over, tab_queue, tab_inc, tab_prov, tab_eval = st.tabs([
    "Executive Overview",
    "Triage Queue",
    "Correlated Incidents",
    "Entity Provenance Graph",
    "Model Evaluation & Baselines",
])

# ---------------- TAB 1: EXECUTIVE OVERVIEW ----------------
with tab_over:
    r1_col1, r1_col2 = st.columns([1, 1])

    with r1_col1:
        st.markdown('<div class="content-panel">', unsafe_allow_html=True)
        st.subheader("Alert Severity Distribution")
        pc = df["priority"].value_counts().reindex(ORDER).fillna(0)
        st.bar_chart(pc, color="#EF4444")
        st.markdown('</div>', unsafe_allow_html=True)

    with r1_col2:
        st.markdown('<div class="content-panel">', unsafe_allow_html=True)
        st.subheader("Risk Score Frequency Spectrum")
        hist, edges = np.histogram(df["risk_score"], bins=20, range=(0, 100))
        st.bar_chart(pd.Series(hist, index=[f"{int(e)}" for e in edges[:-1]]), color="#38BDF8")
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="content-panel">', unsafe_allow_html=True)
    st.subheader("Temporal Alert Ingestion Velocity (5-Minute Window)")
    t = df.set_index("timestamp").groupby([pd.Grouper(freq="5min"), "priority"]).size().unstack(fill_value=0)
    t = t.reindex(columns=[p for p in ORDER if p in t.columns])
    st.area_chart(t, color=[COLORS[p] for p in t.columns])
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="content-panel">', unsafe_allow_html=True)
    st.subheader("Top Threat Originators (Critical & High Incident Volumes)")
    top = queue[queue["priority"].isin(["High", "Critical"])].groupby("src_ip").size().sort_values(ascending=False).head(10)
    st.bar_chart(top, color="#F97316")
    st.markdown('</div>', unsafe_allow_html=True)

# ---------------- TAB 2: ACTIVE TRIAGE QUEUE ----------------
with tab_queue:
    st.markdown("### Actionable Triage Queue")
    st.caption(f"Displaying {len(view):,} prioritized alerts sorted by descending risk score.")

    q = view.sort_values("risk_score", ascending=False)
    cols = ["timestamp", "priority", "risk_score", "src_ip", "dst_ip", "dst_port", "signature", "source",
            "ml_prob", "rule_score", "dup_count", "rule_hits"]

    st.dataframe(
        q[cols].head(1000),
        use_container_width=True,
        hide_index=True,
        column_config={
            "risk_score": st.column_config.ProgressColumn("Risk Index (0-100)", min_value=0, max_value=100, format="%.1f"),
            "ml_prob": st.column_config.NumberColumn("ML Prob", format="%.3f"),
            "rule_score": st.column_config.NumberColumn("Rule Score", format="%.2f"),
            "src_ip": st.column_config.TextColumn("Source Entity"),
            "dst_ip": st.column_config.TextColumn("Target Entity"),
            "signature": st.column_config.TextColumn("Attack Classification"),
        }
    )

    st.markdown("---")
    st.markdown("### Forensic Incident Drill-Down & XAI Explainability")

    ids = q["alert_id"].head(300).tolist()
    if ids:
        sel = st.selectbox("Select Alert Identifier to Investigate:", ids)
        r = q[q["alert_id"] == sel].iloc[0]

        d_col1, d_col2 = st.columns([1.1, 1.4])

        with d_col1:
            p_color = COLORS.get(r['priority'], '#64748B')
            st.markdown(f"""
            <div style="background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(148, 163, 184, 0.15); border-radius: 10px; padding: 18px; margin-bottom: 15px;">
                <div style="font-size: 0.8rem; color: #94A3B8; text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em;">Incident Fingerprint</div>
                <div style="font-size: 1.15rem; font-weight: 700; color: #F8FAFC; margin-top: 4px;">{r['signature']}</div>
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #38BDF8; margin-top: 6px;">
                    {r['src_ip']} → {r['dst_ip']}:{r['dst_port']}
                </div>
                <div style="margin-top: 12px; display: flex; gap: 10px; align-items: center;">
                    <span style="background: {p_color}22; color: {p_color}; border: 1px solid {p_color}55; padding: 4px 10px; border-radius: 6px; font-weight: 700; font-size: 0.8rem;">
                        {r['priority']} PRIORITY
                    </span>
                    <span style="font-family: 'JetBrains Mono', monospace; font-weight: 700; font-size: 0.95rem; color: #F8FAFC;">
                        SCORE: {r['risk_score']:.1f} / 100
                    </span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("**Risk Factor Contribution Decomposition**")
            w = cfg["weights"]
            tot = sum(w.values())
            ctx = cfg["context_mix"]["provenance"] * r["prov_score"] + cfg["context_mix"]["rules"] * r["rule_score"]
            contrib = pd.Series({
                "Reported Severity": w["severity"] * (r["severity"] - 1) / 4,
                "Context (Graph + Rules)": w["context"] * ctx,
                "Temporal Burst Factor": w["temporal"] * r["temporal_score"],
                "ML Malicious Confidence": w["ml"] * r["ml_prob"]
            }) * 100 / tot
            st.bar_chart(contrib, color="#38BDF8")

        with d_col2:
            st.markdown("**Tactical Reason Codes & Explainability Signals (XAI)**")
            reasons_raw = str(r["reasons"]).split(";") if ";" in str(r["reasons"]) else str(r["reasons"]).split(",")
            chips_html = "".join([f'<span class="reason-chip">{reason.strip()}</span>' for reason in reasons_raw if reason.strip()])
            st.markdown(f'<div style="margin-bottom: 12px;">{chips_html}</div>', unsafe_allow_html=True)

            st.write(f"**Heuristic Rules Triggered:** `{r['rule_hits'] or 'None (Baseline)'}`")
            if int(r["label"]) >= 0:
                gt_text = "MALICIOUS (True Threat)" if r["label"] == 1 else "BENIGN (Safe Telemetry)"
                gt_color = "#EF4444" if r["label"] == 1 else "#10B981"
                st.markdown(f"**Evaluation Ground Truth:** <span style='color: {gt_color}; font-weight: 700;'>{gt_text}</span> `({r['attack_cat'] or 'Standard'})`", unsafe_allow_html=True)

            st.markdown("**Analyst Action Desk (Human-AI Decision Support)**")
            a_c1, a_c2, a_c3 = st.columns(3)
            with a_c1:
                if st.button("🚨 Escalate to Tier-2", key="btn_esc", use_container_width=True):
                    st.success(f"Incident {sel} escalated to Tier-2 Incident Response Team.")
            with a_c2:
                if st.button("✅ Validate Threat", key="btn_val", use_container_width=True):
                    st.info(f"Threat confirmed by Analyst. Security ticket dispatched.")
            with a_c3:
                if st.button("🔇 Suppress Rule", key="btn_sup", use_container_width=True):
                    st.warning(f"Signature for {sel} marked as False Alarm baseline.")

# ---------------- TAB 3: CORRELATED INCIDENTS ----------------
with tab_inc:
    st.markdown("### High-Level Security Incidents")
    st.caption("Aggregated security episodes grouped per adversary source entity and operational session window.")

    inc = build_incidents(df)
    st.dataframe(
        inc.head(500),
        use_container_width=True,
        hide_index=True,
        column_config={
            "max_risk": st.column_config.ProgressColumn("Max Risk Index", min_value=0, max_value=100, format="%.1f"),
            "alert_count": st.column_config.NumberColumn("Aggregated Alerts"),
            "src_ip": st.column_config.TextColumn("Originating Entity"),
        }
    )

# ---------------- TAB 4: ENTITY PROVENANCE GRAPH ----------------
with tab_prov:
    st.markdown("### Heterogeneous Entity Provenance Topology")
    st.caption("Graph mapping communication and execution paths between IP entities, hosts, user sessions, and binaries.")

    top_src = queue.sort_values("risk_score", ascending=False)["src_ip"].drop_duplicates().head(30).tolist()
    if not top_src:
        st.info("No active communication entities available in current buffer.")
    else:
        ent = st.selectbox("Inspect Target Entity Subgraph (Ranked by Risk):", top_src)
        G = build_graph(df)
        sub = entity_subgraph(G, f"ip:{ent}", radius=2)

        if sub.number_of_nodes() == 0:
            st.info("No topological graph context for this entity.")
        else:
            fig, ax = plt.subplots(figsize=(10, 6), facecolor="#070B14")
            ax.set_facecolor("#070B14")

            pos = nx.spring_layout(sub, seed=3, k=0.9)
            cmap = {
                "ip": "#38BDF8",       # Cyan
                "host": "#A855F7",     # Violet
                "user": "#F59E0B",     # Amber
                "process": "#F43F5E"   # Rose
            }

            node_colors = [cmap.get(sub.nodes[n].get("ntype"), "#94A3B8") for n in sub]
            node_sizes = [850 if n == f"ip:{ent}" else 340 for n in sub]

            nx.draw_networkx_nodes(sub, pos, node_color=node_colors, node_size=node_sizes, ax=ax, edgecolors="#1E293B", linewidths=1.5)
            nx.draw_networkx_edges(
                sub, pos,
                width=[min(1.2 + np.log1p(d["n"]), 5) for _, _, d in sub.edges(data=True)],
                edge_color="#94A3B866",
                arrows=True,
                arrowsize=14,
                ax=ax
            )

            labels = {n: n.split(":", 1)[1] for n in sub}
            nx.draw_networkx_labels(sub, pos, labels=labels, font_size=8, font_family="sans-serif", font_color="#F8FAFC", ax=ax)

            ax.axis("off")
            plt.tight_layout()
            st.pyplot(fig)
            plt.close()

            st.markdown("""
            <div style="display: flex; gap: 20px; justify-content: center; margin-top: 10px; font-size: 0.8rem; font-weight: 600;">
                <span style="color: #38BDF8;">● IPv4/IPv6 Entity</span>
                <span style="color: #A855F7;">● Host Endpoint</span>
                <span style="color: #F59E0B;">● User Account</span>
                <span style="color: #F43F5E;">● System Process</span>
            </div>
            """, unsafe_allow_html=True)

# ---------------- TAB 5: MODEL BENCHMARKS ----------------
with tab_eval:
    st.markdown("### Academic Model Verification & Baseline Benchmarking")
    st.caption("Quantitative comparative evaluation against conventional rule-based and severity-only heuristics.")

    lab = df[df["label"] >= 0]
    if lab.empty or lab["label"].nunique() < 2:
        st.info("No ground-truth labels present in active stream (typical in live production environments).")
    else:
        rep = evaluate(lab, cfg)
        rows = []
        for name, m in rep["methods"].items():
            rows.append({
                "Methodology": name,
                "Precision": m["precision"],
                "Recall (Detection Rate)": m["recall"],
                "F1-Score": m["f1"],
                "False-Positive Rate": m["false_positive_rate"],
                "ROC-AUC": m["roc_auc"],
                "Workload Volume Reduction": m["alert_volume_reduction"]
            })
        t = pd.DataFrame(rows).set_index("Methodology")
        st.dataframe(t.style.format("{:.3f}"), use_container_width=True)

        st.markdown("**Metric Comparison Across Triage Architectures**")
        st.bar_chart(t[["Precision", "Recall (Detection Rate)", "F1-Score"]])

        st.markdown("**Priority Triage Accuracy (True Threat Distribution per Tier)**")
        st.dataframe(pd.DataFrame(rep["priority_breakdown"]), use_container_width=True, hide_index=True)

# ---------------- REFRESH LOOP ----------------
if auto:
    if sim_continuous:
        inject_simulated_alerts(count=random.randint(5, 12), db_target=db_name)
    time.sleep(every)
    st.rerun()
