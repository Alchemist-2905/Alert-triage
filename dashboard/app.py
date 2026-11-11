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
import json
import random
import streamlit as st
import streamlit.components.v1 as components
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


def render_interactive_vis_graph(sub: nx.DiGraph, root_entity: str, height: int = 620) -> str:
    """Generate an interactive HTML/JS physics-driven topology canvas using Vis.js."""
    cmap = {
        "ip": {"bg": "#0284C7", "border": "#38BDF8", "highlight": "#7DD3FC"},
        "host": {"bg": "#7E22CE", "border": "#C084FC", "highlight": "#E9D5FF"},
        "user": {"bg": "#D97706", "border": "#FBBF24", "highlight": "#FDE68A"},
        "process": {"bg": "#BE123C", "border": "#FB7185", "highlight": "#FECDD3"},
    }
    
    nodes_data = []
    for n in sub.nodes:
        ntype = sub.nodes[n].get("ntype", "ip")
        is_root = (n == f"ip:{root_entity}")
        style = cmap.get(ntype, {"bg": "#334155", "border": "#94A3B8", "highlight": "#CBD5E1"})
        label = n.split(":", 1)[1] if ":" in n else n
        
        in_deg = sub.in_degree(n)
        out_deg = sub.out_degree(n)
        badge = ntype.upper()
        root_tag = "<br><span style='color: #EF4444; font-weight: bold;'>🚨 TARGET INVESTIGATION SEED</span>" if is_root else ""
        title = f"<div style='font-family: monospace; font-size: 11px; padding: 6px 10px; background: #0A0F1D; border: 1px solid #38BDF8; border-radius: 6px; color: #F8FAFC;'><b style='color: {style['border']};'>[{badge}]</b> {label}<br><span style='color: #94A3B8;'>Inbound:</span> {in_deg} | <span style='color: #94A3B8;'>Outbound:</span> {out_deg}{root_tag}</div>"
        
        nodes_data.append({
            "id": n,
            "label": label,
            "title": title,
            "shape": "dot",
            "size": 28 if is_root else 16,
            "color": {
                "background": style["bg"],
                "border": style["border"],
                "highlight": {
                    "background": style["highlight"],
                    "border": "#FFFFFF"
                },
                "hover": {
                    "background": style["highlight"],
                    "border": "#38BDF8"
                }
            },
            "borderWidth": 3 if is_root else 1.5,
            "borderWidthSelected": 4,
            "font": {
                "color": "#F8FAFC",
                "size": 11,
                "face": "JetBrains Mono, -apple-system, sans-serif",
                "strokeWidth": 2,
                "strokeColor": "#070B14"
            },
            "shadow": {
                "enabled": True,
                "color": style["border"] + "66",
                "size": 14 if is_root else 8,
                "x": 0,
                "y": 0
            }
        })
        
    edges_data = []
    for u, v, d in sub.edges(data=True):
        n_events = int(d.get("n", 1))
        rel = d.get("rel", "communicates")
        max_sev = d.get("max_sev", 1)
        edge_color = "rgba(239, 68, 68, 0.75)" if max_sev >= 4 else "rgba(56, 189, 248, 0.5)"
        
        title = f"<div style='font-family: monospace; font-size: 11px; padding: 4px 8px; background: #0A0F1D; border: 1px solid #64748B; border-radius: 4px; color: #F8FAFC;'><b>Relation:</b> {rel}<br><b>Alerts:</b> {n_events} | <b>Max Sev:</b> {max_sev}/5</div>"
        
        edges_data.append({
            "from": u,
            "to": v,
            "title": title,
            "arrows": {"to": {"enabled": True, "scaleFactor": 0.65}},
            "width": max(1.2, min(4.5, 1.2 + np.log1p(n_events))),
            "color": {
                "color": edge_color,
                "highlight": "#38BDF8",
                "hover": "#34D399"
            },
            "smooth": {"type": "curvedCW", "roundness": 0.15}
        })

    nodes_json = json.dumps(nodes_data)
    edges_json = json.dumps(edges_data)

    return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css"/>
    <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        html, body {{
            width: 100%;
            height: 100%;
            background: #070B14;
            overflow: hidden;
            font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
        }}
        #graph-container {{
            width: 100%;
            height: {height}px;
            background-color: #070B14;
            background-image: 
                radial-gradient(circle at 50% 50%, rgba(56, 189, 248, 0.06) 0%, transparent 80%),
                linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
            background-size: 100% 100%, 32px 32px, 32px 32px;
            border: 1px solid rgba(148, 163, 184, 0.15);
            border-radius: 14px;
            position: relative;
        }}
        .graph-controls {{
            position: absolute;
            top: 14px;
            right: 14px;
            display: flex;
            gap: 8px;
            z-index: 10;
        }}
        .ctrl-btn {{
            background: rgba(15, 23, 42, 0.85);
            border: 1px solid rgba(56, 189, 248, 0.3);
            color: #38BDF8;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 11px;
            font-family: monospace;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
            backdrop-filter: blur(8px);
        }}
        .ctrl-btn:hover {{
            background: rgba(56, 189, 248, 0.25);
            border-color: #38BDF8;
            color: #F8FAFC;
            transform: translateY(-1px);
        }}
        .graph-legend {{
            position: absolute;
            bottom: 14px;
            left: 14px;
            display: flex;
            gap: 16px;
            background: rgba(15, 23, 42, 0.9);
            border: 1px solid rgba(148, 163, 184, 0.15);
            padding: 7px 16px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            backdrop-filter: blur(8px);
            z-index: 10;
        }}
        .vis-tooltip {{
            position: absolute;
            background: transparent !important;
            border: none !important;
            padding: 0 !important;
        }}
    </style>
</head>
<body>
    <div id="graph-container">
        <div class="graph-controls">
            <button class="ctrl-btn" onclick="network.fit({{animation: true}})">RESET VIEW</button>
            <button class="ctrl-btn" onclick="togglePhysics()">FREEZE / UNFREEZE</button>
        </div>
        <div class="graph-legend">
            <span style="color: #38BDF8;">● IPv4/IPv6 Entity</span>
            <span style="color: #C084FC;">● Host Endpoint</span>
            <span style="color: #FBBF24;">● User Account</span>
            <span style="color: #FB7185;">● System Process</span>
        </div>
    </div>
    <script type="text/javascript">
        const nodes = new vis.DataSet({nodes_json});
        const edges = new vis.DataSet({edges_json});
        const container = document.getElementById('graph-container');
        const data = {{ nodes: nodes, edges: edges }};
        const options = {{
            nodes: {{
                borderWidth: 2,
                shape: 'dot'
            }},
            edges: {{
                arrows: {{ to: {{ enabled: true, scaleFactor: 0.65 }} }},
                smooth: {{ type: 'continuous' }}
            }},
            physics: {{
                solver: 'forceAtlas2Based',
                forceAtlas2Based: {{
                    gravitationalConstant: -75,
                    centralGravity: 0.02,
                    springLength: 90,
                    springConstant: 0.08,
                    damping: 0.45
                }},
                stabilization: {{
                    enabled: true,
                    iterations: 150,
                    updateInterval: 25
                }}
            }},
            interaction: {{
                hover: true,
                tooltipDelay: 40,
                zoomView: true,
                dragView: true,
                multiselect: false
            }}
        }};
        const network = new vis.Network(container, data, options);
        
        let physicsEnabled = true;
        function togglePhysics() {{
            physicsEnabled = !physicsEnabled;
            network.setOptions({{ physics: {{ enabled: physicsEnabled }} }});
        }}
        
        network.on("click", function (params) {{
            if (params.nodes.length > 0) {{
                const selectedNode = params.nodes[0];
                const connectedNodes = network.getConnectedNodes(selectedNode);
                connectedNodes.push(selectedNode);
                
                nodes.forEach(node => {{
                    if (connectedNodes.includes(node.id)) {{
                        nodes.update({{ id: node.id, opacity: 1.0 }});
                    }} else {{
                        nodes.update({{ id: node.id, opacity: 0.15 }});
                    }}
                }});
            }} else {{
                nodes.forEach(node => {{
                    nodes.update({{ id: node.id, opacity: 1.0 }});
                }});
            }}
        }});
    </script>
</body>
</html>'''

# Professional SOC Severity Palette
COLORS = {
    "Critical": "#EF4444",  # Ruby Crimson
    "High": "#F97316",      # Vivid Tangerine
    "Medium": "#FBBF24",    # Warning Amber
    "Low": "#10B981",       # Emerald Safe
}
ORDER = ["Critical", "High", "Medium", "Low"]

# Injection of Enterprise SOC UI/UX Design System with Fluid Ambient Transitions
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

    /* Ambient Cyber Background with Fluid Breathing Animation */
    .stApp {
        background-color: #060913;
        background-image: 
            radial-gradient(circle at 50% 0%, rgba(56, 189, 248, 0.12) 0%, transparent 65%),
            radial-gradient(circle at 85% 25%, rgba(168, 85, 247, 0.08) 0%, transparent 50%),
            radial-gradient(circle at 15% 75%, rgba(16, 185, 129, 0.06) 0%, transparent 45%),
            linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
        background-size: 100% 100%, 100% 100%, 100% 100%, 36px 36px, 36px 36px;
        background-position: 0 0, 0 0, 0 0, -1px -1px, -1px -1px;
        color: #E2E8F0;
        animation: ambientBreath 12s ease-in-out infinite alternate;
    }

    @keyframes ambientBreath {
        0% { background-color: #060913; }
        50% { background-color: #070E1E; }
        100% { background-color: #060913; }
    }

    /* Section & Graph Arise Entrance Transitions */
    @keyframes ariseIn {
        0% {
            opacity: 0;
            transform: translateY(22px) scale(0.985);
            filter: blur(4px);
        }
        100% {
            opacity: 1;
            transform: translateY(0) scale(1);
            filter: blur(0);
        }
    }

    .stTabs [role="tabpanel"] {
        animation: ariseIn 0.55s cubic-bezier(0.16, 1, 0.3, 1) both;
    }

    .arise-stagger-1 {
        animation: ariseIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) both;
    }

    .arise-stagger-2 {
        animation: ariseIn 0.65s cubic-bezier(0.16, 1, 0.3, 1) both;
        animation-delay: 0.1s;
    }

    .arise-stagger-3 {
        animation: ariseIn 0.8s cubic-bezier(0.16, 1, 0.3, 1) both;
        animation-delay: 0.2s;
    }

    .arise-stagger-4 {
        animation: ariseIn 0.95s cubic-bezier(0.16, 1, 0.3, 1) both;
        animation-delay: 0.3s;
    }
    
    /* Top Banner / Command Header */
    .command-header {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.85) 0%, rgba(30, 41, 59, 0.45) 100%);
        border: 1px solid rgba(148, 163, 184, 0.15);
        backdrop-filter: blur(16px);
        border-radius: 14px;
        padding: 20px 24px;
        margin-bottom: 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 4px 28px -2px rgba(0, 0, 0, 0.6);
        animation: ariseIn 0.5s cubic-bezier(0.16, 1, 0.3, 1) both;
    }
    
    .brand-title {
        font-size: 1.45rem;
        font-weight: 800;
        letter-spacing: -0.02em;
        background: linear-gradient(90deg, #F8FAFC 0%, #38BDF8 60%, #94A3B8 100%);
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
        gap: 9px;
        padding: 6px 16px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        background: rgba(16, 185, 129, 0.12);
        color: #34D399;
        border: 1px solid rgba(16, 185, 129, 0.35);
        box-shadow: 0 0 15px rgba(16, 185, 129, 0.15);
        transition: all 0.3s ease;
    }

    .live-status-pill:hover {
        box-shadow: 0 0 20px rgba(16, 185, 129, 0.35);
        border-color: #34D399;
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
        70% { transform: scale(1.05); box-shadow: 0 0 0 8px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    .tenant-pill {
        display: inline-block;
        padding: 6px 14px;
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
        background: rgba(14, 22, 38, 0.75);
        border: 1px solid rgba(148, 163, 184, 0.12);
        border-radius: 14px;
        padding: 16px 18px;
        position: relative;
        overflow: hidden;
        backdrop-filter: blur(12px);
        transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.4);
    }

    .kpi-card-v2:hover {
        border-color: rgba(56, 189, 248, 0.45);
        transform: translateY(-4px) scale(1.015);
        box-shadow: 0 12px 30px -5px rgba(56, 189, 248, 0.22);
    }

    .kpi-card-v2::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent, rgba(56, 189, 248, 0.5), transparent);
        transition: height 0.3s ease, background 0.3s ease;
    }

    .kpi-card-v2:hover::before {
        height: 3px;
        background: linear-gradient(90deg, #0284C7, #38BDF8, #7DD3FC);
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
        background: rgba(30, 41, 59, 0.85);
        border: 1px solid rgba(56, 189, 248, 0.25);
        color: #38BDF8;
        padding: 5px 12px;
        border-radius: 8px;
        font-size: 0.76rem;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
        margin: 3px 6px 3px 0;
        transition: all 0.25s ease;
        cursor: default;
    }

    .reason-chip:hover {
        border-color: #38BDF8;
        color: #F8FAFC;
        background: rgba(56, 189, 248, 0.2);
        transform: translateY(-1px);
        box-shadow: 0 0 12px rgba(56, 189, 248, 0.35);
    }

    /* Card Panels & Containers */
    .content-panel {
        background: rgba(14, 22, 38, 0.65);
        border: 1px solid rgba(148, 163, 184, 0.12);
        border-radius: 14px;
        padding: 22px;
        margin-bottom: 22px;
        backdrop-filter: blur(16px);
        box-shadow: 0 4px 24px -2px rgba(0, 0, 0, 0.4);
        transition: all 0.35s cubic-bezier(0.16, 1, 0.3, 1);
        animation: ariseIn 0.6s cubic-bezier(0.16, 1, 0.3, 1) both;
    }

    .content-panel:hover {
        border-color: rgba(56, 189, 248, 0.35);
        box-shadow: 0 10px 32px -4px rgba(0, 0, 0, 0.6), 0 0 18px -4px rgba(56, 189, 248, 0.15);
        transform: translateY(-2px);
    }

    /* Tabs Styling with Responsive Highlighting */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
        border-bottom: 1px solid rgba(148, 163, 184, 0.15);
        padding-bottom: 4px;
        margin-bottom: 24px;
    }

    .stTabs [data-baseweb="tab"] {
        height: 44px;
        background-color: transparent;
        border-radius: 8px 8px 0 0;
        color: #94A3B8;
        font-size: 0.85rem;
        font-weight: 600;
        letter-spacing: 0.02em;
        padding: 0 18px;
        border: none;
        transition: all 0.2s ease;
    }

    .stTabs [data-baseweb="tab"]:hover {
        color: #F8FAFC;
        background-color: rgba(255, 255, 255, 0.03);
    }

    .stTabs [aria-selected="true"] {
        background-color: rgba(56, 189, 248, 0.08) !important;
        color: #38BDF8 !important;
        border-bottom: 2px solid #38BDF8 !important;
        text-shadow: 0 0 10px rgba(56, 189, 248, 0.5);
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
    <div class="kpi-card-v2 arise-stagger-1">
        <div class="kpi-label-v2">Ingested Stream</div>
        <div class="kpi-value-v2">{total_raw:,}</div>
        <div class="kpi-sub-v2">Raw telemetry events</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="kpi-card-v2 arise-stagger-2">
        <div class="kpi-label-v2">De-duplicated</div>
        <div class="kpi-value-v2" style="color: #38BDF8;">{total_dedup:,}</div>
        <div class="kpi-sub-v2" style="color: #38BDF8;">-{arr_pct:.1f}% noise suppressed</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="kpi-card-v2 arise-stagger-3">
        <div class="kpi-label-v2">Critical Threats</div>
        <div class="kpi-value-v2" style="color: #EF4444;">{crit_count:,}</div>
        <div class="kpi-sub-v2" style="color: #EF4444;">Immediate isolation SLA</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="kpi-card-v2 arise-stagger-2">
        <div class="kpi-label-v2">High Priority</div>
        <div class="kpi-value-v2" style="color: #F97316;">{high_count:,}</div>
        <div class="kpi-sub-v2" style="color: #F97316;">Forensic review required</div>
    </div>
    """, unsafe_allow_html=True)

with col5:
    st.markdown(f"""
    <div class="kpi-card-v2 arise-stagger-3">
        <div class="kpi-label-v2">Workload Cut</div>
        <div class="kpi-value-v2" style="color: #10B981;">{workload_reduction:.1f}%</div>
        <div class="kpi-sub-v2" style="color: #10B981;">Filtered non-actionable</div>
    </div>
    """, unsafe_allow_html=True)

with col6:
    st.markdown(f"""
    <div class="kpi-card-v2 arise-stagger-4">
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
        st.markdown('<div class="content-panel arise-stagger-1">', unsafe_allow_html=True)
        st.subheader("Alert Severity Distribution")
        pc = df["priority"].value_counts().reindex(ORDER).fillna(0)
        st.bar_chart(pc, color="#EF4444")
        st.markdown('</div>', unsafe_allow_html=True)

    with r1_col2:
        st.markdown('<div class="content-panel arise-stagger-2">', unsafe_allow_html=True)
        st.subheader("Risk Score Frequency Spectrum")
        hist, edges = np.histogram(df["risk_score"], bins=20, range=(0, 100))
        st.bar_chart(pd.Series(hist, index=[f"{int(e)}" for e in edges[:-1]]), color="#38BDF8")
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="content-panel arise-stagger-3">', unsafe_allow_html=True)
    st.subheader("Temporal Alert Ingestion Velocity (5-Minute Window)")
    t = df.set_index("timestamp").groupby([pd.Grouper(freq="5min"), "priority"]).size().unstack(fill_value=0)
    t = t.reindex(columns=[p for p in ORDER if p in t.columns])
    st.area_chart(t, color=[COLORS[p] for p in t.columns])
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="content-panel arise-stagger-4">', unsafe_allow_html=True)
    st.subheader("Top Threat Originators (Critical & High Incident Volumes)")
    top = queue[queue["priority"].isin(["High", "Critical"])].groupby("src_ip").size().sort_values(ascending=False).head(10)
    st.bar_chart(top, color="#F97316")
    st.markdown('</div>', unsafe_allow_html=True)

# ---------------- TAB 2: ACTIVE TRIAGE QUEUE ----------------
with tab_queue:
    st.markdown('<div class="content-panel arise-stagger-1">', unsafe_allow_html=True)
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
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="content-panel arise-stagger-2">', unsafe_allow_html=True)
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
    st.markdown('</div>', unsafe_allow_html=True)

# ---------------- TAB 3: CORRELATED INCIDENTS ----------------
with tab_inc:
    st.markdown('<div class="content-panel arise-stagger-1">', unsafe_allow_html=True)
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
    st.markdown('</div>', unsafe_allow_html=True)

# ---------------- TAB 4: ENTITY PROVENANCE GRAPH ----------------
with tab_prov:
    st.markdown('<div class="content-panel arise-stagger-1">', unsafe_allow_html=True)
    st.markdown("### Heterogeneous Entity Provenance Topology")
    st.caption("Graph mapping communication and execution paths between IP entities, hosts, user sessions, and binaries.")

    top_src = queue.sort_values("risk_score", ascending=False)["src_ip"].drop_duplicates().head(30).tolist()
    if not top_src:
        st.info("No active communication entities available in current buffer.")
    else:
        ctl_c1, ctl_c2 = st.columns([1.3, 1.7])
        with ctl_c1:
            ent = st.selectbox("Inspect Target Entity Subgraph (Ranked by Risk):", top_src)
        with ctl_c2:
            render_mode = st.radio(
                "Topology Visualization Engine",
                ["⚡ Interactive Physics Network (Vis.js / WebGL)", "📊 Static High-Res Vector (Matplotlib)"],
                index=0,
                horizontal=True
            )

        G = build_graph(df)
        sub = entity_subgraph(G, f"ip:{ent}", radius=2)

        if sub.number_of_nodes() == 0:
            st.info("No topological graph context for this entity.")
        else:
            if "Interactive" in render_mode:
                html_vis = render_interactive_vis_graph(sub, ent, height=600)
                components.html(html_vis, height=620)
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
    st.markdown('</div>', unsafe_allow_html=True)

# ---------------- TAB 5: MODEL BENCHMARKS ----------------
with tab_eval:
    st.markdown('<div class="content-panel arise-stagger-1">', unsafe_allow_html=True)
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
    st.markdown('</div>', unsafe_allow_html=True)

# ---------------- REFRESH LOOP ----------------
if auto:
    if sim_continuous:
        inject_simulated_alerts(count=random.randint(5, 12), db_target=db_name)
    time.sleep(every)
    st.rerun()
