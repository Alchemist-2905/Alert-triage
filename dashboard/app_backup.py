"""Streamlit analyst dashboard: ranked alerts, risk scores, evidence/provenance path, evaluation."""
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
import streamlit as st

from alert_triage.config import load_config
from alert_triage.evaluation import evaluate
from alert_triage.provenance import build_graph, entity_subgraph
from alert_triage.store import Store
from alert_triage.triage import analyst_queue, build_incidents

st.set_page_config(page_title="AI Alert Triage", page_icon="🛡️", layout="wide")
cfg = load_config()
COLORS = {"Low": "#2e9e5b", "Medium": "#e0b020", "High": "#e8742a", "Critical": "#c8283c"}
ORDER = ["Critical", "High", "Medium", "Low"]

st.title("🛡️ AI-Based Cyber Incident Prioritization & Risk-Aware Alert Triage")

# ---------------- sidebar ----------------
out_dir = ROOT / "output"
dbs = sorted(out_dir.glob("*.db")) if out_dir.exists() else []
if not dbs:
    st.warning("No results yet. Run `python main.py demo` (historical) or `python main.py live` (real-time), then refresh.")
    st.stop()
with st.sidebar:
    st.header("Controls")
    db_name = st.selectbox("Data source", [d.name for d in dbs],
                           index=[d.name for d in dbs].index("live.db") if "live.db" in [d.name for d in dbs] else 0)
    limit = st.slider("Most recent alerts to load", 500, 100000, 20000, 500)
    levels = st.multiselect("Priority filter", ORDER, default=ORDER)
    hide_dups = st.checkbox("Hide duplicate alerts", value=True)
    auto = st.checkbox("Auto-refresh (live mode)", value=db_name == "live.db")
    every = st.slider("Refresh every (s)", 2, 30, 5)
    st.caption("Risk = 100 × (w₁·severity + w₂·context + w₃·temporal + w₄·ML)")
    st.json(cfg["weights"], expanded=False)

store = Store(out_dir / db_name)
df = store.read(limit=limit)
store.close()
if df.empty:
    st.info("Database is empty — waiting for alerts…")
    if auto:
        time.sleep(every)
        st.rerun()
    st.stop()

view = df[df["priority"].isin(levels)]
if hide_dups:
    view = view[view["is_duplicate"] == 0]
queue = analyst_queue(df)

# ---------------- KPIs ----------------
c = st.columns(6)
c[0].metric("Alerts ingested", f"{len(df):,}")
c[1].metric("After de-duplication", f"{len(queue):,}", f"-{(1 - len(queue) / len(df)):.0%}")
c[2].metric("Critical", int((queue["priority"] == "Critical").sum()))
c[3].metric("High", int((queue["priority"] == "High").sum()))
hi = (df["risk_score"] >= cfg["thresholds"]["high"]).sum()
c[4].metric("Analyst workload reduction", f"{1 - hi / len(df):.1%}", help="Alerts that do NOT need immediate analyst review")
c[5].metric("Avg risk", f"{df['risk_score'].mean():.1f}")

tab_over, tab_queue, tab_inc, tab_prov, tab_eval = st.tabs(
    ["📊 Overview", "📋 Alert queue", "🧩 Incidents", "🕸️ Provenance", "✅ Evaluation"])

with tab_over:
    a, b = st.columns(2)
    with a:
        st.subheader("Alerts by priority")
        pc = df["priority"].value_counts().reindex(ORDER).fillna(0)
        st.bar_chart(pc, color="#c8283c")
    with b:
        st.subheader("Risk-score distribution")
        hist, edges = np.histogram(df["risk_score"], bins=20, range=(0, 100))
        st.bar_chart(pd.Series(hist, index=[f"{int(e)}" for e in edges[:-1]]))
    st.subheader("Alert volume over time (by priority)")
    t = df.set_index("timestamp").groupby([pd.Grouper(freq="5min"), "priority"]).size().unstack(fill_value=0)
    t = t.reindex(columns=[p for p in ORDER if p in t.columns])
    st.area_chart(t, color=[COLORS[p] for p in t.columns])
    st.subheader("Top alert sources (by High/Critical count)")
    top = queue[queue["priority"].isin(["High", "Critical"])].groupby("src_ip").size().sort_values(ascending=False).head(15)
    st.bar_chart(top)

with tab_queue:
    st.subheader("Prioritised analyst queue")
    q = view.sort_values("risk_score", ascending=False)
    cols = ["timestamp", "priority", "risk_score", "src_ip", "dst_ip", "dst_port", "signature", "source",
            "ml_prob", "rule_score", "dup_count", "rule_hits"]
    st.dataframe(q[cols].head(1000), hide_index=True,
                 column_config={"risk_score": st.column_config.ProgressColumn("risk", min_value=0, max_value=100, format="%.1f")})
    st.subheader("Why was this alert ranked here?")
    ids = q["alert_id"].head(300).tolist()
    if ids:
        sel = st.selectbox("Alert", ids)
        r = q[q["alert_id"] == sel].iloc[0]
        l, rr = st.columns([1, 2])
        with l:
            st.markdown(f"**{r['signature']}**  \n`{r['src_ip']}` → `{r['dst_ip']}:{r['dst_port']}`  \n"
                        f"Priority: **{r['priority']}** · Risk **{r['risk_score']:.1f}/100**")
            w = cfg["weights"]; tot = sum(w.values())
            ctx = cfg["context_mix"]["provenance"] * r["prov_score"] + cfg["context_mix"]["rules"] * r["rule_score"]
            contrib = pd.Series({"Severity": w["severity"] * (r["severity"] - 1) / 4, "Context (prov+rules)": w["context"] * ctx,
                                 "Temporal correlation": w["temporal"] * r["temporal_score"], "ML confidence": w["ml"] * r["ml_prob"]}) * 100 / tot
            st.bar_chart(contrib)
        with rr:
            st.markdown("**Evidence / reason codes**")
            st.info(r["reasons"])
            st.write("Rules fired:", r["rule_hits"] or "none")
            if int(r["label"]) >= 0:
                st.write("Ground truth:", "🔴 malicious" if r["label"] == 1 else "🟢 benign",
                         f"({r['attack_cat']})" if r["attack_cat"] else "")

with tab_inc:
    st.subheader("Incidents (alerts grouped per source entity & time session)")
    inc = build_incidents(df)
    st.dataframe(inc.head(500), hide_index=True,
                 column_config={"max_risk": st.column_config.ProgressColumn("max risk", min_value=0, max_value=100, format="%.1f")})

with tab_prov:
    st.subheader("Provenance / context graph")
    st.caption("Nodes: IPs, hosts, users, processes. Edges: communication / execution / logon events (width = alert count).")
    top_src = queue.sort_values("risk_score", ascending=False)["src_ip"].drop_duplicates().head(30).tolist()
    ent = st.selectbox("Entity (source IP, ranked by risk)", top_src)
    G = build_graph(df)
    sub = entity_subgraph(G, f"ip:{ent}", radius=2)
    if sub.number_of_nodes() == 0:
        st.info("No graph context for this entity.")
    else:
        fig, ax = plt.subplots(figsize=(9, 6))
        pos = nx.spring_layout(sub, seed=3, k=0.9)
        cmap = {"ip": "#4c78a8", "host": "#72b7b2", "user": "#e0b020", "process": "#c8283c"}
        nx.draw_networkx_nodes(sub, pos, node_color=[cmap.get(sub.nodes[n].get("ntype"), "#999") for n in sub],
                               node_size=[700 if n == f"ip:{ent}" else 280 for n in sub], ax=ax)
        nx.draw_networkx_edges(sub, pos, width=[min(1 + np.log1p(d["n"]), 6) for _, _, d in sub.edges(data=True)],
                               edge_color="#888", arrows=True, ax=ax)
        nx.draw_networkx_labels(sub, pos, labels={n: n.split(":", 1)[1] for n in sub}, font_size=7, ax=ax)
        ax.axis("off")
        st.pyplot(fig)
        st.caption("Blue = IP · Teal = host · Yellow = user · Red = process")

with tab_eval:
    st.subheader("Evaluation vs. baselines")
    lab = df[df["label"] >= 0]
    if lab.empty or lab["label"].nunique() < 2:
        st.info("No ground-truth labels in this data source (normal for real production alerts).")
    else:
        rep = evaluate(lab, cfg)
        rows = []
        for name, m in rep["methods"].items():
            rows.append({"Method": name, "Precision": m["precision"], "Recall": m["recall"], "F1": m["f1"],
                         "False-positive rate": m["false_positive_rate"], "ROC-AUC": m["roc_auc"],
                         "Alert-volume reduction": m["alert_volume_reduction"]})
        t = pd.DataFrame(rows).set_index("Method")
        st.dataframe(t.style.format("{:.3f}"))
        st.bar_chart(t[["Precision", "Recall", "F1"]])
        st.write("Priority breakdown (how many alerts at each level were truly malicious):")
        st.dataframe(pd.DataFrame(rep["priority_breakdown"]), hide_index=True)

if auto:
    time.sleep(every)
    st.rerun()
