import numpy as np
import pandas as pd

from alert_triage.preprocess import preprocess
from alert_triage.provenance import build_graph, entity_subgraph
from alert_triage.rules import apply_rules
from alert_triage.scoring import risk_score, to_priority
from alert_triage.triage import analyst_queue, build_incidents


def test_provenance_graph_links_entities(data):
    clean, _ = preprocess(data.head(3000))
    G = build_graph(clean)
    assert G.number_of_nodes() > 50 and G.number_of_edges() > 50
    kinds = {d["ntype"] for _, d in G.nodes(data=True)}
    assert {"ip", "host"} <= kinds
    ip = next(n for n in G if n.startswith("ip:") and G.out_degree(n) > 0)
    assert entity_subgraph(G, ip).number_of_nodes() >= 2


def test_rules_flag_ioc_scan_and_suspicious_process(bundle, test_df):
    clean, _ = preprocess(test_df)
    X = bundle.fb.transform(clean)
    s, hits = apply_rules(clean, X, bundle.cfg)
    assert ((s >= 0) & (s <= 1)).all()
    assert any("R5:PORT_SCAN" in h for h in hits) or any("R7:MULTI_STAGE" in h for h in hits)
    sus = clean["process"].str.contains("mimikatz|psexec", regex=True)
    assert sus.any() and (s[sus.values] >= 0.85).all()


def test_priority_bands(cfg):
    sc = np.array([0, 30, 31, 70, 71, 85, 86, 100.0])
    assert list(to_priority(sc, cfg)) == ["Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"]
    parts = {k: np.ones(3) for k in ("severity", "context", "temporal", "ml")}
    assert (risk_score(parts, cfg) == 100).all()
    parts = {k: np.zeros(3) for k in parts}
    assert (risk_score(parts, cfg) == 0).all()


def test_dedup_queue_and_incidents(bundle, test_df):
    from alert_triage.pipeline import score
    s = score(test_df, bundle)
    assert s["is_duplicate"].sum() > 0
    q = analyst_queue(s)
    assert (q["is_duplicate"] == 0).all() and q["risk_score"].is_monotonic_decreasing
    inc = build_incidents(s)
    assert inc["alerts"].sum() == len(s) and inc["max_risk"].is_monotonic_decreasing
