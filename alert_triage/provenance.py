"""Provenance / context graph (NetworkX): users, hosts, processes, IPs and the events linking them."""
from __future__ import annotations

import networkx as nx
import numpy as np
import pandas as pd

NODE_COLS = ["out_deg", "in_deg", "pagerank", "component", "reach3", "pivot"]
_SPECS = [
    ("src_ip", "dst_ip", "ip", "ip", "communicates"),
    ("dst_ip", "host", "ip", "host", "resolves_to"),
    ("user", "host", "user", "host", "logged_on"),
    ("process", "host", "process", "host", "executed_on"),
]


def build_graph(df: pd.DataFrame) -> nx.DiGraph:
    """Directed graph; edge attrs: n (alert count), max_sev, rel."""
    G = nx.DiGraph()
    for a, b, ta, tb, rel in _SPECS:
        sub = df[(df[a] != "unknown") & (df[b] != "unknown") & (df[a].astype(str) != df[b].astype(str))]
        if sub.empty:
            continue
        e = sub.groupby([a, b]).agg(n=("alert_id", "size"), max_sev=("severity", "max")).reset_index()
        for x, y, n, s in e.itertuples(index=False):
            u, v = f"{ta}:{x}", f"{tb}:{y}"
            if not G.has_node(u):
                G.add_node(u, ntype=ta)
            if not G.has_node(v):
                G.add_node(v, ntype=tb)
            if G.has_edge(u, v):
                G[u][v]["n"] += int(n)
                G[u][v]["max_sev"] = max(G[u][v]["max_sev"], int(s))
            else:
                G.add_edge(u, v, rel=rel, n=int(n), max_sev=int(s))
    return G


def node_features(G: nx.DiGraph) -> pd.DataFrame:
    if G.number_of_nodes() == 0:
        return pd.DataFrame(columns=NODE_COLS)
    try:
        pr = nx.pagerank(G, weight="n", max_iter=100, tol=1e-6)
    except Exception:  # convergence problems on tiny / odd graphs
        pr = {n: 1.0 / G.number_of_nodes() for n in G}
    comp = {}
    for c in nx.connected_components(G.to_undirected(as_view=True)):
        for node in c:
            comp[node] = len(c)
    rows = {}
    for node in G.nodes:
        out_d, in_d = G.out_degree(node), G.in_degree(node)
        reach = 0
        if out_d > 0 and node.startswith("ip:"):
            reach = len(nx.single_source_shortest_path_length(G, node, cutoff=3)) - 1
        rows[node] = (out_d, in_d, pr.get(node, 0.0), comp.get(node, 1), reach,
                      float(out_d > 0 and in_d > 0 and node.startswith("ip:")))
    return pd.DataFrame.from_dict(rows, orient="index", columns=NODE_COLS)


def graph_features(df: pd.DataFrame) -> pd.DataFrame:
    """Per-alert provenance features, aligned with df.index."""
    nf = node_features(build_graph(df))
    out = pd.DataFrame(index=df.index)
    sn, dn = "ip:" + df["src_ip"].astype(str), "ip:" + df["dst_ip"].astype(str)
    for col, key, nodes in [("prov_out_deg", "out_deg", sn), ("prov_in_deg", "in_deg", sn),
                            ("prov_pagerank", "pagerank", sn), ("prov_component", "component", sn),
                            ("prov_reach3", "reach3", sn), ("prov_pivot", "pivot", sn),
                            ("prov_dst_in_deg", "in_deg", dn)]:
        out[col] = nodes.map(nf[key]).fillna(0).astype(float).values if len(nf) else 0.0
    out["prov_user_hosts"] = ("user:" + df["user"].astype(str)).map(nf["out_deg"]).fillna(0).astype(float).values if len(nf) else 0.0
    out["prov_proc_hosts"] = ("process:" + df["process"].astype(str)).map(nf["out_deg"]).fillna(0).astype(float).values if len(nf) else 0.0
    return out


def entity_subgraph(G: nx.DiGraph, entity: str, radius: int = 2, max_nodes: int = 60) -> nx.DiGraph:
    """Ego graph around an entity (e.g. 'ip:185.10.0.1') used by the dashboard and for explanation."""
    if entity not in G:
        return nx.DiGraph()
    sub = nx.ego_graph(G, entity, radius=radius, undirected=True)
    if sub.number_of_nodes() > max_nodes:
        keep = sorted(sub.nodes, key=lambda n: -sub.degree(n))[:max_nodes]
        if entity not in keep:
            keep[-1] = entity
        sub = sub.subgraph(keep).copy()
    return sub
