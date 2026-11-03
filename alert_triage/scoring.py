"""Contextual risk score (0-100) and priority levels.

Risk = 100 * ( w1*severity + w2*context(provenance, rules) + w3*temporal_correlation + w4*ML_confidence )
"""
from __future__ import annotations

import numpy as np
import pandas as pd

PRIORITIES = ["Low", "Medium", "High", "Critical"]


def components(df: pd.DataFrame, X: pd.DataFrame, ml_prob: np.ndarray, rule_score: np.ndarray, cfg: dict) -> dict:
    sev_n = np.clip((df["severity"].values - 1) / 4.0, 0, 1)
    prov = (0.5 * np.tanh(X["prov_out_deg"].values / 25.0) + 0.3 * np.tanh(X["prov_reach3"].values / 40.0)
            + 0.2 * X["prov_pivot"].values)
    mix = cfg["context_mix"]
    context = np.clip(mix["provenance"] * prov + mix["rules"] * rule_score, 0, 1)
    temporal = np.clip(0.4 * np.tanh(X["src_alerts_w"].values / 30.0)
                       + 0.3 * np.tanh(X["src_distinct_dst_w"].values / 15.0)
                       + 0.3 * np.tanh((X["src_distinct_sig_w"].values - 1) / 3.0), 0, 1)
    return {"severity": sev_n, "prov": np.clip(prov, 0, 1), "context": context,
            "temporal": temporal, "ml": np.clip(ml_prob, 0, 1)}


def risk_score(parts: dict, cfg: dict) -> np.ndarray:
    w = cfg["weights"]
    s = sum(w[k] * parts[k] for k in ("severity", "context", "temporal", "ml")) / sum(w.values())
    return np.clip(100.0 * s, 0, 100)


def to_priority(score: np.ndarray, cfg: dict) -> np.ndarray:
    t = cfg["thresholds"]
    return np.select([score >= t["critical"], score >= t["high"], score >= t["medium"]],
                     ["Critical", "High", "Medium"], default="Low").astype(object)
