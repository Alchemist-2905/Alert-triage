"""Rule-based detection engine: severity thresholds, IOC / suspicious-pattern rules, correlation rules."""
from __future__ import annotations

import numpy as np
import pandas as pd


def apply_rules(df: pd.DataFrame, X: pd.DataFrame, cfg: dict) -> tuple[np.ndarray, np.ndarray]:
    """Return (rule_score in 0..1, rule_hits as 'R2:IOC_MATCH;R5:PORT_SCAN;')."""
    r = cfg["rules"]
    sev = df["severity"].values
    rules = [
        ("R1", "HIGH_SEVERITY", sev >= 4, np.where(sev >= 5, 0.8, 0.6)),
        ("R2", "IOC_MATCH", X["ioc_match"].values > 0, 0.9),
        ("R3", "SUSPICIOUS_PORT", X["dst_port_suspicious"].values > 0, 0.3),
        ("R4", "SUSPICIOUS_PROCESS", X["proc_suspicious"].values > 0, 0.85),
        ("R5", "PORT_SCAN", (X["src_distinct_port_w"].values >= r["scan_distinct_ports"])
         | (X["src_distinct_dst_w"].values >= r["scan_distinct_hosts"]), 0.7),
        ("R6", "BRUTE_FORCE", (df["category"].values == "auth_failure")
         & (X["src_alerts_w"].values >= r["bruteforce_alerts"]), 0.75),
        ("R7", "MULTI_STAGE", (X["src_distinct_cat_w"].values >= r["multistage_categories"])
         & (X["src_max_sev_w"].values >= 3), 0.8),
        ("R8", "REPEAT_OFFENDER", X["src_alerts_w"].values >= r["repeat_offender_alerts"], 0.5),
    ]
    n = len(df)
    score, count = np.zeros(n), np.zeros(n)
    hits = np.full(n, "", dtype=object)
    for code, name, mask, w in rules:
        mask = np.asarray(mask, dtype=bool)
        score = np.maximum(score, np.where(mask, w, 0.0))
        count += mask
        if mask.any():
            hits[mask] = hits[mask] + f"{code}:{name};"
    return np.clip(score + 0.05 * np.maximum(count - 1, 0), 0, 1), hits
