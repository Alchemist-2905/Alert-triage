"""Alert triage: de-duplication, ranking queue and incident (entity-session) grouping."""
from __future__ import annotations

import pandas as pd

from .features import time_bucket
from .scoring import PRIORITIES


def mark_duplicates(df: pd.DataFrame, window: str) -> pd.DataFrame:
    """is_duplicate = a repeat of (src, dst, signature) inside the same window; dup_count = repeats so far."""
    df = df.sort_values("timestamp", kind="stable")
    key = [df["src_ip"], df["dst_ip"], df["signature"], time_bucket(df, window)]
    seq = df.groupby(key, sort=False).cumcount()
    df = df.assign(dup_count=seq + 1, is_duplicate=(seq > 0).astype(int))
    return df.sort_index()


def analyst_queue(df: pd.DataFrame) -> pd.DataFrame:
    """Ranked, de-duplicated worklist (highest risk first)."""
    return df[df["is_duplicate"] == 0].sort_values(["risk_score", "timestamp"], ascending=[False, True])


def build_incidents(df: pd.DataFrame, gap_minutes: int = 30) -> pd.DataFrame:
    """Group alerts into incidents: same source entity, new incident after `gap_minutes` of silence."""
    if df.empty:
        return pd.DataFrame()
    d = df.sort_values("timestamp", kind="stable").copy()
    gap = d.groupby("src_ip")["timestamp"].diff() > pd.Timedelta(minutes=gap_minutes)
    seq = gap.groupby(d["src_ip"]).cumsum()
    d["incident_id"] = d["src_ip"] + "#" + seq.astype(int).astype(str)
    agg = d.groupby("incident_id").agg(
        src_ip=("src_ip", "first"), alerts=("alert_id", "size"),
        first_seen=("timestamp", "min"), last_seen=("timestamp", "max"),
        max_risk=("risk_score", "max"), mean_risk=("risk_score", "mean"),
        distinct_signatures=("signature", "nunique"), distinct_targets=("dst_ip", "nunique"),
        top_signature=("signature", lambda s: s.value_counts().index[0]),
    ).reset_index()
    if "label" in d.columns and (d["label"] >= 0).any():
        agg = agg.merge(d.groupby("incident_id")["label"].max().rename("any_malicious").reset_index(), on="incident_id")
    return agg.sort_values("max_risk", ascending=False).reset_index(drop=True)
