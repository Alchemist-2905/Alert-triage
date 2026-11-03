"""Feature engineering: alert attributes + temporal correlation + provenance-graph context."""
from __future__ import annotations

import numpy as np
import pandas as pd

from .provenance import graph_features

CAT_COLS = ["proto", "service", "source", "category"]


def time_bucket(df: pd.DataFrame, window: str) -> pd.Series:
    return df["timestamp"].dt.floor(window)


class FeatureBuilder:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.levels: dict[str, list[str]] = {}
        self.extra_cols: list[str] = []
        self.columns_: list[str] | None = None

    def fit(self, df: pd.DataFrame) -> "FeatureBuilder":
        self.levels = {c: df[c].value_counts().head(12).index.tolist() for c in CAT_COLS}
        self.extra_cols = [c for c in df.columns if c.startswith("x_")]
        self.columns_ = None
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        cfg = self.cfg
        f = pd.DataFrame(index=df.index)
        ioc_set = set(cfg.get("ioc_set", []))
        f["severity"] = df["severity"].astype(float)
        f["ioc_match"] = ((df["ioc_match"] > 0) | df["src_ip"].isin(ioc_set) | df["dst_ip"].isin(ioc_set)).astype(float)
        f["dst_port_suspicious"] = df["dst_port"].isin(cfg["suspicious_ports"]).astype(float)
        f["dst_port_well_known"] = ((df["dst_port"] > 0) & (df["dst_port"] < 1024)).astype(float)
        f["bytes_log"] = np.log1p(df["bytes"].astype(float).clip(lower=0))
        f["duration_log"] = np.log1p(df["duration"].astype(float).clip(lower=0))
        hour = df["timestamp"].dt.hour
        f["is_night"] = ((hour < 6) | (hour >= 22)).astype(float)
        f["is_weekend"] = (df["timestamp"].dt.dayofweek >= 5).astype(float)
        rx = "|".join(cfg["suspicious_process_patterns"])
        f["proc_suspicious"] = df["process"].str.contains(rx, case=False, regex=True, na=False).astype(float)
        for c in CAT_COLS:
            for lv in self.levels.get(c, []):
                f[f"{c}={lv}"] = (df[c] == lv).astype(float)

        # temporal correlation inside tumbling windows
        tmp = df[["alert_id", "src_ip", "dst_ip", "dst_port", "signature", "category", "severity"]].copy()
        tmp["_b"] = time_bucket(df, cfg["window"])
        g = tmp.groupby(["src_ip", "_b"], sort=False)
        f["src_alerts_w"] = g["alert_id"].transform("size")
        f["src_distinct_dst_w"] = g["dst_ip"].transform("nunique")
        f["src_distinct_port_w"] = g["dst_port"].transform("nunique")
        f["src_distinct_sig_w"] = g["signature"].transform("nunique")
        f["src_distinct_cat_w"] = g["category"].transform("nunique")
        f["src_max_sev_w"] = g["severity"].transform("max")
        f["dup_count"] = tmp.groupby(["src_ip", "dst_ip", "signature", "_b"], sort=False)["alert_id"].transform("size")
        f["dst_alerts_w"] = tmp.groupby(["dst_ip", "_b"], sort=False)["alert_id"].transform("size")

        # context window: graph/volume features are computed per fixed-length window so the model sees the
        # same scale in batch mode and in the live engine (whose rolling buffer is `live.window_minutes`)
        chunk = df["timestamp"].dt.floor(cfg["context_window"])
        f["src_alerts_ctx"] = tmp.assign(_c=chunk).groupby(["src_ip", "_c"], sort=False)["alert_id"].transform("size")
        parts = [graph_features(df.loc[idx]) for idx in chunk.groupby(chunk).groups.values()]
        f = f.join(pd.concat(parts).reindex(df.index))
        for c in self.extra_cols:
            f[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0) if c in df.columns else 0.0
        f = f.astype("float32")
        if self.columns_ is None:
            self.columns_ = list(f.columns)
        return f.reindex(columns=self.columns_, fill_value=0.0)
