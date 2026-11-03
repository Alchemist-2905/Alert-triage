"""Preprocessing: missing values, duplicates, normalisation, timestamp parsing."""
from __future__ import annotations

import hashlib

import numpy as np
import pandas as pd

from .ingest import STR_COLS, ensure_columns


def preprocess(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Return (clean_df sorted by time, stats)."""
    df = ensure_columns(df.copy())
    stats = {"rows_in": int(len(df))}

    ts = df["timestamp"]
    if pd.api.types.is_numeric_dtype(ts):
        parsed = pd.to_datetime(ts, unit="s", errors="coerce")
    else:
        parsed = pd.to_datetime(ts, errors="coerce", utc=True, format="ISO8601")
        bad = parsed.isna() & ts.notna()
        if bad.any():  # non-ISO strings: let pandas guess element-wise
            parsed[bad] = pd.to_datetime(ts[bad], errors="coerce", utc=True, format="mixed")
        parsed = parsed.dt.tz_convert(None)
    df["timestamp"] = parsed
    stats["bad_timestamps_dropped"] = int(parsed.isna().sum())
    df = df[parsed.notna()].copy()

    filled = 0
    for c in STR_COLS:
        s = df[c].astype(object).where(df[c].notna(), "")
        s = s.astype(str).str.strip().str.lower()
        blank = s.isin(["", "nan", "none", "null", "-", "<na>"])
        if c == "alert_id":
            s = s.where(~blank, "")
        else:
            filled += int(blank.sum())
            s = s.where(~blank, "unknown")
        df[c] = s.astype(object)
    for c, default in [("severity", 2), ("dst_port", 0), ("bytes", 0), ("duration", 0.0),
                       ("ioc_match", 0), ("label", -1)]:
        num = pd.to_numeric(df[c], errors="coerce")
        filled += int(num.isna().sum())
        df[c] = num.fillna(default)
    df["severity"] = df["severity"].round().clip(1, 5).astype(int)
    df["dst_port"] = df["dst_port"].clip(0, 65535).astype(int)
    df["ioc_match"] = (df["ioc_match"] > 0).astype(int)
    df["label"] = df["label"].astype(int)
    stats["missing_values_filled"] = filled

    key = ["timestamp", "src_ip", "dst_ip", "dst_port", "signature", "process", "host", "user", "bytes"]
    before = len(df)
    df = df.drop_duplicates(subset=key, keep="first")
    stats["exact_duplicates_removed"] = int(before - len(df))

    df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
    blank_id = df["alert_id"] == ""
    if blank_id.any():
        df.loc[blank_id, "alert_id"] = [
            "a-" + hashlib.sha1(f"{r.timestamp}|{r.src_ip}|{r.dst_ip}|{r.signature}|{i}".encode()).hexdigest()[:12]
            for i, r in zip(df.index[blank_id], df.loc[blank_id].itertuples())
        ]
    df = df.drop_duplicates(subset="alert_id", keep="first").reset_index(drop=True)
    stats["rows_out"] = int(len(df))
    for c in df.columns:
        if c.startswith("x_"):
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0).astype(np.float32)
    return df, stats
