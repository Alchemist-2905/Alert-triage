"""Ingestion: load alerts from CSV / JSON / JSONL and normalise vendor formats
(Suricata eve.json, Wazuh alerts.json, generic) into one canonical schema."""
from __future__ import annotations

import json
import math
from pathlib import Path

import pandas as pd

CANON_COLS = [
    "alert_id", "timestamp", "source", "src_ip", "dst_ip", "dst_port", "proto", "service",
    "host", "user", "process", "signature", "category", "severity", "bytes", "duration",
    "ioc_match", "label", "attack_cat",
]
STR_COLS = ["alert_id", "source", "src_ip", "dst_ip", "proto", "service", "host", "user",
            "process", "signature", "category", "attack_cat"]
ALIASES = {
    "src": "src_ip", "source_ip": "src_ip", "srcip": "src_ip", "src_addr": "src_ip",
    "dest_ip": "dst_ip", "dst": "dst_ip", "dstip": "dst_ip", "destination_ip": "dst_ip",
    "dest_port": "dst_port", "dport": "dst_port", "destination_port": "dst_port",
    "time": "timestamp", "@timestamp": "timestamp", "ts": "timestamp", "event_time": "timestamp",
    "hostname": "host", "agent_name": "host", "username": "user", "process_name": "process",
    "image": "process", "rule": "signature", "alert_signature": "signature", "msg": "signature",
    "level": "severity", "sev": "severity", "id": "alert_id", "event_id": "alert_id",
}


def _suricata(rec: dict) -> dict:
    a = rec["alert"]
    sev = {1: 5, 2: 3, 3: 2}.get(int(a.get("severity", 3) or 3), 1)  # eve: 1 = high
    flow = rec.get("flow") or {}
    fid = rec.get("flow_id")
    return {
        "alert_id": f"sur-{fid}-{rec.get('timestamp')}" if fid else None,
        "timestamp": rec.get("timestamp"), "source": "suricata",
        "src_ip": rec.get("src_ip"), "dst_ip": rec.get("dest_ip"), "dst_port": rec.get("dest_port"),
        "proto": str(rec.get("proto", "")).lower(), "service": rec.get("app_proto"),
        "host": rec.get("host"), "signature": a.get("signature"), "category": a.get("category"),
        "severity": sev,
        "bytes": (flow.get("bytes_toserver") or 0) + (flow.get("bytes_toclient") or 0),
    }


def _wazuh(rec: dict) -> dict:
    r, data, agent = rec["rule"], rec.get("data") or {}, rec.get("agent") or {}
    lvl = int(r.get("level", 0) or 0)
    groups = r.get("groups") or ["wazuh"]
    return {
        "alert_id": rec.get("id"), "timestamp": rec.get("timestamp"), "source": "wazuh",
        "src_ip": data.get("srcip") or agent.get("ip"), "dst_ip": data.get("dstip") or agent.get("ip"),
        "dst_port": data.get("dstport"), "host": agent.get("name"),
        "user": data.get("dstuser") or data.get("srcuser"),
        "process": data.get("process") or data.get("command"),
        "signature": r.get("description"), "category": groups[0],
        "severity": min(5, max(1, math.ceil(lvl / 3))),
    }


def flatten_record(rec: dict) -> dict:
    """Detect vendor format of a single JSON record and map it to canonical keys."""
    if isinstance(rec.get("alert"), dict) and ("src_ip" in rec or "dest_ip" in rec):
        return _suricata(rec)
    if isinstance(rec.get("rule"), dict) and "level" in rec["rule"]:
        return _wazuh(rec)
    return rec


DEFAULTS = {"alert_id": None, "timestamp": None, "source": "unknown", "dst_port": 0,
            "severity": 2, "bytes": 0, "duration": 0.0, "ioc_match": 0, "label": -1}


def ensure_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Add any missing canonical columns with neutral defaults."""
    for c in CANON_COLS:
        if c not in df.columns:
            df[c] = DEFAULTS.get(c, "unknown")
    return df


def normalize_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Rename aliases (merging with existing columns), add missing canonical columns, keep `x_*` extras."""
    df = df.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]
    for alias, target in ALIASES.items():
        if alias in df.columns:
            if target in df.columns:
                df[target] = df[target].combine_first(df[alias])
                df = df.drop(columns=alias)
            else:
                df = df.rename(columns={alias: target})
    df = ensure_columns(df)
    extra = [c for c in df.columns if c.startswith("x_")]
    return df[CANON_COLS + extra].reset_index(drop=True)


def records_to_frame(records: list[dict]) -> pd.DataFrame:
    if not records:
        return normalize_frame(pd.DataFrame(columns=CANON_COLS))
    flat = [flatten_record(r) for r in records if isinstance(r, dict)]
    return normalize_frame(pd.DataFrame(flat))


def read_json_records(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    if text[0] == "[":
        return json.loads(text)
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def load_alerts(path: str | Path) -> pd.DataFrame:
    """Load a CSV / JSON / JSONL file. UNSW-NB15 CSVs are detected automatically."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Input file not found: {p}")
    if p.suffix.lower() == ".csv":
        raw = pd.read_csv(p, low_memory=False)
        from .unsw import adapt_unsw, is_unsw
        if is_unsw(raw):
            return adapt_unsw(raw)
        return normalize_frame(raw)
    return records_to_frame(read_json_records(p))
