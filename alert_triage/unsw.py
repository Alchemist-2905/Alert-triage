"""Adapter for the official UNSW-NB15 training/testing CSVs (flow records).

The partitioned UNSW-NB15 files contain flow statistics + `label`/`attack_cat` but NO IP
addresses, timestamps, users or sensor severity. To exercise the context/provenance and
temporal-correlation modules, this adapter *synthesises* that context deterministically:
attack rows are grouped into campaigns that share an attacker IP and a time window, benign
rows are spread over internal hosts. The sensor severity is a noisy function of the attack
category (as an IDS would assign). Ground-truth labels are never given to the model as a
feature. This is documented as an evaluation assumption in the README.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .data_gen import ATTACKERS, EXTERNAL, HOSTNAME, INTERNAL, SERVERS
from .ingest import CANON_COLS

SERVICE_PORT = {"http": 80, "ftp": 21, "ftp-data": 20, "smtp": 25, "ssh": 22, "dns": 53, "pop3": 110,
                "snmp": 161, "ssl": 443, "irc": 6667, "radius": 1812, "dhcp": 67}
SEV_BASE = {"normal": 1, "generic": 2, "fuzzers": 2, "reconnaissance": 2, "analysis": 2, "dos": 3,
            "exploits": 3, "backdoor": 4, "backdoors": 4, "shellcode": 4, "worms": 5}
DROP = {"id", "label", "attack_cat"}


def is_unsw(df: pd.DataFrame) -> bool:
    cols = {str(c).lower() for c in df.columns}
    return {"sbytes", "dbytes", "attack_cat", "label", "proto", "state"} <= cols


def adapt_unsw(raw: pd.DataFrame, seed: int = 7, span_days: int = 7) -> pd.DataFrame:
    d = raw.copy()
    d.columns = [str(c).lower() for c in d.columns]
    rng = np.random.default_rng(seed)
    n = len(d)
    label = pd.to_numeric(d["label"], errors="coerce").fillna(0).astype(int).values
    cat = d["attack_cat"].fillna("normal").astype(str).str.strip().str.lower().replace({"": "normal"}).values
    span = span_days * 86400.0
    ts = np.zeros(n)
    src = np.empty(n, dtype=object)
    dst = np.empty(n, dtype=object)
    inside = INTERNAL + SERVERS

    ben = np.where(label == 0)[0]
    ts[ben] = rng.uniform(0, span, len(ben))
    src[ben] = rng.choice(INTERNAL, len(ben))
    dst[ben] = rng.choice(SERVERS + EXTERNAL[:60], len(ben))

    att = np.where(label == 1)[0]
    rng.shuffle(att)
    pos = 0
    while pos < len(att):
        size = int(rng.integers(30, 300))
        idx = att[pos:pos + size]
        pos += size
        start = rng.uniform(0, span - 3600)
        ts[idx] = start + np.sort(rng.uniform(0, rng.uniform(300, 1800), len(idx)))
        src[idx] = ATTACKERS[int(rng.integers(len(ATTACKERS)))]
        targets = rng.choice(inside, int(rng.integers(1, 15)), replace=False)
        dst[idx] = rng.choice(targets, len(idx))

    service = d["service"].fillna("-").astype(str).str.lower().replace({"-": "none"})
    port = service.map(SERVICE_PORT).fillna(0).astype(int).values
    base = np.array([SEV_BASE.get(c, 2) for c in cat])
    noise = rng.random(n) < 0.30
    sev = np.where(label == 1, base + np.where(noise, rng.choice([-1, 1], n), 0),
                   np.where(rng.random(n) < 0.06, rng.integers(2, 5, n), 1))
    sev = np.clip(sev, 1, 5)

    out = pd.DataFrame({
        "alert_id": [f"U{i:07d}" for i in range(n)],
        "timestamp": pd.Timestamp("2026-10-01") + pd.to_timedelta(ts, unit="s"),
        "source": "ids", "src_ip": src, "dst_ip": dst, "dst_port": port,
        "proto": d["proto"].astype(str).str.lower(), "service": service,
        "host": [HOSTNAME.get(x, x) for x in dst], "user": "unknown", "process": "unknown",
        "signature": "flow " + d["proto"].astype(str) + "/" + service + "/" + d["state"].astype(str),
        "category": "flow", "severity": sev,
        "bytes": pd.to_numeric(d["sbytes"], errors="coerce").fillna(0) + pd.to_numeric(d["dbytes"], errors="coerce").fillna(0),
        "duration": pd.to_numeric(d["dur"], errors="coerce").fillna(0) if "dur" in d else 0.0,
        "ioc_match": 0, "label": label, "attack_cat": cat,
    })
    for c in d.columns:
        if c not in DROP and pd.api.types.is_numeric_dtype(d[c]):
            out["x_" + c] = d[c].values
    return out[CANON_COLS + [c for c in out.columns if c.startswith("x_")]]
