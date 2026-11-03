"""SQLite alert store shared by the batch pipeline, the live engine and the dashboard (WAL mode)."""
from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd

COLS = [
    ("alert_id", "TEXT PRIMARY KEY"), ("timestamp", "TEXT"), ("source", "TEXT"), ("src_ip", "TEXT"),
    ("dst_ip", "TEXT"), ("dst_port", "INTEGER"), ("proto", "TEXT"), ("service", "TEXT"), ("host", "TEXT"),
    ("user", "TEXT"), ("process", "TEXT"), ("signature", "TEXT"), ("category", "TEXT"),
    ("severity", "INTEGER"), ("bytes", "REAL"), ("duration", "REAL"), ("ioc_match", "INTEGER"),
    ("label", "INTEGER"), ("attack_cat", "TEXT"), ("ml_prob", "REAL"), ("rule_score", "REAL"),
    ("prov_score", "REAL"), ("temporal_score", "REAL"), ("risk_score", "REAL"), ("priority", "TEXT"),
    ("rule_hits", "TEXT"), ("reasons", "TEXT"), ("dup_count", "INTEGER"), ("is_duplicate", "INTEGER"),
    ("ingested_at", "TEXT"),
]
NAMES = [c for c, _ in COLS]


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute(f"CREATE TABLE IF NOT EXISTS triaged ({', '.join(f'{c} {t}' for c, t in COLS)})")
        self.conn.execute("CREATE INDEX IF NOT EXISTS ix_risk ON triaged(risk_score)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS ix_ts ON triaged(timestamp)")
        self.conn.commit()

    def clear(self):
        self.conn.execute("DELETE FROM triaged")
        self.conn.commit()

    def write(self, df: pd.DataFrame) -> int:
        if df.empty:
            return 0
        d = df.copy()
        d["timestamp"] = d["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%S.%f")
        d["ingested_at"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        for c in NAMES:
            if c not in d.columns:
                d[c] = None
        rows = d[NAMES].astype(object).where(d[NAMES].notna(), None).values.tolist()
        self.conn.executemany(
            f"INSERT OR REPLACE INTO triaged ({','.join(NAMES)}) VALUES ({','.join('?' * len(NAMES))})", rows)
        self.conn.commit()
        return len(rows)

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM triaged").fetchone()[0]

    def read(self, limit: int | None = None, newest: bool = True) -> pd.DataFrame:
        q = "SELECT * FROM triaged ORDER BY timestamp " + ("DESC" if newest else "ASC")
        if limit:
            q += f" LIMIT {int(limit)}"
        df = pd.read_sql_query(q, self.conn)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df.sort_values("timestamp").reset_index(drop=True)

    def close(self):
        self.conn.close()
