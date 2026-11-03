import numpy as np
import pandas as pd

from alert_triage import pipeline as P
from alert_triage.evaluation import evaluate
from alert_triage.ingest import load_alerts
from alert_triage.unsw import adapt_unsw, is_unsw


def fake_unsw(n=3000, seed=0):
    r = np.random.default_rng(seed)
    lab = (r.random(n) < 0.4).astype(int)
    cats = np.where(lab == 1, r.choice(["Exploits", "Generic", "DoS", "Fuzzers"], n), "Normal")
    return pd.DataFrame({
        "id": range(n), "dur": r.exponential(1, n), "proto": r.choice(["tcp", "udp"], n),
        "service": r.choice(["-", "http", "dns", "ssh"], n), "state": r.choice(["FIN", "CON", "INT"], n),
        "spkts": r.integers(1, 50, n) + lab * 30, "dpkts": r.integers(1, 50, n),
        "sbytes": r.integers(100, 5000, n) * (1 + lab * 3), "dbytes": r.integers(100, 5000, n),
        "attack_cat": cats, "label": lab})


def test_unsw_detected_adapted_and_scored(tmp_path, cfg):
    raw = fake_unsw()
    assert is_unsw(raw)
    p = tmp_path / "UNSW_NB15_training-set.csv"
    raw.to_csv(p, index=False)
    df = load_alerts(p)
    assert len(df) == len(raw) and any(c.startswith("x_") for c in df.columns)
    assert df["signature"].str.startswith("flow").all()          # no label leakage into signature
    assert df.loc[df.label == 1, "src_ip"].nunique() <= 30       # attack campaigns share attacker IPs
    cut = int(len(df) * 0.7)
    b = P.train(df.iloc[:cut], cfg)
    s = P.score(df.iloc[cut:], b)
    rep = evaluate(s, cfg)
    assert rep["methods"]["Hybrid risk (Medium+)"]["roc_auc"] > 0.9
