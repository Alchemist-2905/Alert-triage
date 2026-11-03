import json

import pandas as pd

from alert_triage.ingest import CANON_COLS, load_alerts, records_to_frame
from alert_triage.preprocess import preprocess

SURICATA = {"timestamp": "2026-10-31T10:00:00.000000+0000", "flow_id": 123, "src_ip": "1.2.3.4",
            "dest_ip": "10.0.0.5", "dest_port": 445, "proto": "TCP",
            "alert": {"signature": "ET EXPLOIT SMB", "category": "Attempted Admin", "severity": 1}}
WAZUH = {"id": "w1", "timestamp": "2026-10-31T10:00:01Z", "rule": {"level": 12, "description": "Brute force", "groups": ["authentication_failed"]},
         "agent": {"name": "web01", "ip": "10.0.0.9"}, "data": {"srcip": "5.6.7.8", "dstuser": "root"}}


def test_vendor_formats_are_normalised():
    df = records_to_frame([SURICATA, WAZUH, {"src": "9.9.9.9", "dst": "10.0.0.1", "time": "2026-10-31T10:00:02", "level": 3}])
    assert list(df.columns[: len(CANON_COLS)]) == CANON_COLS
    assert df.loc[0, "severity"] == 5 and df.loc[0, "dst_port"] == 445     # suricata sev 1 -> 5
    assert df.loc[1, "severity"] == 4 and df.loc[1, "src_ip"] == "5.6.7.8"  # wazuh level 12 -> 4
    assert df.loc[2, "src_ip"] == "9.9.9.9"                                 # aliases


def test_preprocess_cleans_and_dedups():
    recs = [SURICATA, dict(SURICATA), {"timestamp": "bad", "src_ip": "1.1.1.1"},
            {"timestamp": "2026-10-31T10:00:05", "src_ip": None, "dst_ip": "10.0.0.2", "severity": 99}]
    clean, st = preprocess(records_to_frame(recs))
    assert st["exact_duplicates_removed"] == 1 and st["bad_timestamps_dropped"] == 1
    assert clean["severity"].between(1, 5).all()
    assert (clean["src_ip"] == "unknown").sum() == 1
    assert clean["alert_id"].is_unique and clean["timestamp"].is_monotonic_increasing


def test_load_jsonl_and_csv(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in [SURICATA, WAZUH]) + "\nnot json\n")
    assert len(load_alerts(p)) == 2
    c = tmp_path / "a.csv"
    pd.DataFrame([{"src": "1.1.1.1", "dst": "2.2.2.2", "time": "2026-10-31T10:00:00", "severity": 2}]).to_csv(c, index=False)
    assert load_alerts(c).loc[0, "dst_ip"] == "2.2.2.2"
