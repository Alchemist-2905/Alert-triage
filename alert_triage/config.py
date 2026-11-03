"""Configuration: defaults + optional config.yaml override."""
from __future__ import annotations

import copy
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

DEFAULT_CONFIG: dict = {
    "window": "5min",  # tumbling window for temporal correlation
    "context_window": "30min",  # window for provenance-graph / volume context (= live.window_minutes)
    # Risk = 100 * (w_sev*severity + w_ctx*context + w_tmp*temporal + w_ml*ml_confidence)
    "weights": {"severity": 0.10, "context": 0.20, "temporal": 0.10, "ml": 0.60},
    "context_mix": {"provenance": 0.5, "rules": 0.5},
    # Low 0-30 | Medium 31-70 | High 71-85 | Critical 86-100
    "thresholds": {"medium": 31, "high": 71, "critical": 86},
    "suspicious_ports": [23, 445, 1433, 3389, 4444, 5900, 5985, 6667, 31337],
    "suspicious_process_patterns": [
        r"mimikatz", r"psexec", r"powershell.*-enc", r"certutil.*-urlcache",
        r"\bnc(?:\.exe)?\b.*-e", r"procdump", r"whoami\s*/all", r"vssadmin.*delete",
    ],
    "ioc_ips": [],
    "ioc_file": "data/ioc_ips.txt",
    "rules": {
        "scan_distinct_ports": 15,
        "scan_distinct_hosts": 10,
        "bruteforce_alerts": 10,
        "multistage_categories": 3,
        "repeat_offender_alerts": 50,
    },
    "model": {"n_estimators": 200, "min_samples_leaf": 2, "random_state": 42},
    "live": {"window_minutes": 30, "max_buffer": 8000, "batch_interval": 2.0, "max_batch": 2000},
}


def _merge(base: dict, over: dict) -> dict:
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _merge(base[k], v)
        else:
            base[k] = v
    return base


def load_config(path: str | Path | None = None) -> dict:
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    p = Path(path) if path else ROOT / "config.yaml"
    if p.exists():
        with open(p, encoding="utf-8") as fh:
            _merge(cfg, yaml.safe_load(fh) or {})
    ioc = set(cfg.get("ioc_ips") or [])
    if cfg.get("ioc_file"):
        f = Path(cfg["ioc_file"])
        f = f if f.is_absolute() else ROOT / f
        if f.exists():
            ioc |= {ln.strip() for ln in f.read_text().splitlines()
                    if ln.strip() and not ln.startswith("#")}
    cfg["ioc_set"] = sorted(ioc)
    return cfg
