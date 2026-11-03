"""Evaluation: classification metrics, ranking metrics and analyst-workload reduction.
Compares baselines (severity-only, rule-only, ML-only) with the proposed hybrid model."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score


def classification_metrics(y: np.ndarray, pred: np.ndarray) -> dict:
    y, pred = np.asarray(y).astype(bool), np.asarray(pred).astype(bool)
    tp, fp = int((y & pred).sum()), int((~y & pred).sum())
    fn, tn = int((y & ~pred).sum()), int((~y & ~pred).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"precision": prec, "recall": rec, "f1": f1,
            "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
            "accuracy": (tp + tn) / max(len(y), 1), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def ranking_metrics(y: np.ndarray, s: np.ndarray, ks=(50, 100, 500)) -> dict:
    y = np.asarray(y)
    order = np.argsort(-np.asarray(s), kind="stable")
    out = {"roc_auc": float(roc_auc_score(y, s)) if len(set(y)) > 1 else float("nan"),
           "avg_precision": float(average_precision_score(y, s)) if len(set(y)) > 1 else float("nan")}
    for k in ks:
        if k <= len(y):
            out[f"precision@{k}"] = float(y[order[:k]].mean())
    return out


def evaluate(scored: pd.DataFrame, cfg: dict) -> dict:
    """Needs ground-truth `label` (0/1). Returns a JSON-serialisable report."""
    d = scored[scored["label"] >= 0]
    if d.empty or d["label"].nunique() < 2:
        return {"error": "no ground-truth labels available for evaluation"}
    y = d["label"].values
    thr = cfg["thresholds"]
    methods = {
        "Severity-only (sev>=4)": (d["severity"].values >= 4, d["severity"].values),
        "Rule-only (score>=0.6)": (d["rule_score"].values >= 0.6, d["rule_score"].values),
        "ML-only (p>=0.5)": (d["ml_prob"].values >= 0.5, d["ml_prob"].values),
        "Hybrid risk (High+Critical)": (d["risk_score"].values >= thr["high"], d["risk_score"].values),
        "Hybrid risk (Medium+)": (d["risk_score"].values >= thr["medium"], d["risk_score"].values),
    }
    n = len(d)
    dedup = d["is_duplicate"].values == 0
    report = {"n_alerts": n, "malicious_rate": float(y.mean()), "methods": {}}
    for name, (pred, s) in methods.items():
        m = classification_metrics(y, pred)
        m.update(ranking_metrics(y, s))
        queue = int((pred & dedup).sum())
        m["analyst_queue"] = queue
        m["alert_volume_reduction"] = 1 - queue / n  # alerts analysts do NOT need to open
        m["malicious_captured_in_queue"] = float((y.astype(bool) & pred).sum() / max(y.sum(), 1))
        report["methods"][name] = m
    report["duplicates_suppressed"] = int((~dedup).sum())
    report["duplicate_rate"] = float((~dedup).mean())
    report["priority_breakdown"] = (d.groupby("priority")["label"].agg(alerts="size", malicious="sum",
                                    malicious_rate="mean").reindex(["Low", "Medium", "High", "Critical"])
                                    .fillna(0).round(4).reset_index().to_dict("records"))
    return report


def save_report(report: dict, path: str | Path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(report, indent=2, default=float), encoding="utf-8")


def format_report(report: dict) -> str:
    if "error" in report:
        return report["error"]
    lines = [f"Evaluated on {report['n_alerts']:,} alerts ({report['malicious_rate']:.1%} malicious); "
             f"{report['duplicates_suppressed']:,} duplicates suppressed.", ""]
    hdr = f"{'Method':32s} {'Prec':>6s} {'Recall':>7s} {'F1':>6s} {'FPR':>7s} {'AUC':>6s} {'Vol.red.':>9s}"
    lines += [hdr, "-" * len(hdr)]
    for name, m in report["methods"].items():
        lines.append(f"{name:32s} {m['precision']:6.3f} {m['recall']:7.3f} {m['f1']:6.3f} "
                     f"{m['false_positive_rate']:7.4f} {m['roc_auc']:6.3f} {m['alert_volume_reduction']:9.1%}")
    return "\n".join(lines)
