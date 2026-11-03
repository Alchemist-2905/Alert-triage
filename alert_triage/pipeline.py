"""End-to-end pipeline: preprocess -> features -> (rules || ML) -> risk score -> triage."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from .features import FeatureBuilder
from .preprocess import preprocess
from .rules import apply_rules
from .scoring import components, risk_score, to_priority
from .triage import mark_duplicates


@dataclass
class ModelBundle:
    cfg: dict
    fb: FeatureBuilder
    rf: RandomForestClassifier
    columns: list
    importances: np.ndarray
    mu: np.ndarray
    sd: np.ndarray
    meta: dict = field(default_factory=dict)

    def save(self, path: str | Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path, compress=3)

    @staticmethod
    def load(path: str | Path) -> "ModelBundle":
        return joblib.load(path)


def train(df: pd.DataFrame, cfg: dict) -> ModelBundle:
    """Fit the feature builder and Random Forest classifier on a labelled alert frame."""
    df, stats = preprocess(df)
    df = df[df["label"] >= 0].reset_index(drop=True)
    if df.empty or df["label"].nunique() < 2:
        raise ValueError("Training data needs labelled alerts with both classes (label 0 and 1).")
    fb = FeatureBuilder(cfg).fit(df)
    X = fb.transform(df)
    m = cfg["model"]
    rf = RandomForestClassifier(
        n_estimators=m["n_estimators"], min_samples_leaf=m["min_samples_leaf"],
        class_weight="balanced_subsample", n_jobs=-1, random_state=m["random_state"],
    ).fit(X.values, df["label"].values)
    sd = X.values.std(axis=0)
    sd[sd == 0] = 1.0
    meta = {"trained_rows": int(len(df)), "positive_rate": float(df["label"].mean()), "n_features": X.shape[1],
            "preprocess": stats}
    return ModelBundle(cfg, fb, rf, list(X.columns), rf.feature_importances_, X.values.mean(axis=0), sd, meta)


def _reasons(df, X, parts, hits, risk, bundle) -> np.ndarray:
    out = np.full(len(df), "low risk: no strong indicators", dtype=object)
    mask = risk >= bundle.cfg["thresholds"]["medium"]
    if not mask.any():
        return out
    Xm = X.values[mask]
    z = np.clip((Xm - bundle.mu) / bundle.sd, 0, 6) * bundle.importances  # importance-weighted elevation
    top = np.argsort(-z, axis=1)[:, :3]
    sev, ml = df["severity"].values[mask], parts["ml"][mask]
    h = hits[mask]
    texts = []
    for i in range(len(top)):
        feats = ", ".join(f"{bundle.columns[j]}={Xm[i, j]:.3g}" for j in top[i] if z[i, j] > 0)
        texts.append(f"severity {sev[i]}/5 | ML confidence {ml[i]:.2f} | rules: {h[i] or 'none'} | elevated: {feats or '-'}")
    out[mask] = texts
    return out


def score(df: pd.DataFrame, bundle: ModelBundle, already_clean: bool = False, explain: bool = True) -> pd.DataFrame:
    """Score a frame of alerts; returns it with risk_score, priority, reasons, etc."""
    if not already_clean:
        df, _ = preprocess(df)
    df = df.reset_index(drop=True)
    cfg = bundle.cfg
    X = bundle.fb.transform(df)
    prob = bundle.rf.predict_proba(X.values)
    prob = prob[:, 1] if prob.shape[1] == 2 else np.zeros(len(df))
    rule_s, hits = apply_rules(df, X, cfg)
    parts = components(df, X, prob, rule_s, cfg)
    risk = risk_score(parts, cfg)
    out = df.copy()
    out["ml_prob"] = prob.round(4)
    out["rule_score"] = rule_s.round(4)
    out["prov_score"] = parts["prov"].round(4)
    out["temporal_score"] = parts["temporal"].round(4)
    out["risk_score"] = risk.round(2)
    out["priority"] = to_priority(risk, cfg)
    out["rule_hits"] = hits
    out["reasons"] = _reasons(df, X, parts, hits, risk, bundle) if explain else ""
    out = mark_duplicates(out, cfg["window"])
    return out
