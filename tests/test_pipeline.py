from alert_triage.evaluation import evaluate
from alert_triage.pipeline import ModelBundle, score


def test_hybrid_beats_baselines(bundle, test_df, cfg):
    s = score(test_df, bundle)
    rep = evaluate(s, cfg)
    m = rep["methods"]
    hy, sev, rule = m["Hybrid risk (Medium+)"], m["Severity-only (sev>=4)"], m["Rule-only (score>=0.6)"]
    assert hy["roc_auc"] > 0.97
    assert hy["f1"] > sev["f1"] + 0.3 and hy["f1"] > rule["f1"]
    hi = m["Hybrid risk (High+Critical)"]
    assert hi["precision"] > 0.9 and hi["recall"] > 0.6
    assert hi["alert_volume_reduction"] > 0.9
    assert s["risk_score"].between(0, 100).all() and set(s["priority"]) <= {"Low", "Medium", "High", "Critical"}


def test_explanations_present(bundle, test_df):
    s = score(test_df, bundle)
    top = s[s["priority"].isin(["High", "Critical"])]
    assert len(top) > 0 and top["reasons"].str.contains("ML confidence").all()


def test_model_roundtrip(bundle, test_df, tmp_path):
    p = tmp_path / "m.joblib"
    bundle.save(p)
    s1, s2 = score(test_df.head(500), bundle), score(test_df.head(500), ModelBundle.load(p))
    assert (s1["risk_score"].values == s2["risk_score"].values).all()


def test_unlabelled_data_can_be_scored(bundle, test_df):
    s = score(test_df.drop(columns=["label", "attack_cat"]).head(400), bundle)
    assert (s["label"] == -1).all() and len(s) > 300
