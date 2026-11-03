"""Command-line interface:  python main.py <command> --help"""
from __future__ import annotations

import argparse
import subprocess
import sys
import warnings
from pathlib import Path

import pandas as pd

from .config import ROOT, load_config
from .data_gen import KNOWN_BAD, generate_dataset, simulate
from .evaluation import evaluate, format_report, save_report
from .ingest import load_alerts
from .pipeline import ModelBundle, score, train
from .preprocess import preprocess
from .store import Store
from .triage import analyst_queue, build_incidents

warnings.filterwarnings("ignore", category=UserWarning)
DEFAULT_MODEL = ROOT / "models" / "default.joblib"


def _p(path):
    p = Path(path)
    return p if p.is_absolute() else Path.cwd() / p


def ensure_ioc_file():
    f = ROOT / "data" / "ioc_ips.txt"
    if not f.exists():
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("# Known-bad IPs (threat-intel feed). One per line.\n" + "\n".join(KNOWN_BAD) + "\n")


def ensure_default_model(cfg, retrain=False) -> ModelBundle:
    if DEFAULT_MODEL.exists() and not retrain:
        return ModelBundle.load(DEFAULT_MODEL)
    print("[model] training default model on synthetic alerts ...")
    b = train(generate_dataset(60000, seed=42, days=1), cfg)
    b.save(DEFAULT_MODEL)
    return b


def cmd_generate(a, cfg):
    df = generate_dataset(a.n, seed=a.seed, days=a.days)
    out = _p(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    print(f"[generate] {len(df):,} alerts ({df['label'].mean():.1%} malicious) -> {out}")


def cmd_train(a, cfg):
    b = train(load_alerts(_p(a.train)), cfg)
    b.save(_p(a.model))
    print(f"[train] model saved to {a.model} | rows={b.meta['trained_rows']:,} features={b.meta['n_features']}")
    top = sorted(zip(b.columns, b.importances), key=lambda t: -t[1])[:10]
    print("[train] top features:", ", ".join(f"{n} ({v:.3f})" for n, v in top))


def cmd_batch(a, cfg):
    """Historical analysis. Train on --train (or a 70% time split of --input) and score the rest."""
    raw = load_alerts(_p(a.input))
    df, stats = preprocess(raw)
    print(f"[ingest] {stats['rows_in']:,} rows -> {stats['rows_out']:,} after cleaning "
          f"({stats['exact_duplicates_removed']:,} exact duplicates, {stats['missing_values_filled']:,} missing values filled)")
    model_path = _p(a.model) if a.model else DEFAULT_MODEL
    if a.train:
        bundle = train(load_alerts(_p(a.train)), cfg)
        bundle.save(model_path)
        test = df
        print(f"[train] fitted on {a.train} ({bundle.meta['trained_rows']:,} alerts)")
    elif model_path.exists() and not a.retrain:
        bundle, test = ModelBundle.load(model_path), df
        print(f"[model] loaded {model_path}")
    else:
        if (df["label"] < 0).all():
            sys.exit("No model available and input has no labels. Run `python main.py demo` or pass --train FILE.")
        cut = int(len(df) * 0.7)
        bundle, test = train(df.iloc[:cut], cfg), df.iloc[cut:].reset_index(drop=True)
        bundle.save(model_path)
        print(f"[train] chronological 70/30 split: trained on {cut:,}, testing on {len(test):,}")
    scored = score(test, bundle, already_clean=True)
    db = _p(a.db)
    store = Store(db)
    store.clear()
    store.write(scored)
    store.close()
    rep = evaluate(scored, bundle.cfg)
    print("\n" + format_report(rep))
    rep_path = _p(a.report) if a.report else db.with_suffix(".metrics.json")
    save_report(rep, rep_path)
    q = analyst_queue(scored)
    print(f"\n[triage] priorities: {scored['priority'].value_counts().to_dict()}")
    print(f"[triage] incidents: {len(build_incidents(scored))} | analyst queue (deduplicated): {len(q):,}")
    print("\nTop 10 alerts for the analyst:")
    cols = ["timestamp", "src_ip", "dst_ip", "signature", "risk_score", "priority"]
    print(q[cols].head(10).to_string(index=False))
    print(f"\n[done] results -> {db}  | report -> {rep_path}\n       view with: python main.py dashboard")


def cmd_live(a, cfg):
    from .realtime import run_live
    ensure_ioc_file()
    mp = _p(a.model) if a.model else DEFAULT_MODEL
    bundle = ModelBundle.load(mp) if mp.exists() else ensure_default_model(cfg)
    run_live(bundle, str(_p(a.db)), [str(_p(w)) for w in (a.watch or [])], a.http_port, a.from_start,
             simulate_feed=bool(getattr(a, "simulate", False)))


def cmd_simulate(a, cfg):
    simulate(_p(a.out), rate=a.rate, duration=a.duration, campaign_every=a.campaign_every)


def cmd_dashboard(a, cfg):
    app = ROOT / "dashboard" / "app.py"
    sys.exit(subprocess.call([sys.executable, "-m", "streamlit", "run", str(app),
                              "--server.port", str(a.port), "--browser.gatherUsageStats", "false"]))


def cmd_demo(a, cfg):
    """One command: generate data -> train -> evaluate -> store results for the dashboard."""
    ensure_ioc_file()
    cfg = load_config()  # reload so the IOC file written above is picked up
    data = ROOT / "data" / "synthetic_alerts.csv"
    if not data.exists():
        generate_dataset(60000, seed=42, days=1).to_csv(data, index=False)
        print(f"[demo] generated {data}")
    ns = argparse.Namespace(input=str(data), train=None, model=str(DEFAULT_MODEL), retrain=True,
                            db=str(ROOT / "output" / "batch.db"), report=None)
    cmd_batch(ns, cfg)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="main.py", description="AI-Based Cyber Incident Prioritization and Risk-Aware Alert Triage")
    ap.add_argument("--config", help="path to config.yaml")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("demo", help="generate synthetic data, train, evaluate, fill the dashboard DB")
    s.set_defaults(fn=cmd_demo)
    s = sub.add_parser("generate", help="create a synthetic labelled alert CSV")
    s.add_argument("--n", type=int, default=60000); s.add_argument("--seed", type=int, default=42)
    s.add_argument("--days", type=int, default=1); s.add_argument("--out", default="data/synthetic_alerts.csv")
    s.set_defaults(fn=cmd_generate)
    s = sub.add_parser("train", help="train the Random Forest on a labelled file (CSV/JSON/UNSW-NB15)")
    s.add_argument("--train", required=True); s.add_argument("--model", default="models/default.joblib")
    s.set_defaults(fn=cmd_train)
    s = sub.add_parser("batch", help="historical analysis + evaluation of an alert file")
    s.add_argument("--input", required=True, help="alerts to triage (CSV/JSON/JSONL; UNSW-NB15 auto-detected)")
    s.add_argument("--train", help="labelled file to train on (e.g. UNSW_NB15_training-set.csv)")
    s.add_argument("--model"); s.add_argument("--retrain", action="store_true")
    s.add_argument("--db", default="output/batch.db"); s.add_argument("--report")
    s.set_defaults(fn=cmd_batch)
    s = sub.add_parser("live", help="real-time triage: tail files and/or accept HTTP POSTs")
    s.add_argument("--watch", nargs="*", help="JSONL file(s) to follow, e.g. /var/log/suricata/eve.json")
    s.add_argument("--http-port", type=int, help="also listen for POST /alert on this port")
    s.add_argument("--simulate", action="store_true", help="stream simulated enterprise SOC events in real time")
    s.add_argument("--from-start", action="store_true", help="process existing file content first")
    s.add_argument("--model"); s.add_argument("--db", default="output/live.db")
    s.set_defaults(fn=cmd_live)
    s = sub.add_parser("simulate", help="write a simulated live alert feed (JSONL)")
    s.add_argument("--out", default="data/live/alerts.jsonl"); s.add_argument("--rate", type=float, default=1.0, help="mean background alerts per second")
    s.add_argument("--campaign-every", type=float, default=240, help="mean seconds between attack campaigns")
    s.add_argument("--duration", type=float); s.set_defaults(fn=cmd_simulate)
    s = sub.add_parser("dashboard", help="launch the Streamlit analyst dashboard")
    s.add_argument("--port", type=int, default=8501); s.set_defaults(fn=cmd_dashboard)

    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    a.fn(a, cfg)


if __name__ == "__main__":
    main()
