# AI-Based Cyber Incident Prioritization and Risk-Aware Alert Triage

B.Tech Project Work – Group **26PB82**, Ramaiah University of Applied Sciences (Dept. of CSE)
Team: Anoop K (23ETCS002014) · Karan S (23ETCS002055) · Kishen G Raj (23ETCS002060) — Guide: Ms. Megharani H M

A SOC alert-triage system that ingests security alerts, builds a **provenance/context graph**, runs a
**rule engine and a Random-Forest classifier in parallel**, fuses them into a **0-100 contextual risk score**
(Low / Medium / High / Critical), de-duplicates and ranks alerts, explains *why* each alert was ranked, and shows
everything on a **Streamlit analyst dashboard**. It works on historical files **and in real time**.

## Quick start (any OS, Python 3.10+)

```bash
git clone <your-repo-url> && cd <repo>
./run.sh            # Linux/macOS: creates .venv, installs, runs demo, opens dashboard
run.bat             # Windows
# or manually:
pip install -r requirements.txt
python main.py demo         # generate data -> train -> evaluate -> save results
python main.py dashboard    # http://localhost:8501
python -m pytest -q         # 15 tests
```
Docker: `docker compose up --build` (dashboard on :8501, live engine on :8080).

## Real-time mode

```bash
# terminal 1 – follow any JSON-lines alert file (generic, Suricata eve.json, Wazuh alerts.json) and/or accept HTTP
python main.py live --watch data/live/alerts.jsonl --http-port 8080
#   real deployment examples:
#   python main.py live --watch /var/log/suricata/eve.json
#   python main.py live --watch /var/ossec/logs/alerts/alerts.json --http-port 8080
# terminal 2 – demo feed (skip if you have a real feed)
python main.py simulate --rate 1 --campaign-every 60
# terminal 3
python main.py dashboard          # pick live.db, auto-refresh is on
# push a single alert over HTTP
curl -X POST localhost:8080/alert -H 'Content-Type: application/json' \
  -d '{"timestamp":"2026-10-31T06:00:00","src_ip":"185.10.0.1","dst_ip":"10.0.50.12","dst_port":3389,"severity":4,"process":"mimikatz.exe"}'
```
Each micro-batch (default 2 s) is scored against a rolling 30-minute context buffer (about 0.1 s per batch in tests).
High/Critical alerts print to the console and append to `output/high_priority_alerts.log`.
Unknown vendor formats: any JSON with keys such as `src_ip, dst_ip, timestamp, severity, signature` works
(aliases in `alert_triage/ingest.py`).

## Using the official UNSW-NB15 sets
See `scripts/download_unsw_nb15.md`. In short:
`python main.py batch --train UNSW_NB15_training-set.csv --input UNSW_NB15_testing-set.csv --model models/unsw.joblib --db output/unsw.db`.
The partitioned UNSW-NB15 files have no IPs/timestamps/users, so `alert_triage/unsw.py` **synthesises** that context
deterministically (attack rows grouped into campaigns sharing an attacker IP and time window; severity is a noisy
function of the attack category). Labels are never used as model features. State this assumption in your report.

## Architecture (mirrors the synopsis block diagram)

```
1 Data sources  -> 2 Ingestion (Python/Pandas) -> 3 Preprocessing (Pandas/NumPy) -> 4 Feature engineering
   alerts/CSV/JSON     ingest.py, realtime.py        preprocess.py                     features.py
-> 5 Context & provenance (NetworkX: provenance.py)
-> 6 Parallel analysis:  A) Rule engine (rules.py)   B) Random Forest (pipeline.py, scikit-learn)
-> 7 Risk scoring & explanation (scoring.py, reason codes)  -> 8 Alert triage (triage.py: dedup, queue, incidents)
-> 9 Dashboard (dashboard/app.py, Streamlit) -> SOC analyst         10 Evaluation (evaluation.py)
```

**Risk score** = 100 × (0.10·severity + 0.20·context[provenance, rules] + 0.10·temporal correlation + 0.60·ML confidence)
(weights in `config.yaml`). Bands: Low 0-30 · Medium 31-70 · High 71-85 · Critical 86-100.

| Synopsis objective | Where it is implemented |
|---|---|
| OB1 Literature survey | `docs/literature_survey.md` (template to complete with your cited papers) |
| OB2 Collect & preprocess alerts | `ingest.py`, `preprocess.py`, `unsw.py`, `data_gen.py` |
| OB3 AI/ML analysis of alert characteristics + risk | `features.py`, `provenance.py` (NetworkX), Random Forest in `pipeline.py` |
| OB4 Risk-based prioritisation | `rules.py`, `scoring.py`, `triage.py` |
| OB5 Verification & evaluation | `evaluation.py`, dashboard *Evaluation* tab, `tests/` |

## Verification results (reproduce with `python main.py demo`)
Chronological 70/30 split of 60,000 **synthetic** alerts (11.7 % malicious in the test part, 18,000 alerts):

| Method | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Severity-only (sev ≥ 4) | 0.363 | 0.232 | 0.283 | 5.43 % |
| Rule-only (score ≥ 0.6) | 0.265 | 0.891 | 0.409 | 32.8 % |
| ML-only (p ≥ 0.5) | 0.998 | 0.995 | 0.997 | 0.03 % |
| **Hybrid, High+Critical** | 1.000 | 0.867 | 0.929 | 0.00 % |
| **Hybrid, Medium+** | 0.948 | 0.999 | 0.973 | 0.73 % |

Also reported: ROC-AUC, precision@k, duplicates suppressed (9.5 %), and alert-volume reduction (about 97 %).
**Important honesty note:** the synthetic data is easier than real traffic, so these numbers are an upper bound and
show that the pipeline works and beats the baselines; they are *not* a claim about real SOC performance.
Report UNSW-NB15 (and any real alerts you can obtain) as your main evidence.

## Project layout
```
main.py                 CLI entry point            config.yaml     tunable weights/thresholds/rules
alert_triage/           ingest · preprocess · features · provenance · rules · pipeline · scoring
                        triage · evaluation · store · realtime · data_gen · unsw · cli
dashboard/app.py        Streamlit dashboard        tests/          15 pytest tests (CI on 3 OS)
data/samples/           Suricata + Wazuh samples   scripts/        GitHub push helpers
```

## Push to GitHub
1. Create an **empty** repository on github.com. 2. Run:
```bash
./scripts/push_to_github.sh https://github.com/<you>/<repo>.git     # Windows: scripts\push_to_github.bat <url>
```
(or `git init -b main && git add -A && git commit -m "init" && git remote add origin <url> && git push -u origin main`).
GitHub Actions (`.github/workflows/ci.yml`) then runs the tests on Linux/Windows/macOS.

## Limitations (mention these in your report)
- Models should be **retrained on the deployment's own labelled alerts**; alert density and signatures differ per site (`python main.py train --train yourfile.csv`).
- Temporal windows are tumbling (5 min) and the graph context is per 30-minute window; in batch mode an alert can see
  later alerts of the same window, in live mode only earlier ones.
- Per-alert explanations are importance-weighted feature elevations + rule hits, not SHAP values.
- Real feeds usually have no ground truth, so the Evaluation tab only works for labelled data.
