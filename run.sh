#!/usr/bin/env bash
# One-command setup + demo for Linux/macOS:  ./run.sh [demo|dashboard|live|test]
set -e
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements-dev.txt
case "${1:-demo}" in
  demo)      python main.py demo && python main.py dashboard ;;
  dashboard) python main.py dashboard ;;
  test)      python -m pytest -q ;;
  live)      python main.py live --watch data/live/alerts.jsonl --http-port 8080 ;;
  *) echo "usage: ./run.sh [demo|dashboard|live|test]"; exit 1 ;;
esac
