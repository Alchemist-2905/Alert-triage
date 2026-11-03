#!/usr/bin/env bash
# Usage: ./scripts/push_to_github.sh https://github.com/<you>/<repo>.git
# Create an EMPTY repo on github.com first (no README/licence), then run this once.
set -e
cd "$(dirname "$0")/.."
REPO_URL="${1:?Pass your GitHub repo URL, e.g. https://github.com/you/ai-alert-triage.git}"
[ -d .git ] || git init -b main
git add -A
git commit -m "AI-based cyber incident prioritization and risk-aware alert triage" || echo "(nothing new to commit)"
git branch -M main
git remote remove origin 2>/dev/null || true
git remote add origin "$REPO_URL"
git push -u origin main
echo "Pushed. CI will run automatically under the repo's Actions tab."
