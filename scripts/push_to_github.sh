#!/usr/bin/env bash
# Usage: ./scripts/push_to_github.sh [https://github.com/<you>/<repo>.git]
set -e
cd "$(dirname "$0")/.."

[ -d .git ] || git init -b main

# If URL argument is provided, safely configure or update origin
if [ -n "$1" ]; then
    if git remote get-url origin >/dev/null 2>&1; then
        git remote set-url origin "$1"
    else
        git remote add origin "$1"
    fi
    echo "[git] Remote origin set to $1"
fi

# Check that origin exists
if ! git remote get-url origin >/dev/null 2>&1; then
    echo "[error] No remote 'origin' configured."
    echo "Usage: ./scripts/push_to_github.sh https://github.com/<you>/<repo>.git"
    exit 1
fi

git add -A
if ! git diff --cached --quiet; then
    git commit -m "update: automated telemetry engine and documentation sync"
else
    echo "[git] No changes to commit."
fi

git branch -M main
echo "[git] Pushing to GitHub (origin main)..."
git push -u origin main
echo "[git] Pushed successfully. CI will run under Actions tab."
