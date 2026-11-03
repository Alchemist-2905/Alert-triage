@echo off
REM Safe GitHub push script for alert-triage
cd /d %~dp0..

if not exist .git (
    echo [git] Initializing git repository on branch main...
    git init -b main
)

REM If a new remote URL was supplied as an argument, configure it safely
if not "%1"=="" (
    git remote get-url origin >nul 2>&1
    if errorlevel 1 (
        git remote add origin %1
    ) else (
        git remote set-url origin %1
    )
    echo [git] Remote origin configured to %1
)

REM Verify that an origin remote exists before attempting to push
git remote get-url origin >nul 2>&1
if errorlevel 1 (
    echo [error] No origin remote configured.
    echo Usage: scripts\push_to_github.bat https://github.com/YourUsername/Alert-triage.git
    exit /b 1
)

echo [git] Staging and committing changes...
git add -A
git diff --cached --quiet
if errorlevel 1 (
    git commit -m "update: automated telemetry engine and documentation sync"
) else (
    echo [git] No changes to commit.
)

git branch -M main
echo [git] Pushing to GitHub (origin main)...
git push -u origin main
echo [git] Done!
