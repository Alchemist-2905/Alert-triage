@echo off
REM Usage: scripts\push_to_github.bat https://github.com/you/repo.git
cd /d %~dp0..
if "%1"=="" ( echo Pass your GitHub repo URL & exit /b 1 )
if not exist .git ( git init -b main )
git add -A
git commit -m "AI-based cyber incident prioritization and risk-aware alert triage"
git branch -M main
git remote remove origin 2>nul
git remote add origin %1
git push -u origin main
