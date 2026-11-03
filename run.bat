@echo off
REM One-command setup + demo for Windows:  run.bat [demo|dashboard|live|test]
cd /d %~dp0
if not exist .venv ( py -3 -m venv .venv )
call .venv\Scripts\activate.bat
pip install -q -r requirements-dev.txt
set CMD=%1
if "%CMD%"=="" set CMD=demo
if "%CMD%"=="demo" ( python main.py demo && python main.py dashboard & goto :eof )
if "%CMD%"=="dashboard" ( python main.py dashboard & goto :eof )
if "%CMD%"=="test" ( python -m pytest -q & goto :eof )
if "%CMD%"=="live" ( python main.py live --watch data\live\alerts.jsonl --http-port 8080 & goto :eof )
echo usage: run.bat [demo^|dashboard^|live^|test]
