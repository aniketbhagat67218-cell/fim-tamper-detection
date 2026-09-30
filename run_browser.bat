@echo off
title FIM Sentinel Web Dashboard
cd /d "%~dp0"
echo Starting FIM Web Dashboard on http://127.0.0.1:5000 ...
if exist "C:\Users\DELL\AppData\Local\Programs\Python\Python314\python.exe" (
    "C:\Users\DELL\AppData\Local\Programs\Python\Python314\python.exe" web_app.py
) else (
    python web_app.py
)
pause
