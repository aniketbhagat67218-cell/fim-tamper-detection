@echo off
title FIM Sentinel Always-On Server
cd /d "%~dp0"
:loop
echo [%date% %time%] Starting FIM Web Dashboard on http://127.0.0.1:5000 ...
if exist "C:\Users\DELL\AppData\Local\Programs\Python\Python314\python.exe" (
    "C:\Users\DELL\AppData\Local\Programs\Python\Python314\python.exe" web_app.py
) else (
    python web_app.py
)
echo Server stopped. Auto-restarting in 2 seconds...
timeout /t 2 /nobreak >nul
goto loop
