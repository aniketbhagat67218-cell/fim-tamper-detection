@echo off
title File Integrity Monitoring System
cd /d "%~dp0"
if exist "C:\Users\DELL\AppData\Local\Programs\Python\Python314\python.exe" (
    "C:\Users\DELL\AppData\Local\Programs\Python\Python314\python.exe" app.py
) else (
    python app.py
)
pause
