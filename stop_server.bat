@echo off
title Stop FIM Server
echo Stopping all FIM servers on port 5000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5000" ^| findstr "LISTENING"') do taskkill /f /pid %%a >nul 2>&1
echo Done! FIM server stopped.
pause
