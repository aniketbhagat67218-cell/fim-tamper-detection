@echo off
title Push FIM Project to GitHub
cd /d "%~dp0"
echo ======================================================
echo   Git Push Assistant for FIM Sentinel Project
echo ======================================================
echo.

git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Git is not installed or not in PATH.
    pause
    exit /b
)

if not exist ".git" (
    echo [*] Initializing Git repository...
    git init
    git branch -M main
)

echo [*] Staging all project files...
git add .

echo [*] Committing changes...
git commit -m "Initial commit: File Integrity Monitoring & Tamper Detection System"

set /p REPO_URL="Enter your GitHub Repository URL (e.g. https://github.com/username/repo.git): "
if "%REPO_URL%"=="" (
    echo [!] No URL provided. Commit created locally.
    pause
    exit /b
)

git remote remove origin >nul 2>&1
git remote add origin %REPO_URL%

echo [*] Pushing to GitHub (main branch)...
git push -u origin main

echo.
echo ======================================================
echo   Successfully pushed to GitHub!
echo ======================================================
pause
