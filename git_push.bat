@echo off
title Push FIM Project to GitHub
cd /d "%~dp0"
echo ======================================================
echo   Git Push Assistant for FIM Sentinel Project
echo ======================================================
echo.

set "GIT_EXE=git"
git --version >nul 2>&1
if %errorlevel% neq 0 (
    if exist "C:\Program Files\Git\cmd\git.exe" (
        set "GIT_EXE=C:\Program Files\Git\cmd\git.exe"
    ) else if exist "C:\Users\DELL\AppData\Local\Programs\Git\cmd\git.exe" (
        set "GIT_EXE=C:\Users\DELL\AppData\Local\Programs\Git\cmd\git.exe"
    ) else (
        echo [ERROR] Git is not installed or not in PATH.
        pause
        exit /b
    )
)


if not exist ".git" (
    echo [*] Initializing Git repository...
    "%GIT_EXE%" init
    "%GIT_EXE%" branch -M main
)

echo [*] Staging all project files...
"%GIT_EXE%" add .

echo [*] Committing changes...
"%GIT_EXE%" commit -m "Initial commit: File Integrity Monitoring & Tamper Detection System"

set /p REPO_URL="Enter your GitHub Repository URL (e.g. https://github.com/username/repo.git): "
if "%REPO_URL%"=="" (
    echo [!] No URL provided. Commit created locally.
    pause
    exit /b
)

"%GIT_EXE%" remote remove origin >nul 2>&1
"%GIT_EXE%" remote add origin %REPO_URL%

echo [*] Pushing to GitHub (main branch)...
"%GIT_EXE%" push -u origin main


echo.
echo ======================================================
echo   Successfully pushed to GitHub!
echo ======================================================
pause
