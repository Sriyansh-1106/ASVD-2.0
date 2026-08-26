@echo off
title ASVD 2.O — AI Scam Voice Detection System
cd /d "%~dp0"
setlocal enabledelayedexpansion

echo ======================================================================
echo   Launching ASVD 2.O — AI Cyber Scam Voice Detection System
echo ======================================================================
echo.

set PYTHONPATH=%~dp0

:: Check if virtual environment python exists
if exist "%~dp0venv\Scripts\python.exe" (
    set "PYTHON_EXE=%~dp0venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

:: Automatically free port 8000 if occupied by a hung process
for /f "tokens=5" %%a in ('netstat -aon ^| findstr /r ":8000.*LISTENING"') do (
    echo   [!] Port 8000 is occupied by PID %%a. Cleaning up...
    taskkill /F /PID %%a >nul 2>&1
)

echo   Starting server with !PYTHON_EXE!...
echo.

"!PYTHON_EXE!" run_demo.py

echo.
echo   Server stopped.
pause
