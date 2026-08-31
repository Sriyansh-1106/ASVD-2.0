@echo off
title ASVD 2.0 - Server + Public Cloud Tunnel
color 0b

echo =================================================================
echo   ASVD 2.0 - Zero-IP Mobile Tunnel ^& AI Backend
echo =================================================================
echo.

if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)

python start_tunnel.py
pause
