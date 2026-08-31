@echo off
title ASVD 2.0 - Build Android APK
color 0a

echo =================================================================
echo   ASVD 2.0 - Android APK Project Setup ^& Builder
echo =================================================================
echo.

if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)

python build_apk.py
pause
