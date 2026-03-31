@echo off
title Security Audit
echo Starting Security Audit...
echo.

REM Try portable EXE first
if exist "%~dp0dist\Security_Audit.exe" (
    start "" "%~dp0dist\Security_Audit.exe"
    exit /b
)

REM Fall back to Python script
python "%~dp0Security_Audit_Portable.py"
if errorlevel 1 (
    echo.
    echo Failed to run. Make sure Python and dependencies are installed:
    echo   pip install customtkinter psutil
    pause
)
