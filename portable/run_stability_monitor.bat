@echo off
:: Network Stability Monitor Pro - Portable Launcher
:: Copy this folder to any machine with Python 3.10+

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

where python >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Python not found. Install Python 3.10+ and add it to PATH.
    pause
    exit /b 1
)

python -c "import customtkinter, psutil, requests" >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing dependencies...
    python -m pip install customtkinter psutil requests
)

python "%~dp0Network_Stability_Monitor_Portable.py"
if %errorLevel% neq 0 pause
