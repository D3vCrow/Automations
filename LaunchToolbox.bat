@echo off
REM Launch Automations Toolbox Pro (Main.py) on Windows

REM Move to the folder where this script lives
cd /d "%~dp0"

REM Prefer the local virtual environment's Python if available
set "VENV_PY=venv\Scripts\python.exe"

if exist "%VENV_PY%" (
    "%VENV_PY%" Main.py
) else (
    REM Fallback to system Python launcher
    py Main.py
)

echo.
echo ----------------------------------------
echo If the window closes immediately, right-click this file and
echo "Run as administrator" or open a terminal here and run:
echo     LaunchToolbox.bat
echo ----------------------------------------
pause

