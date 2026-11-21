@echo off
setlocal
cd /d "%~dp0"

echo ======================================================
echo   SecureSign Cloud 2.1 - Local Development
echo ======================================================

if not exist ".venv\Scripts\python.exe" (
    echo [1/3] Creating Python virtual environment...
    py -3 -m venv .venv
    if errorlevel 1 (
        echo Could not create virtual environment. Check Python 3.11+.
        pause
        exit /b 1
    )
)

echo [2/3] Installing dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo Dependency installation failed.
    pause
    exit /b 1
)

echo [3/3] Opening browser and starting SecureSign...
start "" http://127.0.0.1:8000
".venv\Scripts\python.exe" -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
pause
