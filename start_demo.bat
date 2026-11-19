@echo off
setlocal enabledelayedexpansion
title Veritas University - Demo Launcher
cd /d "%~dp0"

echo ======================================================================
echo    STARTING VERITAS UNIVERSITY CYBERSECURITY DEMO SYSTEM
echo ======================================================================

:: Resolve Python executable (prefer installed Python 3.14 if available, fallback to PATH)
set "PYTHON_EXE="
if exist "%LOCALAPPDATA%\Programs\Python\Python314\python.exe" (
    set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
) else (
    set "PYTHON_EXE=python"
)

echo [*] Using Python: !PYTHON_EXE!

:: 1. Launch Flask University SSO Portal on port 5000 in background window
echo [*] Starting University SSO Portal on http://localhost:5000 ...
start "Veritas SSO Portal (Port 5000)" "!PYTHON_EXE!" 3_university_portal.py

:: 2. Launch Streamlit SOC Dashboard on port 8501 in background window
echo [*] Starting Streamlit SOC Dashboard on http://localhost:8501 ...
start "Veritas SOC Dashboard (Port 8501)" "!PYTHON_EXE!" -m streamlit run 4_dashboard.py --server.port 8501 --server.headless true

:: 3. Wait briefly for services to initialize
echo [*] Waiting for services to initialize...
timeout /t 3 /nobreak >nul

:: 4. Automatically open Dashboard and Portal in default browser
echo [*] Opening Dashboard (http://localhost:8501) and Portal (http://localhost:5000) ...
start http://localhost:8501
start http://localhost:5000

echo ======================================================================
echo    SERVICES ARE RUNNING!
echo    - Streamlit SOC Dashboard: http://localhost:8501
echo    - University SSO Portal:  http://localhost:5000
echo ======================================================================
