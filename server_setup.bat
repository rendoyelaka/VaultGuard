@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

:: ══════════════════════════════════════════════════════════════
:: VAULTGUARD APK FACTORY — MASTER SETUP
:: Double-click this on ANY Windows 10 RDP.
:: Does EVERYTHING automatically.
::
:: 3 Modes (auto-detected):
::   FRESH   — New RDP: installs all tools, fills config, starts services
::   UPDATE  — Existing RDP: update changed credentials only
::   RESTORE — New RDP with Telegram backup: restores everything
::
:: Pass --update flag to force update mode:
::   server_setup.bat --update
:: ══════════════════════════════════════════════════════════════

title VaultGuard APK Factory Setup
color 0A

echo.
echo ══════════════════════════════════════════════════════════════
echo   VAULTGUARD APK FACTORY — MASTER SETUP
echo   Mode will be auto-detected.
echo ══════════════════════════════════════════════════════════════
echo.

cd /d %~dp0

:: ── STEP 0: Kill all stale Python processes ───────────────────
echo [CLEANUP] Stopping old Python processes...
taskkill /F /IM python.exe /T 2>nul
timeout /t 2 /nobreak >nul

:: ── STEP 0b: Kill old terminal windows by title ───────────────
taskkill /F /FI "WINDOWTITLE eq vaultguard_mutation" /T 2>nul
taskkill /F /FI "WINDOWTITLE eq vaultguard_telegram" /T 2>nul
taskkill /F /FI "WINDOWTITLE eq vaultguard_cloudflare" /T 2>nul
timeout /t 1 /nobreak >nul

:: ── STEP 0c: Kill anything on port 2053 ──────────────────────
echo [CLEANUP] Clearing port 2053...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :2053 2^>nul') do (
    taskkill /F /PID %%a /T 2>nul
)
timeout /t 1 /nobreak >nul

:: ── STEP 0d: Delete stale lock files ─────────────────────────
if exist "C:\VaultGuard\vaultguard_setup.lock" (
    del /F "C:\VaultGuard\vaultguard_setup.lock" 2>nul
    echo [CLEANUP] Removed stale vaultguard_setup.lock
)
if exist "C:\VaultGuard\vaultguard_bot.lock" (
    del /F "C:\VaultGuard\vaultguard_bot.lock" 2>nul
    echo [CLEANUP] Removed stale vaultguard_bot.lock
)

echo [CLEANUP] Done. Starting fresh.
echo.

:: ── STEP 1: Check Python ─────────────────────────────────────
echo [CHECK] Verifying Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found.
    echo         Download from https://www.python.org/downloads/
    echo         Install with "Add to PATH" checked.
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo [OK] %%v

:: ── STEP 2: Check if vaultguard_setup.py exists ──────────────
set SETUP_SCRIPT=C:\VaultGuard\repo\server\vaultguard_setup.py
set SETUP_SCRIPT_LOCAL=%~dp0server\vaultguard_setup.py

:: Check repo path first, then local path
if exist "%SETUP_SCRIPT%" (
    echo [OK] vaultguard_setup.py found at repo path
    goto :run_setup
)
if exist "%SETUP_SCRIPT_LOCAL%" (
    echo [OK] vaultguard_setup.py found at local path
    set SETUP_SCRIPT=%SETUP_SCRIPT_LOCAL%
    goto :run_setup
)

echo [BOOTSTRAP] vaultguard_setup.py not found — bootstrapping...
echo [BOOTSTRAP] Creating required folders...
mkdir C:\VaultGuard 2>nul
mkdir C:\VaultGuard\repo 2>nul
mkdir C:\VaultGuard\repo\server 2>nul
mkdir C:\VaultGuard\logs 2>nul

echo [BOOTSTRAP] Installing git if not present...
git --version >nul 2>&1
if errorlevel 1 (
    echo [BOOTSTRAP] Git not found — installing via winget...
    winget install Git.Git --silent --accept-source-agreements 2>nul
    timeout /t 15 /nobreak >nul
)

echo [BOOTSTRAP] Cloning repository...
git clone https://github.com/rendoyelaka/VaultGuard.git C:\VaultGuard\repo
if errorlevel 1 (
    echo [ERROR] Clone failed. Check internet connection.
    pause
    exit /b 1
)
set SETUP_SCRIPT=C:\VaultGuard\repo\server\vaultguard_setup.py

:run_setup
echo.
echo [SETUP] Running vaultguard_setup.py in mode: %1
echo.

:: ── STEP 3: Run vaultguard_setup.py ──────────────────────────
python "%SETUP_SCRIPT%" %1 %2 %3

if errorlevel 1 (
    echo.
    echo [WARN] Setup exited with error code.
    echo        Check logs at: C:\VaultGuard\logs\vaultguard_setup.log
    pause
    exit /b 1
)

echo.
echo ══════════════════════════════════════════════════════════════
echo   SETUP COMPLETE
echo   Check Telegram for confirmation alert.
echo   Open @AppMetricsMonitor_Bot and send /start
echo ══════════════════════════════════════════════════════════════
echo.
pause
