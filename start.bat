@echo off
title Sentinel SIEM - SOC Console Launcher
color 0B
cls

echo =======================================================
echo          SENTINEL SIEM - SECURITY OPERATIONS CENTER
echo =======================================================
echo.

:: Check PHP executable path
set "PHP_CMD=php"
if exist "C:\xampp\php\php.exe" (
    set "PHP_CMD=C:\xampp\php\php.exe"
)

echo [*] Checking PHP environment...
"%PHP_CMD%" -v >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Error: PHP was not found. Please ensure XAMPP is installed.
    pause
    exit /b
)

echo [*] Starting Sentinel SIEM local server on http://localhost:8000 ...
echo [*] Opening default web browser...
echo.
echo -------------------------------------------------------
echo  Portal URL    : http://localhost:8000
echo  Default User  : admin
echo  Default Pass  : admin123 (Varun Lakhankiya)
echo -------------------------------------------------------
echo.
echo Press Ctrl+C in this window to stop the server anytime.
echo.

:: Launch browser in background after 1 second delay
start "" timeout /t 1 /nobreak >nul & start http://localhost:8000

:: Start PHP Built-in Server
cd /d "%~dp0"
"%PHP_CMD%" -S localhost:8000
