@echo off
title Aegis Service Uninstaller
cls

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ERROR: Administrator privileges required.
    echo Right-click this script and select "Run as administrator".
    pause
    exit /b 1
)

echo [*] Stopping and removing Aegis background service...
taskkill /f /im "Aegis-Guard.exe" >nul 2>&1
schtasks /delete /f /tn "AegisGuardRuntime" >nul 2>&1

echo [?] Aegis background service removed.
echo.
pause
