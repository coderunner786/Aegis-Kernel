@echo off
title Aegis 24/7 Background Agent Installer
cls
echo ===================================================
echo   AEGIS RUNTIME DEFENSE - 24/7 SERVICE INSTALLER
echo ===================================================
echo.

:: Check for Administrative Privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ERROR: Administrator privileges required.
    echo Right-click this script and select "Run as administrator".
    pause
    exit /b 1
)

set "TARGET_EXE=%~dp0dist\Aegis-Guard.exe"
if not exist "%TARGET_EXE%" (
    set "TARGET_EXE=%~dp0Aegis-Guard.exe"
)

if not exist "%TARGET_EXE%" (
    echo [!] ERROR: Could not locate Aegis-Guard.exe.
    echo Ensure the compiled binary is in this folder or dist\
    pause
    exit /b 1
)

echo [*] Target Binary: %TARGET_EXE%
echo [*] Registering 24/7 persistent background task in Windows Engine...

:: Register task to launch silently at system startup with highest privileges
schtasks /create /f /tn "AegisGuardRuntime" /tr "\"%TARGET_EXE%\" --enforce" /sc onstart /ru "SYSTEM" /rl HIGHEST >nul 2>&1

if %errorLevel% equ 0 (
    echo [?] Aegis 24/7 Task registered successfully!
    echo [*] Starting Aegis in the background now...
    schtasks /run /tn "AegisGuardRuntime" >nul 2>&1
    echo [?] Aegis is now actively running in the background and will auto-start on reboots.
) else (
    echo [!] Failed to register scheduled task. Error code: %errorLevel%
)

echo.
pause
