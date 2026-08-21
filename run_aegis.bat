@echo off
title Aegis Runtime Defense Engine
cls
echo [AEGIS RUNTIME DEFENSE ENGINE]
echo.

if exist "dist\Aegis-Guard.exe" (
    echo [*] Launching standalone binary dist\Aegis-Guard.exe...
    dist\Aegis-Guard.exe %*
    goto end
)

if exist "Aegis-Guard.exe" (
    echo [*] Launching standalone binary Aegis-Guard.exe...
    Aegis-Guard.exe %*
    goto end
)

if exist ".venv\Scripts\python.exe" (
    echo [*] Using virtual environment Python...
    .venv\Scripts\python.exe aegis_main.py %*
    goto end
)

python aegis_main.py %*

:end
