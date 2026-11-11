@echo off
setlocal
title PerfDiag - Windows Performance Analyse

:: In das Verzeichnis dieses Skripts wechseln (wichtig bei "Als Administrator ausfuehren")
cd /d "%~dp0"

:: PowerShell mit ExecutionPolicy Bypass und dem PerfDiag-Skript starten
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0PerfDiag.ps1" %*

:: Bei Fehlern Fenster offen halten, damit Fehlermeldungen lesbar bleiben
if %ERRORLEVEL% neq 0 (
    echo.
    echo [PerfDiag] Beendet mit Fehlercode %ERRORLEVEL%.
    pause
)
