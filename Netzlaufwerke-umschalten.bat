@echo off
:: Netzlaufwerke umschalten (NICHT als Administrator starten)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Netzlaufwerke.ps1" %*
