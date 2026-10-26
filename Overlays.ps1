#Requires -Version 5.1
<#
.SYNOPSIS
    Symbol-Overlays (Sync-Statussymbole im Explorer) anzeigen, deaktivieren, wiederherstellen.

.DESCRIPTION
    Die Sync-Programme laufen weiter und synchronisieren normal - nur die kleinen Statussymbole
    (Haken, Wolke, Pfeile) an Dateien verschwinden. Explorer muss dafür nicht mehr bei jeder
    angezeigten Datei jedes Sync-Programm nach dem Status fragen.

    Vor dem Deaktivieren wird eine Sicherung (.reg) neben dem Skript angelegt.
    Benötigt Administratorrechte (Schlüssel liegt unter HKLM). Explorer wird danach neu gestartet.
    Hinweis: Updates der Sync-Programme können ihre Overlays wieder eintragen - dann einfach erneut ausführen.

.EXAMPLE
    .\Overlays.ps1                  # Liste anzeigen
    .\Overlays.ps1 -Deaktivieren    # Overlays von Dropbox, Synology, Google Drive entfernen
    .\Overlays.ps1 -Deaktivieren -Muster 'Dropbox'
    .\Overlays.ps1 -Wiederherstellen
#>
[CmdletBinding(DefaultParameterSetName = 'List')]
param(
    [Parameter(ParameterSetName = 'Off')][switch]$Deaktivieren,
    [Parameter(ParameterSetName = 'Off')][string[]]$Muster = @('Dropbox', 'Synology', 'DriveFS', 'GoogleDrive', 'Google Drive'),
    [Parameter(ParameterSetName = 'Restore')][switch]$Wiederherstellen,
    [switch]$NoPause
)

$key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers'
$regKey = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers'
$dir = $PSScriptRoot
if (-not $dir) { $dir = (Get-Location).Path }

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-List {
    # Windows sortiert die Namen alphabetisch (führende Leerzeichen zuerst) und nutzt nur die ersten ~15
    $names = @(Get-ChildItem $key -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName } | Sort-Object)
    Write-Host ('  {0} Overlays registriert (Windows zeigt nur die ersten ca. 15):' -f $names.Count) -ForegroundColor White
    $i = 0
    foreach ($n in $names) {
        $i++
        $color = 'Gray'
        if ($i -gt 15) { $color = 'DarkGray' }
        Write-Host ('  {0,3}. "{1}"' -f $i, $n) -ForegroundColor $color
    }
}

function Restart-Explorer {
    Write-Host '  Explorer wird neu gestartet ...' -ForegroundColor DarkGray
    Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
    if (-not (Get-Process explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }
}

Write-Host ''
Write-Host '  Symbol-Overlays' -ForegroundColor White

if ($Deaktivieren -or $Wiederherstellen) {
    if (-not (Test-Admin)) {
        Write-Host '  Bitte als Administrator starten (Rechtsklick > Als Administrator ausführen).' -ForegroundColor Red
        if (-not $NoPause) { [void](Read-Host '  Enter zum Schließen') }
        return
    }
}

if ($Deaktivieren) {
    $backup = Join-Path $dir ('Overlays_Sicherung_{0}.reg' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    & reg.exe export $regKey $backup /y | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $backup)) { Write-Host '  Sicherung fehlgeschlagen - breche ab.' -ForegroundColor Red; return }
    Write-Host ('  Sicherung: {0}' -f $backup) -ForegroundColor DarkGray
    $removed = 0
    foreach ($k in @(Get-ChildItem $key -ErrorAction SilentlyContinue)) {
        $name = $k.PSChildName
        $hit = $false
        foreach ($m in $Muster) { if ($name -like ('*{0}*' -f $m)) { $hit = $true } }
        if ($hit) {
            Remove-Item -LiteralPath $k.PSPath -Recurse -Force
            Write-Host ('  entfernt: "{0}"' -f $name) -ForegroundColor Yellow
            $removed++
        }
    }
    Write-Host ('  {0} Overlay(s) entfernt.' -f $removed) -ForegroundColor Green
    if ($removed -gt 0) { Restart-Explorer }
}
elseif ($Wiederherstellen) {
    $latest = Get-ChildItem -Path $dir -Filter 'Overlays_Sicherung_*.reg' -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $latest) { Write-Host '  Keine Sicherung gefunden.' -ForegroundColor Red }
    else {
        & reg.exe import $latest.FullName | Out-Null
        Write-Host ('  Wiederhergestellt aus {0}' -f $latest.Name) -ForegroundColor Green
        Restart-Explorer
    }
}
Show-List
Write-Host ''
if (-not $NoPause) { [void](Read-Host '  Enter zum Schließen') }
