#Requires -Version 5.1
<#
.SYNOPSIS
    Netzlaufwerke der Synology verbinden oder trennen (Umschalter).

.DESCRIPTION
    Ohne Parameter: Sind alle Laufwerke verbunden, werden sie getrennt - sonst verbunden.
    -Verbinden / -Trennen erzwingen die Richtung, -Status zeigt nur den Zustand.

    Beim Verbinden wird zuerst geprüft, ob der Server erreichbar ist (Port 445, 2 s).
    So hängt der Explorer nie wieder an einem nicht erreichbaren Laufwerk.
    Zugangsdaten werden beim ersten Mal abgefragt und in der Windows-Anmeldeinformationsverwaltung
    gespeichert (cmdkey), nicht im Skript.

    WICHTIG: NICHT "Als Administrator" starten. Laufwerke aus einer Admin-Sitzung sind im
    normalen Explorer unsichtbar.

.EXAMPLE
    .\Netzlaufwerke.ps1             # umschalten
    .\Netzlaufwerke.ps1 -Verbinden
    .\Netzlaufwerke.ps1 -Trennen
    .\Netzlaufwerke.ps1 -Status
#>
[CmdletBinding(DefaultParameterSetName = 'Toggle')]
param(
    [Parameter(ParameterSetName = 'On')][switch]$Verbinden,
    [Parameter(ParameterSetName = 'Off')][switch]$Trennen,
    [Parameter(ParameterSetName = 'Status')][switch]$Status,
    [switch]$NoPause
)

# ---------------------------------------------------------------- Konfiguration
$Server = 'synology'
$Laufwerke = @(
    @{ Buchstabe = 'Z:'; Pfad = '\\synology\DATEN_ANDRE' }
    # Zweites Laufwerk hier eintragen, z. B.:
    # @{ Buchstabe = 'Y:'; Pfad = '\\synology\home' }
)
# -----------------------------------------------------------------------------

function Test-Server {
    param([string]$HostName, [int]$TimeoutMs = 2000)
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $c.BeginConnect($HostName, 445, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutMs)) { return $false }
        $c.EndConnect($ar)
        return $true
    } catch { return $false } finally { $c.Close() }
}

function Get-Mapped {
    param([string]$Letter)
    $out = (& net.exe use $Letter 2>$null) -join "`n"
    return ($LASTEXITCODE -eq 0 -and $out)
}

function Show-Status {
    foreach ($l in $Laufwerke) {
        if (Get-Mapped $l.Buchstabe) { Write-Host ('  {0} -> {1}: verbunden' -f $l.Buchstabe, $l.Pfad) -ForegroundColor Green }
        else { Write-Host ('  {0} -> {1}: getrennt' -f $l.Buchstabe, $l.Pfad) -ForegroundColor DarkGray }
    }
}

function Connect-All {
    Write-Host ('  Prüfe Server "{0}" ...' -f $Server)
    if (-not (Test-Server $Server)) {
        Write-Host ('  Server "{0}" ist nicht erreichbar (Port 445). Nichts verbunden.' -f $Server) -ForegroundColor Red
        Write-Host '  Tipp: läuft die Synology? Ist der Name richtig (sonst IP-Adresse oben eintragen)?' -ForegroundColor DarkGray
        return
    }
    # Zugangsdaten einmalig in der Windows-Anmeldeinformationsverwaltung hinterlegen
    $hasCred = ((& cmdkey.exe /list:$Server) -join ' ') -match [regex]::Escape($Server) -and ((& cmdkey.exe /list:$Server) -join ' ') -notmatch 'NONE|KEINE'
    if (-not $hasCred) {
        $cred = Get-Credential -Message ('Anmeldung für \\{0} (wird in Windows gespeichert)' -f $Server)
        if (-not $cred) { Write-Host '  Abgebrochen.' -ForegroundColor Yellow; return }
        & cmdkey.exe /add:$Server /user:$($cred.UserName) /pass:$($cred.GetNetworkCredential().Password) | Out-Null
    }
    foreach ($l in $Laufwerke) {
        if (Get-Mapped $l.Buchstabe) { Write-Host ('  {0} ist bereits verbunden.' -f $l.Buchstabe) -ForegroundColor DarkGray; continue }
        $o = & net.exe use $l.Buchstabe $l.Pfad /persistent:yes 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Host ('  {0} -> {1} verbunden.' -f $l.Buchstabe, $l.Pfad) -ForegroundColor Green }
        else { Write-Host ('  {0} fehlgeschlagen: {1}' -f $l.Buchstabe, (($o | Out-String).Trim())) -ForegroundColor Red }
    }
}

function Disconnect-All {
    foreach ($l in $Laufwerke) {
        if (-not (Get-Mapped $l.Buchstabe)) {
            # auch verwaiste Einträge (nur noch in der Registry) entfernen
            Remove-Item -LiteralPath ('HKCU:\Network\{0}' -f $l.Buchstabe.TrimEnd(':')) -Recurse -ErrorAction SilentlyContinue
            Write-Host ('  {0} war nicht verbunden.' -f $l.Buchstabe) -ForegroundColor DarkGray
            continue
        }
        $o = & net.exe use $l.Buchstabe /delete /y 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Host ('  {0} getrennt.' -f $l.Buchstabe) -ForegroundColor Yellow }
        else { Write-Host ('  {0}: {1}' -f $l.Buchstabe, (($o | Out-String).Trim())) -ForegroundColor Red }
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host '  Achtung: Das Skript läuft als Administrator - so verbundene Laufwerke sieht der normale Explorer nicht.' -ForegroundColor Yellow
    Write-Host '  Bitte ohne "Als Administrator ausführen" starten.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host '  Netzlaufwerke' -ForegroundColor White
if ($Status) { Show-Status }
elseif ($Verbinden) { Connect-All; Show-Status }
elseif ($Trennen) { Disconnect-All; Show-Status }
else {
    $allOn = $true
    foreach ($l in $Laufwerke) { if (-not (Get-Mapped $l.Buchstabe)) { $allOn = $false } }
    if ($allOn) { Write-Host '  Alle verbunden -> trenne ...'; Disconnect-All }
    else { Write-Host '  Nicht (alle) verbunden -> verbinde ...'; Connect-All }
    Show-Status
}
Write-Host ''
if (-not $NoPause) { [void](Read-Host '  Enter zum Schließen') }
