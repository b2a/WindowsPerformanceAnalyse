# WPA-Watch.ps1
# Protokolliert die Zahl der Schluessel in HKLM\SYSTEM\WPA und warnt, wenn sie waechst.
# Hintergrund: 347.377 Schluessel in diesem Zweig verursachten einen 25-Minuten-Systemstart
# (SYSTEM-Hive 125 MB). Siehe _Reports\BootTrace\WPA-Offline.ps1 fuer die Bereinigung.
# Laeuft ohne Administratorrechte. Mit -Register legt es sich selbst als Aufgabe an.

[CmdletBinding()]
param(
    # Ab dieser Schluesselzahl wird gewarnt. Normal sind 2 bis etwa 20.
    [int]$Schwelle = 500,
    # Legt die geplante Aufgabe an (bei Anmeldung und taeglich) und beendet sich.
    [switch]$Register,
    # Entfernt die geplante Aufgabe wieder.
    [switch]$Entfernen
)

$ErrorActionPreference = 'Stop'
$skript   = $PSCommandPath
$basis    = Split-Path -Parent $skript
$berichte = Join-Path $basis '_Reports'
$csv      = Join-Path $berichte 'WPA-Watch.csv'
$aufgabe  = 'WPA-Watch'

# --- Aufgabe anlegen oder entfernen ---------------------------------------
if ($Register -or $Entfernen) {
    Unregister-ScheduledTask -TaskName $aufgabe -Confirm:$false -ErrorAction SilentlyContinue
    if ($Entfernen) { Write-Host "Aufgabe '$aufgabe' entfernt." -ForegroundColor Green; return }

    $aktion = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}" -Schwelle {1}' -f $skript, $Schwelle)
    $trigger = @(
        New-ScheduledTaskTrigger -AtLogOn
        New-ScheduledTaskTrigger -Daily -At '12:00'
    )
    # Verzoegerung, damit der Start nicht zusaetzlich belastet wird
    $trigger[0].Delay = 'PT3M'
    $einst = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask -TaskName $aufgabe -Action $aktion -Trigger $trigger -Settings $einst `
        -Description 'Ueberwacht die Groesse des Lizenzspeichers HKLM\SYSTEM\WPA.' | Out-Null
    Write-Host "Aufgabe '$aufgabe' angelegt (bei Anmeldung +3 min und taeglich 12:00)." -ForegroundColor Green
    Write-Host "Protokoll: $csv"
    return
}

# --- Messung ---------------------------------------------------------------
if (-not (Test-Path $berichte)) { New-Item -ItemType Directory -Path $berichte -Force | Out-Null }

$anzahl = (Get-Item 'HKLM:\SYSTEM\WPA').SubKeyCount

# Vorherigen Wert aus dem Protokoll holen, um das Wachstum zu sehen
$vorher = $null
if (Test-Path $csv) {
    $letzte = Import-Csv $csv -ErrorAction SilentlyContinue | Select-Object -Last 1
    if ($letzte) { $vorher = [int]$letzte.Anzahl }
}
$delta = if ($null -ne $vorher) { $anzahl - $vorher } else { 0 }

# Begleitdaten: Lizenzzustand und KMS-Erreichbarkeit helfen beim Zuordnen der Ursache
$start = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$office = Get-CimInstance SoftwareLicensingProduct -ErrorAction SilentlyContinue |
    Where-Object { $_.PartialProductKey -and $_.Name -like 'Office*' } | Select-Object -First 1

$zeile = [pscustomobject]@{
    Zeit        = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Anzahl      = $anzahl
    Delta       = $delta
    LetzterStart= $start.ToString('yyyy-MM-dd HH:mm:ss')
    OfficeStatus= if ($office) { $office.LicenseStatus } else { '' }
    OfficeRest  = if ($office) { $office.GracePeriodRemaining } else { '' }
    KmsHost     = if ($office) { $office.KeyManagementServiceMachine } else { '' }
}
$zeile | Export-Csv $csv -NoTypeInformation -Append -Encoding UTF8

# --- Ausgabe und Warnung ---------------------------------------------------
Write-Host ("WPA-Schluessel: {0} (Veraenderung seit letzter Messung: {1:+#;-#;0})" -f $anzahl, $delta)

if ($anzahl -ge $Schwelle) {
    $text = "Der Lizenzspeicher HKLM\SYSTEM\WPA hat $anzahl Schluessel (Schwelle $Schwelle). " +
            "Das war die Ursache des langsamen Systemstarts. Bereinigung: WPA-Offline.ps1."
    Write-Warning $text
    # Sichtbare Meldung, auch wenn das Skript unbeaufsichtigt laeuft
    try {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show($text, 'WPA-Watch: Lizenzspeicher waechst',
            'OK', 'Warning') | Out-Null
    } catch { }
    exit 2
}
elseif ($delta -gt 50) {
    Write-Warning "Zuwachs von $delta Schluesseln seit der letzten Messung - Protokoll beobachten: $csv"
}
