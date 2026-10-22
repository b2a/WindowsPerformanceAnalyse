# PerfDiag – findet heraus, was deinen PC bremst

Ein einzelnes PowerShell-Skript, keine Installation nötig. Läuft mit Windows PowerShell 5.1 (bei Windows 10/11 dabei) und PowerShell 7.

## Starten

1. `PerfDiag.ps1` z. B. in den Ordner *Downloads* legen.
2. PowerShell öffnen (Start → „PowerShell“) und eingeben:

   ```powershell
   powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Downloads\PerfDiag.ps1" -Seconds 900
   ```

3. Die Frage nach Administratorrechten mit **J** beantworten (sonst fehlen S.M.A.R.T.-Werte, Boot-Diagnose und Autoruns).
4. **Normal weiterarbeiten**, während das Skript misst (Chrome, Explorer usw. wie immer benutzen).
5. **Wenn du einen Hänger spürst:** `Pause/Untbr`, `Strg+Alt+Umschalt+M` oder `M` im Konsolenfenster drücken. Ein Piepton bestätigt die Markierung. Das Skript speichert das gerade aktive Programm/Fenster sowie alles, was in den 5 Sekunden davor los war.
6. Am Ende öffnet sich `Bericht.md`. Diese Datei kannst du Claude schicken.

## Was gemessen wird

| Bereich | Inhalt |
|---|---|
| Live (ganze Messdauer) | CPU gesamt und je Prozess, Kernel-Anteil, GPU 3D-Auslastung & VRAM, DPC-/Interrupt-Last je Kern (Treiber), System-Hänger (eingebauter Mini-LatencyMon), RAM, Auslagerung, Non-Paged/Paged Pool, Latenz/Auslastung je Laufwerk, I/O je Prozess, CPU-Takt unter Last |
| Laufwerke | SSD/HDD mit automatischer Zuordnung der Laufwerksbuchstaben (`C:`, `D:`, …), Zustand, S.M.A.R.T./NVMe (Temperatur, Verschleiß, Lesefehler), freier Platz, TRIM |
| Ereignisprotokolle (7 Tage) | Laufwerks-Resets (129/153), Bad Sectors (inkl. Modell-/Laufwerkszuordnung), WHEA-Hardwarefehler, CPU-Drosselung (37), Bluescreens, Grafiktreiber-Resets, hängende Programme (auch explorer.exe), Startzeit und Start-Bremsen |
| Explorer | nicht erreichbare Netzlaufwerke, Ordner mit sehr vielen Dateien, Schreibtest (Virenscanner-Bremse), Kontextmenü-Erweiterungen von Drittanbietern (auch defekte), Cloud-Sync, Indexer |
| Software | Virenscanner (auch doppelte oder pausierte mit aktiven Treibern), aktive Dateisystem-Minifilter, Autostart, Drittanbieter-Dienste, bekannte Latenz-Verursacher (RGB-/Audio-/Hersteller-Tools), Browser-Anteil an CPU und RAM |
| Treiber & Kernel-Pool | Nicht-Microsoft-Kernel-Treiber (typische DPC-Verdächtige), Kernel-Speicher je Pool-Tag mit automatischer Treiber-Zuordnung (`System32\drivers` + `DriverStore`), Netzwerkadapter, Geräte mit Fehlern |
| Tastatur | Anschlagverzögerung (Filtertasten), Einrastfunktion, Wiederholverzögerung, Peripherie-Software |

## Optionen

| Parameter | Wirkung |
|---|---|
| `-Seconds 900` | Messdauer (Standard 120 s). Bei gelegentlichen Hängern 15–30 Minuten |
| `-AutorunsPath C:\Tools` | Ordner mit `autorunsc64.exe` (Sysinternals). Wird auch automatisch neben dem Skript und in *Downloads* gesucht |
| `-Trace` | zusätzliche WPR-Aufzeichnung (max. 5 Min.). Mit installiertem Windows ADK (xperf) entsteht automatisch ein DPC/ISR-Bericht je Treiber |
| `-FromJson pfad\daten.json` | eine frühere Messung neu auswerten |
| `-NoAnonymize` | Benutzer- und Computername im Bericht nicht ersetzen |
| `-SkipAutoruns`, `-SkipDrivers`, `-NoOpen`, `-NoPause`, `-NoElevate` | Teile überspringen bzw. ohne Rückfragen laufen |

## Ausgabe (Ordner `PerfDiag_<Datum>` auf dem Desktop)

- `Bericht.md`: Ampel je Kategorie, die wahrscheinlichsten Bremsen mit Empfehlungen, alle Messdaten
- `daten.json`: alle Rohdaten (für eine erneute Auswertung)
- `zeitverlauf.csv`: Messwerte pro Sekunde (in Excel öffnen)

Das Skript ändert nichts am System. Es liest nur und schreibt die Berichtsdateien sowie für den Schreibtest kurz 20 kleine Dateien in den Temp-Ordner, die es sofort wieder löscht.
