# SSD-Umzug: Samsung 970 EVO ersetzen

Stand: 23.11.2026

Diese Anleitung ist auf **diesen** PC zugeschnitten. Die Werte stammen aus der Analyse
dieses Rechners, nicht aus einer allgemeinen Vorlage.

## Ausgangslage

| | |
|---|---|
| Board | MSI Z390-A PRO (MS-7B98), BIOS 1.F0 |
| CPU | Intel Core i5-9600K |
| M.2-Steckplätze für SSDs | **genau einer** (M2_1, Key M, PCIe 3.0 x4) |
| Zweiter M.2-Anschluss | E-Key, nur für Intel-CNVi-WLAN — dort passt keine SSD |
| Aktuelle SSD | Samsung 970 EVO 500 GB, Firmware 2B2QEXE7 |
| Firmware-Modus | UEFI, Datenträger GPT |
| Partitionen | Recovery 0,49 GB / System (EFI) 0,1 GB / Reserved 0,02 GB / C: 418,58 GB |
| Belegt auf C: | 334,7 GB |
| Windows | 10 Pro, RETAIL-Kanal, aktiviert (LicenseStatus 1) |

### Zustand der alten SSD

- Available Spare (Reservezellen): **52 %** — bei einer gesunden SSD dauerhaft 100 %
- Media and Data Integrity Errors: **312** — gesund ist 0
- Einträge im Fehlerprotokoll der SSD: **1515**
- Bad-Block-Meldungen im Windows-Ereignisprotokoll: 198 seit August 2023

Der Verlauf ist **nicht** gleichmäßig, sondern schubweise. Der größte Ausbruch war am
6.11.2026: 62 defekte Blöcke innerhalb von 35 Minuten, 51 davon in zwei Minuten,
parallel zu einer Schattenkopie-Operation. Der bisherige Rekord waren 14 an einem Tag
(April 2024). Seit dem 6.11. keine weitere Meldung.

**Was das bedeutet:** Es gibt einen beschädigten Bereich, der bei normaler Nutzung nicht
berührt wird. Erst großflächiges Lesen oder Schreiben läuft hinein. Ein Klon liest die
ganze Platte — also genau die Operation, die den Ausbruch ausgelöst hat. Je später der
Umzug, desto wahrscheinlicher scheitert er oder zieht beschädigte Daten mit.

## Welche SSD kaufen

Das Board ist eine PCIe-3.0-Plattform. Jede PCIe-4.0- oder 5.0-SSD läuft darauf, aber
gebremst auf etwa 3.500 MB/s — genau das, was die alte 970 EVO schon leistet. **Mehr
Tempo ist durch den Tausch nicht zu erwarten**, der Grund ist allein die defekte Platte.

Deshalb zählt nur noch ein technisches Kriterium: **eigener DRAM-Cache**. Gute Wahl:

- SK hynix Platinum P41
- Samsung 990 PRO
- WD Black SN850X
- Kingston KC3000

**Samsung 990 EVO Plus** funktioniert ebenfalls, ist aber DRAM-los (nutzt Host Memory
Buffer) und damit architektonisch ein Rückschritt gegenüber der jetzigen 970 EVO. Von
Gen-5-SSDs ist hier komplett abzuraten — verschenktes Geld.

**Größe: 1 TB.** Bei 334,7 GB belegt ist die 500er zu knapp, und wenig freier Platz
schadet SSDs zusätzlich.

**Bauform:** M.2 2280 (passt sicher). Der Slot nimmt laut MSI auch 22110 auf.

### Außerdem nötig

- **USB-NVMe-Gehäuse** (ca. 15–25 €). Weil nur ein M.2-Slot vorhanden ist, lassen sich
  alte und neue SSD nicht gleichzeitig einbauen. Nach dem Umzug wird die alte 970 EVO
  damit zur externen Platte — allerdings nur als Wegwerf-Datenträger, nicht für Backups.
- **Externe Festplatte mit mindestens 400 GB frei** für die Dateisicherung.

## Vor dem Umzug

### 1. Dateisicherung, heute

Das ist der wichtigste Schritt und unabhängig davon, welchen Weg du danach wählst.
Wichtig: **zuerst** sichern, **dann** klonen — nicht umgekehrt. Jeder weitere Ausbruch
nimmt Daten mit, die danach nicht mehr zu retten sind.

```powershell
robocopy "C:\Users\Besitzer" "E:\Sicherung\Besitzer" /MIR /R:1 /W:1 /XJ /MT:8 /LOG:"E:\Sicherung\robocopy.log" /TEE
```

`E:` durch den Buchstaben der externen Platte ersetzen. `/R:1 /W:1` sorgt dafür, dass
robocopy bei einem Lesefehler nicht minutenlang hängt, sondern weitergeht und den Fehler
protokolliert. **Nach dem Lauf die Log-Datei nach `ERROR` durchsuchen** — das sind die
Dateien, die die SSD nicht mehr hergeben konnte:

```powershell
Select-String -Path "E:\Sicherung\robocopy.log" -Pattern 'ERROR' -Context 0,1
```

Nicht vergessen, was außerhalb des Benutzerordners liegt: Daten in `C:\MSI`, Projekte
unter `C:\`, Lizenzschlüssel, Browser-Profile (falls nicht im Benutzerordner), virtuelle
Maschinen, Datenbanken.

### 2. Lizenzlage klären

Windows ist als RETAIL aktiviert. Vor dem Wipe prüfen, was dort steht:

**Einstellungen → System → Aktivierung**

- Steht dort **„digitale Lizenz"**, reaktiviert sich Windows auf derselben Hardware nach
  der Neuinstallation von selbst.
- Steht dort ein Produktschlüssel, notiere ihn vorher.
- In beiden Fällen: die Lizenz mit dem Microsoft-Konto verknüpfen, dann lässt sie sich
  im Zweifel über „Ich habe die Hardware dieses Geräts kürzlich geändert" zurückholen.

Office 2019 hängt an einem externen KMS-Server und muss nach einer Neuinstallation neu
aktiviert werden. Siehe `WPA-Watch.ps1` und die Hinweise zum Lizenzspeicher.

### 3. BitLocker prüfen

Konnte ich ohne Administratorrechte nicht feststellen. In einer PowerShell als
Administrator:

```powershell
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus
```

Ist C: verschlüsselt, **vor** dem Klonen den Wiederherstellungsschlüssel sichern,
sonst ist der Klon nicht lesbar. Besser: BitLocker vorher aussetzen.

### 4. Was du NICHT tun solltest

- **Kein `chkdsk /r`.** Das erzwingt einen Oberflächenscan der ganzen Platte — genau die
  Belastung, die am 6.11. die 62 Fehler ausgelöst hat. `chkdsk /f` (nur Dateisystem) ist
  unkritisch, war hier aber schon sauber.
- **Keine Defragmentierung, keine SSD-Optimierung** vor dem Umzug.
- **Nicht die alte Platte löschen oder formatieren**, bis der neue Zustand mehrere Tage
  stabil läuft.

## Weg A: Neuinstallation (empfohlen)

Die 312 nicht behebbaren Datenfehler bedeuten, dass die SSD schon mehrfach Daten nicht
mehr korrekt zurückgeben konnte. Welche Dateien betroffen sind, weiß niemand — es können
Systemdateien sein. Ein Klon nimmt diese Schäden mit. Dazu kommt, dass dieses Windows
eine 125-MB-Registry mit 347.377 Lizenzmüll-Schlüsseln angesammelt hatte; eine
Neuinstallation räumt das mit auf.

1. Windows-11-/10-Installationsmedium mit dem Media Creation Tool auf einen USB-Stick
   schreiben (an einem anderen PC, oder jetzt, solange dieser läuft).
2. Neue SSD in den M.2-Slot einbauen, alte SSD ausbauen.
3. Vom Stick booten, bei der Partitionierung **alle** Partitionen der neuen SSD löschen
   und Windows auf den unzugeordneten Speicherplatz installieren. Dann legt Windows das
   UEFI/GPT-Layout korrekt neu an.
4. Treiber: Chipsatz und LAN von der MSI-Produktseite zum Z390-A PRO. Der NVMe-Treiber
   von Windows genügt.
5. Daten aus der Sicherung zurückkopieren, Programme neu installieren.
6. Alte SSD ins USB-Gehäuse — falls doch etwas fehlt, ist es dort noch (soweit lesbar).

## Weg B: Klonen (wenn es schnell gehen muss)

Nachteil: Mögliche Dateischäden und die Altlasten ziehen mit um.

1. Neue SSD ins USB-Gehäuse, anschließen.
2. Klonen. Macrium Reflect Free gibt es nicht mehr (Support endete Anfang 2024).
   Kostenlos und für diesen Fall geeignet:
   - **Rescuezilla** (grafisch) oder **Clonezilla** (textbasiert), beide bootfähig
   - **Hasleo Backup Suite Free** oder **Veeam Agent for Windows Free** für Images
   - **GNU ddrescue** von einem Linux-Stick ist bei einer defekten Quellplatte technisch
     am saubersten: es protokolliert jeden unlesbaren Sektor, wiederholt gezielt und
     sagt dir am Ende genau, was fehlt. Dafür ohne Komfort.
3. **Wichtig:** ein Klonwerkzeug wählen, das Lesefehler **protokolliert** statt sie
   stillschweigend zu überspringen. Sonst hast du eine Kopie, die scheinbar in Ordnung
   ist, und merkst den Verlust Monate später.
4. Klon prüfen, bevor die alte Platte aus dem Rechner kommt.
5. Platten tauschen: neue SSD in den M.2-Slot, alte ins Gehäuse.
6. Da die neue SSD größer ist, die Systempartition in der Datenträgerverwaltung auf den
   freien Platz erweitern.

## Nach dem Umzug

1. Im BIOS prüfen, dass die neue SSD als Startgerät eingetragen ist (UEFI, nicht Legacy).
2. Startzeit messen. Nach der WPA-Bereinigung lag sie bei 30 Sekunden — das ist der
   Vergleichswert.
3. Diagnose laufen lassen und die neuen NVMe-Werte ansehen. Reserve muss **100 %** und
   Datenfehler **0** sein:
   ```powershell
   & "C:\Users\Besitzer\Documents\_ANDRE\WindowsPerformanceAnalyse\_Start-PerfDiag.bat"
   ```
4. Lizenzspeicher-Überwachung wieder einrichten:
   ```powershell
   powershell -ExecutionPolicy Bypass -File "C:\Users\Besitzer\Documents\_ANDRE\WindowsPerformanceAnalyse\WPA-Watch.ps1" -Register
   ```
5. TRIM prüfen (muss `0` sein): `fsutil behavior query DisableDeleteNotify`
6. Alte SSD mindestens zwei Wochen unangetastet aufbewahren.

## Wenn der neue Start scheitert

- Alte SSD zurück in den M.2-Slot — damit ist der alte Zustand wieder da, solange du sie
  nicht gelöscht hast.
- Startet die neue SSD nicht, liegt es meist an der Bootreihenfolge im BIOS oder an einer
  fehlenden EFI-Partition (bei Weg B, wenn nur C: geklont wurde statt der ganzen Platte).

## Randnotiz

Auf der alten Platte sind nur 419,19 GB der 466 GB partitioniert, etwa 47 GB liegen
unzugeordnet. Das wirkt wie zusätzliches Overprovisioning und ist bei einer abgenutzten
SSD eher günstig. Bei der neuen SSD ist das nicht nötig — moderne Laufwerke bringen ihre
Reserve selbst mit.
