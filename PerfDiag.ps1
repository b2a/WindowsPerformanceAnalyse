#Requires -Version 5.1
<#
.SYNOPSIS
    PerfDiag - Leistungs- und Flaschenhals-Analyse fuer Windows 10/11.

.DESCRIPTION
    Phase 1 (Live-Messung): misst ueber einen Zeitraum CPU, DPC/Interrupts (Treiberlast), System-Haenger
    (eingebauter Mini-"LatencyMon"), RAM/Auslagerung, Datentraeger-Latenz und Prozesse.
    Waehrend der Messung kannst du per Tastenkombination markieren, wann du einen Haenger spuerst.

    Phase 2 (Systemzustand): S.M.A.R.T./NVMe-Zustand, freier Speicher, Ereignisprotokolle,
    Netzlaufwerke, Explorer-Erweiterungen, Autostart, Virenschutz, Treiber, Tastatur-Einstellungen.

    Phase 3 (Auswertung): Ampel je Kategorie, priorisierte Liste der wahrscheinlichsten Bremsen
    mit Empfehlungen. Ausgabe: Konsole + Bericht.md + daten.json + zeitverlauf.csv.

.PARAMETER Seconds
    Messdauer in Sekunden (Standard 120). Fuer gelegentliche Haenger besser 900-1800 waehrend normaler Arbeit.

.PARAMETER OutputDir
    Zielordner fuer die Berichte (Standard: Desktop\PerfDiag_<Datum>).

.PARAMETER AutorunsPath
    Pfad zu autorunsc64.exe oder dessen Ordner (Sysinternals, optional).

.PARAMETER Trace
    Zusaetzlich eine WPR-Ablaufverfolgung (CPU + Disk) aufzeichnen. Wenn xperf (Windows ADK) installiert ist,
    wird automatisch ein DPC/ISR-Bericht pro Treiber erstellt. Nur fuer Messungen bis 5 Minuten.

.PARAMETER FromJson
    Eine fruehere daten.json erneut auswerten (ohne neue Messung).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\PerfDiag.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\PerfDiag.ps1 -Seconds 1200
#>
[CmdletBinding()]
param(
    [ValidateRange(10, 14400)]
    [int]$Seconds = 120,
    [string]$OutputDir,
    [ValidateRange(1, 60)]
    [int]$EventDays = 7,
    [string]$AutorunsPath,
    [switch]$Trace,
    [switch]$SkipAutoruns,
    [switch]$SkipDrivers,
    [switch]$NoElevate,
    [switch]$NoAnonymize,
    [switch]$NoOpen,
    [switch]$NoPause,
    [string]$FromJson
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$script:Version = '1.2.0'
$script:Errors = New-Object System.Collections.Generic.List[string]
$script:Findings = New-Object System.Collections.Generic.List[object]
$script:CompanyCache = @{}

$script:Categories = @(
    'CPU',
    'Treiber & Latenz',
    'Arbeitsspeicher',
    'Datenträger',
    'Explorer & Dateien',
    'Eingabe',
    'Energie & Thermik',
    'Software & Autostart',
    'Stabilität & Hardware'
)

#region ---------------------------------------------------------------- Native helpers (C#)
# Bewusst C# 5 kompatibel, damit es mit Windows PowerShell 5.1 (csc.exe aus .NET 4.x) kompiliert.
$script:NativeCode = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PerfDiagV1
{
    // Leistungsindikatoren ueber PDH. Englische Pfade funktionieren auf jeder Sprachversion
    // (PdhAddEnglishCounter); Fallback: Uebersetzung ueber die Perflib-Namensliste.
    public class Pdh : IDisposable
    {
        [StructLayout(LayoutKind.Sequential)]
        struct FmtValue { public uint CStatus; public double DoubleValue; }

        [StructLayout(LayoutKind.Sequential)]
        struct FmtItem { public IntPtr Name; public FmtValue Value; }

        [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
        static extern uint PdhOpenQueryW(string dataSource, IntPtr userData, out IntPtr query);
        [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
        static extern uint PdhAddEnglishCounterW(IntPtr query, string path, IntPtr userData, out IntPtr counter);
        [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
        static extern uint PdhAddCounterW(IntPtr query, string path, IntPtr userData, out IntPtr counter);
        [DllImport("pdh.dll")]
        static extern uint PdhCollectQueryData(IntPtr query);
        [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
        static extern uint PdhGetFormattedCounterArrayW(IntPtr counter, uint format, ref uint bufferSize, out uint itemCount, IntPtr itemBuffer);
        [DllImport("pdh.dll")]
        static extern uint PdhCloseQuery(IntPtr query);
        [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
        static extern uint PdhLookupPerfNameByIndexW(string machine, uint index, StringBuilder nameBuffer, ref uint bufferSize);
        [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
        static extern uint PdhExpandWildCardPathW(string dataSource, string wildCardPath, IntPtr expandedPathList, ref uint pathListLength, uint flags);

        const uint PDH_MORE_DATA = 0x800007D2;
        const uint FMT_DOUBLE_NOCAP = 0x00000200 | 0x00008000;
        static readonly int ItemSize = Marshal.SizeOf(typeof(FmtItem));

        IntPtr query = IntPtr.Zero;
        readonly Dictionary<string, IntPtr> counters = new Dictionary<string, IntPtr>();
        readonly Dictionary<string, uint> english = new Dictionary<string, uint>(StringComparer.OrdinalIgnoreCase);

        public Pdh()
        {
            uint r = PdhOpenQueryW(null, IntPtr.Zero, out query);
            if (r != 0) throw new InvalidOperationException("PdhOpenQuery fehlgeschlagen: 0x" + r.ToString("X8"));
        }

        public void SetEnglishNames(string[] perflibCounter)
        {
            if (perflibCounter == null) return;
            for (int i = 0; i + 1 < perflibCounter.Length; i += 2)
            {
                uint idx;
                string name = perflibCounter[i + 1];
                if (uint.TryParse(perflibCounter[i], out idx) && !string.IsNullOrEmpty(name) && !english.ContainsKey(name))
                    english[name] = idx;
            }
        }

        string LocalName(string englishName)
        {
            uint idx;
            if (!english.TryGetValue(englishName, out idx)) return null;
            uint size = 1024;
            StringBuilder sb = new StringBuilder((int)size);
            if (PdhLookupPerfNameByIndexW(null, idx, sb, ref size) != 0) return null;
            return sb.ToString();
        }

        public string Translate(string path)
        {
            Match m = Regex.Match(path, @"^\\([^\\(]+)(\([^)]*\))?\\(.+)$");
            if (!m.Success) return null;
            string obj = LocalName(m.Groups[1].Value);
            string ctr = LocalName(m.Groups[3].Value);
            if (obj == null || ctr == null) return null;
            return "\\" + obj + m.Groups[2].Value + "\\" + ctr;
        }

        static string ExpandFirstInstance(string wildPath)
        {
            uint len = 0;
            uint r = PdhExpandWildCardPathW(null, wildPath, IntPtr.Zero, ref len, 0);
            if (r != PDH_MORE_DATA || len == 0) return null;
            IntPtr buf = Marshal.AllocHGlobal((int)((len + 16) * 2));
            try
            {
                r = PdhExpandWildCardPathW(null, wildPath, buf, ref len, 0);
                if (r != 0) return null;
                return Marshal.PtrToStringUni(buf);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public string Add(string key, string path)
        {
            IntPtr c;
            uint r = PdhAddEnglishCounterW(query, path, IntPtr.Zero, out c);
            if (r == 0) { counters[key] = c; return null; }
            string local = Translate(path);
            if (local != null)
            {
                uint r2 = PdhAddCounterW(query, local, IntPtr.Zero, out c);
                if (r2 == 0) { counters[key] = c; return null; }
                if (local.IndexOf("(_Total)", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    string wild = Regex.Replace(local, @"\(_Total\)", "(*)", RegexOptions.IgnoreCase);
                    string exp = ExpandFirstInstance(wild);
                    if (!string.IsNullOrEmpty(exp))
                    {
                        uint r3 = PdhAddCounterW(query, exp, IntPtr.Zero, out c);
                        if (r3 == 0) { counters[key] = c; return null; }
                    }
                }
                return "0x" + r.ToString("X8") + " (lokalisiert '" + local + "': 0x" + r2.ToString("X8") + ")";
            }
            return "0x" + r.ToString("X8");
        }

        public bool Has(string key) { return counters.ContainsKey(key); }

        public uint Collect() { return PdhCollectQueryData(query); }

        public Dictionary<string, double> Read(string key)
        {
            Dictionary<string, double> result = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
            IntPtr c;
            if (!counters.TryGetValue(key, out c)) return result;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                uint size = 0;
                uint count;
                uint r = PdhGetFormattedCounterArrayW(c, FMT_DOUBLE_NOCAP, ref size, out count, IntPtr.Zero);
                if (r != PDH_MORE_DATA || size == 0) return result;
                size += 4096;
                IntPtr buf = Marshal.AllocHGlobal((int)size);
                try
                {
                    r = PdhGetFormattedCounterArrayW(c, FMT_DOUBLE_NOCAP, ref size, out count, buf);
                    if (r == PDH_MORE_DATA) continue;
                    if (r != 0) return result;
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr p = new IntPtr(buf.ToInt64() + (long)i * ItemSize);
                        FmtItem item = (FmtItem)Marshal.PtrToStructure(p, typeof(FmtItem));
                        if (item.Value.CStatus != 0 && item.Value.CStatus != 1) continue;
                        double v = item.Value.DoubleValue;
                        if (double.IsNaN(v) || double.IsInfinity(v)) continue;
                        string name = item.Name == IntPtr.Zero ? "" : Marshal.PtrToStringUni(item.Name);
                        double old;
                        if (result.TryGetValue(name, out old)) result[name] = old + v; else result[name] = v;
                    }
                    return result;
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            return result;
        }

        public void Dispose()
        {
            if (query != IntPtr.Zero) { PdhCloseQuery(query); query = IntPtr.Zero; }
        }
    }

    public class StallEvent
    {
        public DateTime Time;
        public double GapMs;
    }

    public class MarkEvent
    {
        public DateTime Time;
        public string ForegroundProcess;
        public string WindowTitle;
    }

    // Mini-"LatencyMon": ein Thread mit hoher Prioritaet schlaeft jeweils 1 ms und misst, wie spaet er
    // wieder aufwacht. Aussetzer >= 50 ms bedeuten, dass das ganze System kurz nicht reagiert hat
    // (typisch: Treiber-DPC/ISR, Firmware/SMI, Energiesparzustaende). Dazu globale Markier-Hotkeys.
    public class LagMonitor
    {
        [DllImport("winmm.dll")] static extern uint timeBeginPeriod(uint p);
        [DllImport("winmm.dll")] static extern uint timeEndPeriod(uint p);
        [DllImport("user32.dll", SetLastError = true)] static extern bool RegisterHotKey(IntPtr hWnd, int id, uint mods, uint vk);
        [DllImport("user32.dll")] static extern bool UnregisterHotKey(IntPtr hWnd, int id);
        [DllImport("user32.dll")] static extern bool PeekMessage(out NativeMsg msg, IntPtr hWnd, uint min, uint max, uint remove);
        [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [StructLayout(LayoutKind.Sequential)]
        struct NativeMsg { public IntPtr hwnd; public uint message; public IntPtr wParam; public IntPtr lParam; public uint time; public int x; public int y; public uint priv; }

        readonly object sync = new object();
        volatile bool running;
        Thread lagThread;
        Thread keyThread;
        readonly List<StallEvent> pending = new List<StallEvent>();
        readonly List<MarkEvent> marks = new List<MarkEvent>();
        double windowMax;

        public long Iterations;
        public double MaxGapMs;
        public int Over50;
        public int Over100;
        public int Over250;
        public int Over1000;
        public double TotalStallMs;
        public int GcSkipped;
        public string HotkeyInfo = "";
        public double ThresholdMs = 50;

        public static MarkEvent CaptureForeground()
        {
            MarkEvent m = new MarkEvent();
            m.Time = DateTime.Now;
            m.ForegroundProcess = "";
            m.WindowTitle = "";
            try
            {
                IntPtr fg = GetForegroundWindow();
                if (fg != IntPtr.Zero)
                {
                    StringBuilder sb = new StringBuilder(256);
                    if (GetWindowTextW(fg, sb, 256) > 0) m.WindowTitle = sb.ToString();
                    uint pid;
                    GetWindowThreadProcessId(fg, out pid);
                    if (pid != 0)
                    {
                        using (Process p = Process.GetProcessById((int)pid)) { m.ForegroundProcess = p.ProcessName; }
                    }
                }
            }
            catch { }
            return m;
        }

        public void Start()
        {
            running = true;
            try { timeBeginPeriod(1); } catch { }
            lagThread = new Thread(LagLoop);
            lagThread.IsBackground = true;
            lagThread.Priority = ThreadPriority.Highest;
            lagThread.Start();
            keyThread = new Thread(KeyLoop);
            keyThread.IsBackground = true;
            keyThread.Start();
        }

        public void Stop()
        {
            running = false;
            if (lagThread != null) lagThread.Join(2000);
            if (keyThread != null) keyThread.Join(2000);
            try { timeEndPeriod(1); } catch { }
        }

        void LagLoop()
        {
            Stopwatch sw = Stopwatch.StartNew();
            double freq = Stopwatch.Frequency;
            long last = sw.ElapsedTicks;
            while (running)
            {
                int gc0 = GC.CollectionCount(0);
                Thread.Sleep(1);
                long now = sw.ElapsedTicks;
                double gap = (now - last) * 1000.0 / freq;
                last = now;
                bool gc = GC.CollectionCount(0) != gc0;
                lock (sync)
                {
                    Iterations++;
                    if (gc && gap >= ThresholdMs) { GcSkipped++; continue; }
                    if (gap > windowMax) windowMax = gap;
                    if (gap > MaxGapMs) MaxGapMs = gap;
                    if (gap >= ThresholdMs)
                    {
                        Over50++;
                        if (gap >= 100) Over100++;
                        if (gap >= 250) Over250++;
                        if (gap >= 1000) Over1000++;
                        TotalStallMs += gap;
                        if (pending.Count < 5000)
                        {
                            StallEvent e = new StallEvent();
                            e.Time = DateTime.Now;
                            e.GapMs = gap;
                            pending.Add(e);
                        }
                    }
                }
            }
        }

        void KeyLoop()
        {
            const uint MOD_ALT = 1, MOD_CONTROL = 2, MOD_SHIFT = 4, MOD_NOREPEAT = 0x4000;
            bool k1 = false, k2 = false;
            try
            {
                k1 = RegisterHotKey(IntPtr.Zero, 1, MOD_NOREPEAT, 0x13);                                   // Pause/Untbr
                k2 = RegisterHotKey(IntPtr.Zero, 2, MOD_CONTROL | MOD_ALT | MOD_SHIFT | MOD_NOREPEAT, 0x4D); // Strg+Alt+Umschalt+M
                HotkeyInfo = (k1 ? "Pause/Untbr" : "") + (k1 && k2 ? " oder " : "") + (k2 ? "Strg+Alt+Umschalt+M" : "");
                while (running)
                {
                    NativeMsg msg;
                    while (PeekMessage(out msg, IntPtr.Zero, 0x0312, 0x0312, 1))
                    {
                        MarkEvent ev = CaptureForeground();
                        lock (sync) { marks.Add(ev); }
                    }
                    Thread.Sleep(25);
                }
            }
            catch (Exception ex) { HotkeyInfo = "Hotkeys nicht verfuegbar: " + ex.Message; }
            finally
            {
                try { if (k1) UnregisterHotKey(IntPtr.Zero, 1); if (k2) UnregisterHotKey(IntPtr.Zero, 2); } catch { }
            }
        }

        public StallEvent[] DrainEvents() { lock (sync) { StallEvent[] a = pending.ToArray(); pending.Clear(); return a; } }
        public MarkEvent[] DrainMarks() { lock (sync) { MarkEvent[] a = marks.ToArray(); marks.Clear(); return a; } }
        public double TakeWindowMax() { lock (sync) { double v = windowMax; windowMax = 0; return v; } }
    }

    // Kernel-Speicher je Pool-Tag (wie poolmon), via NtQuerySystemInformation(SystemPoolTagInformation).
    public static class PoolTags
    {
        [DllImport("ntdll.dll")]
        static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);

        // Liefert je Tag: [Tag, PagedBytes, NonPagedBytes, PagedAllocsOffen, NonPagedAllocsOffen]
        public static object[][] Query()
        {
            int size = 1 << 20;
            for (int attempt = 0; attempt < 6; attempt++)
            {
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    int ret;
                    int st = NtQuerySystemInformation(22, buf, size, out ret);
                    if (st == unchecked((int)0xC0000004)) { size = Math.Max(size * 2, ret + 65536); continue; }
                    if (st != 0) throw new InvalidOperationException("NtQuerySystemInformation: 0x" + st.ToString("X8"));
                    int count = Marshal.ReadInt32(buf);
                    bool x64 = IntPtr.Size == 8;
                    int head = IntPtr.Size;
                    int entry = x64 ? 40 : 28;
                    List<object[]> list = new List<object[]>();
                    for (int i = 0; i < count; i++)
                    {
                        long b = buf.ToInt64() + head + (long)i * entry;
                        byte[] t = new byte[4];
                        Marshal.Copy(new IntPtr(b), t, 0, 4);
                        string tag = Encoding.ASCII.GetString(t).Replace('\0', ' ');
                        long pa = (uint)Marshal.ReadInt32(new IntPtr(b + 4));
                        long pf = (uint)Marshal.ReadInt32(new IntPtr(b + 8));
                        long pu = x64 ? Marshal.ReadInt64(new IntPtr(b + 16)) : (uint)Marshal.ReadInt32(new IntPtr(b + 12));
                        long na = (uint)Marshal.ReadInt32(new IntPtr(b + (x64 ? 24 : 16)));
                        long nf = (uint)Marshal.ReadInt32(new IntPtr(b + (x64 ? 28 : 20)));
                        long nu = x64 ? Marshal.ReadInt64(new IntPtr(b + 32)) : (uint)Marshal.ReadInt32(new IntPtr(b + 24));
                        list.Add(new object[] { tag, pu, nu, pa - pf, na - nf });
                    }
                    return list.ToArray();
                }
                finally { Marshal.FreeHGlobal(buf); }
            }
            throw new InvalidOperationException("Puffer zu klein");
        }

        // Sucht die Tags als Text in den Treiberdateien (wie "findstr /m /l TAG *.sys").
        public static Dictionary<string, List<string>> FindInDrivers(string[] tags, string[] files)
        {
            Dictionary<string, List<string>> res = new Dictionary<string, List<string>>();
            foreach (string t in tags) res[t] = new List<string>();
            Encoding latin = Encoding.GetEncoding(28591);
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string f in files)
            {
                if (string.IsNullOrEmpty(f)) continue;
                string leaf = Path.GetFileName(f);
                if (!seen.Add(leaf)) continue;
                string text;
                try { text = latin.GetString(File.ReadAllBytes(f)); } catch { continue; }
                foreach (string t in tags)
                {
                    if (text.IndexOf(t, StringComparison.Ordinal) >= 0) res[t].Add(f);
                }
            }
            return res;
        }
    }

    public static class FsProbe
    {
        // Liefert [Anzahl Eintraege, Millisekunden, Status]; blockiert hoechstens timeoutMs.
        public static object[] TimedEnumerate(string path, int timeoutMs)
        {
            int count = -1;
            string err = null;
            Stopwatch sw = Stopwatch.StartNew();
            Thread t = new Thread(delegate ()
            {
                try
                {
                    int n = 0;
                    foreach (string entry in Directory.EnumerateFileSystemEntries(path)) { n++; }
                    count = n;
                }
                catch (Exception ex) { err = ex.Message; }
            });
            t.IsBackground = true;
            t.Start();
            bool done = t.Join(timeoutMs);
            double ms = Math.Round(sw.Elapsed.TotalMilliseconds, 1);
            string status = done ? (err == null ? "OK" : "Fehler: " + err) : "Timeout";
            return new object[] { count, ms, status };
        }

        // Liefert [existiert, Millisekunden, Status]
        public static object[] TimedExists(string path, int timeoutMs)
        {
            bool exists = false;
            string err = null;
            Stopwatch sw = Stopwatch.StartNew();
            Thread t = new Thread(delegate ()
            {
                try { exists = Directory.Exists(path); }
                catch (Exception ex) { err = ex.Message; }
            });
            t.IsBackground = true;
            t.Start();
            bool done = t.Join(timeoutMs);
            double ms = Math.Round(sw.Elapsed.TotalMilliseconds, 1);
            string status = done ? (err == null ? (exists ? "OK" : "nicht erreichbar") : "Fehler: " + err) : "Timeout";
            return new object[] { exists && done, ms, status };
        }

        // Schreibt n kleine Dateien mit WriteThrough und misst die Dauer (zeigt Virenscanner-/Disk-Bremsen).
        public static double[] WriteLatency(string dir, int n)
        {
            double[] res = new double[n];
            byte[] data = new byte[4096];
            new Random().NextBytes(data);
            for (int i = 0; i < n; i++)
            {
                string p = Path.Combine(dir, "perfdiag_probe_" + i + ".tmp");
                Stopwatch sw = Stopwatch.StartNew();
                using (FileStream fs = new FileStream(p, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                {
                    fs.Write(data, 0, data.Length);
                    fs.Flush(true);
                }
                res[i] = Math.Round(sw.Elapsed.TotalMilliseconds, 2);
                try { File.Delete(p); } catch { }
            }
            return res;
        }
    }
}
'@
#endregion

#region ---------------------------------------------------------------- General helpers
function Add-Err {
    param([string]$Where, $Err)
    if ($Err -is [System.Management.Automation.ErrorRecord]) { $msg = $Err.Exception.Message }
    elseif ($Err -is [Exception]) { $msg = $Err.Message }
    else { $msg = [string]$Err }
    $script:Errors.Add(('{0}: {1}' -f $Where, (($msg -replace '\s+', ' ').Trim())))
}

function Test-NoEvents {
    param($Err)
    return ($Err.FullyQualifiedErrorId -match 'NoMatchingEventsFound' -or $Err.Exception.Message -match 'No events were found|Es wurden keine Ereignisse gefunden|keine Ereignisse')
}

function Invoke-Collector {
    param([string]$Name, [scriptblock]$Block)
    Write-Host ('      {0} ...' -f $Name) -ForegroundColor DarkGray
    try { $r = & $Block }
    catch { Add-Err $Name $_; $r = $null }
    return $r
}

function Get-Rounded {
    param($Value, [int]$Digits = 0)
    if ($null -eq $Value) { return $null }
    try { return [math]::Round([double]$Value, $Digits) } catch { return $null }
}

function Get-Stats {
    param($Values)
    $list = New-Object System.Collections.Generic.List[double]
    foreach ($v in @($Values)) {
        if ($null -eq $v) { continue }
        $d = [double]$v
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { continue }
        $list.Add($d)
    }
    if ($list.Count -eq 0) { return $null }
    $arr = $list.ToArray()
    [Array]::Sort($arr)
    $sum = 0.0
    foreach ($v in $arr) { $sum += $v }
    $n = $arr.Length
    $i50 = [math]::Max(0, [int][math]::Ceiling(0.50 * $n) - 1)
    $i95 = [math]::Max(0, [int][math]::Ceiling(0.95 * $n) - 1)
    return [pscustomobject]@{
        Avg = [math]::Round($sum / $n, 3)
        P50 = [math]::Round($arr[$i50], 3)
        P95 = [math]::Round($arr[$i95], 3)
        Min = [math]::Round($arr[0], 3)
        Max = [math]::Round($arr[$n - 1], 3)
        N   = $n
    }
}

function Get-Count {
    param($Items)
    return @(@($Items) | Where-Object { $null -ne $_ }).Count
}

function Get-MaxExcept {
    param($Dict, [string]$Except = '_Total')
    $max = $null
    if ($null -eq $Dict) { return $null }
    foreach ($kv in $Dict.GetEnumerator()) {
        if ($kv.Key -eq $Except) { continue }
        if ($null -eq $max -or $kv.Value -gt $max) { $max = $kv.Value }
    }
    return $max
}

function Get-TopText {
    param($Map, [string]$Format, [int]$N = 3, [double]$Min = 0)
    if ($null -eq $Map -or $Map.Count -eq 0) { return '' }
    $items = $Map.GetEnumerator() | Where-Object { $_.Value -ge $Min } | Sort-Object Value -Descending | Select-Object -First $N
    return (@($items | ForEach-Object { $Format -f $_.Key, $_.Value }) -join ', ')
}

function Resolve-BinaryPath {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($Raw.Trim())
    if ($p.StartsWith('"')) {
        $end = $p.IndexOf('"', 1)
        if ($end -gt 1) { $p = $p.Substring(1, $end - 1) }
    }
    else {
        $m = [regex]::Match($p, '(?i)^(.+?\.(exe|dll|sys|ocx|cpl))(\s|,|$)')
        if ($m.Success) { $p = $m.Groups[1].Value }
    }
    $p = $p -replace '^\\\?\?\\', ''
    $p = $p -replace '(?i)^\\SystemRoot\\', ($env:SystemRoot + '\')
    if ($p -match '(?i)^system32\\') { $p = Join-Path $env:SystemRoot $p }
    if ($p -and -not [IO.Path]::IsPathRooted($p)) {
        $c = Join-Path (Join-Path $env:SystemRoot 'System32') $p
        if (Test-Path -LiteralPath $c) { $p = $c }
    }
    return $p
}

function Get-FileCompany {
    param([string]$Path)
    if (-not $Path) { return $null }
    if ($script:CompanyCache.ContainsKey($Path)) { return $script:CompanyCache[$Path] }
    $info = [pscustomobject]@{ Exists = $false; Company = ''; Product = ''; Date = '' }
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $fi = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
            $info.Exists = $true
            $info.Company = ([string]$fi.VersionInfo.CompanyName).Trim()
            $info.Product = ([string]$fi.VersionInfo.ProductName).Trim()
            $info.Date = $fi.LastWriteTime.ToString('yyyy-MM-dd')
        }
    } catch {}
    $script:CompanyCache[$Path] = $info
    return $info
}

function Test-Microsoft {
    param([string]$Company)
    return ($Company -match '(?i)microsoft')
}

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Format-Date {
    param($Date, [string]$Format = 'yyyy-MM-dd HH:mm')
    if ($null -eq $Date) { return '' }
    try { return ([datetime]$Date).ToString($Format) } catch { return [string]$Date }
}
#endregion

#region ---------------------------------------------------------------- Known patterns
# Ereignis-Regeln: Provider (Regex), IDs, Tag fuer die Auswertung, Bedeutung
$script:StorageProv = '(?i)stor|nvme|iastor|ahci|sata|amdsbs|raid|megasas|rst'
$script:EventRules = @(
    @{ P = '^disk$'; Ids = @(7); Tag = 'disk-bad'; Text = 'Fehlerhafter Block (Bad Sector) auf einem Laufwerk' }
    @{ P = '^disk$'; Ids = @(11); Tag = 'disk-bad'; Text = 'Controller-Fehler an einem Laufwerk' }
    @{ P = '^disk$'; Ids = @(52); Tag = 'disk-bad'; Text = 'Laufwerk meldet drohenden Ausfall (S.M.A.R.T.)' }
    @{ P = '^disk$'; Ids = @(51); Tag = 'disk-retry'; Text = 'Fehler beim Auslagern (Paging) auf ein Laufwerk' }
    @{ P = '^disk$'; Ids = @(153); Tag = 'disk-retry'; Text = 'E/A wurde wiederholt - Laufwerk hat nicht rechtzeitig geantwortet' }
    @{ P = '^disk$'; Ids = @(157); Tag = 'disk-retry'; Text = 'Laufwerk wurde unerwartet entfernt' }
    @{ P = $script:StorageProv; Ids = @(129, 9); Tag = 'disk-reset'; Text = 'Speicher-Controller musste Laufwerk zuruecksetzen (Laufwerk hing)' }
    @{ P = '(?i)^(Microsoft-Windows-)?Ntfs$'; Ids = @(55, 98, 137, 140); Tag = 'ntfs'; Text = 'Dateisystem-Problem (NTFS)' }
    @{ P = 'Kernel-Power'; Ids = @(41); Tag = 'kernel-power'; Text = 'Unerwarteter Neustart / Absturz ohne sauberes Herunterfahren' }
    @{ P = 'WER-SystemErrorReporting|BugCheck'; Ids = @(1001); Tag = 'bugcheck'; Text = 'Bluescreen (BugCheck)' }
    @{ P = 'WHEA-Logger'; Ids = @(17); Tag = 'whea-corrected'; Text = 'Korrigierter Hardwarefehler (meist PCIe) - kann Ruckler verursachen' }
    @{ P = 'WHEA-Logger'; Ids = @(1, 18, 19, 20, 46, 47); Tag = 'whea'; Text = 'Hardwarefehler (CPU/RAM/PCIe)' }
    @{ P = 'Kernel-Processor-Power'; Ids = @(37); Tag = 'throttle'; Text = 'CPU-Takt wird durch Firmware begrenzt (Hitze/Energie)' }
    @{ P = 'Resource-Exhaustion-Detector'; Ids = @(2004); Tag = 'lowmem'; Text = 'Windows meldet zu wenig virtuellen Arbeitsspeicher' }
    @{ P = '^Display$'; Ids = @(4101); Tag = 'gpu-tdr'; Text = 'Grafiktreiber reagierte nicht und wurde neu gestartet' }
    @{ P = '(?i)nvlddmkm|amdkmdag|amdwddmg|igfx'; Ids = @(); Tag = 'gpu-tdr'; Text = 'Fehler im Grafiktreiber' }
    @{ P = 'Service Control Manager'; Ids = @(7009, 7011); Tag = 'svc-timeout'; Text = 'Dienst hat nicht rechtzeitig reagiert' }
    @{ P = 'Service Control Manager'; Ids = @(7031, 7034); Tag = 'svc-crash'; Text = 'Dienst wurde unerwartet beendet' }
    @{ P = 'Kernel-PnP'; Ids = @(219); Tag = 'pnp'; Text = 'Treiber konnte nicht geladen werden' }
    @{ P = 'DistributedCOM'; Ids = @(10016); Tag = 'noise'; Text = 'Harmlos (DCOM-Berechtigungen) - ignorieren' }
)

# Programme, die haeufig Latenzen/Hintergrundlast verursachen (Hinweis, keine Verurteilung)
$script:KnownTools = @(
    @{ P = '(?i)^(ArmouryCrate|ArmouryCrate\.Service|ArmourySocketServer|LightingService|ROGLiveService|AsusCertService)'; Name = 'ASUS Armoury Crate / Aura'; Kind = 'latency' }
    @{ P = '(?i)^Nahimic'; Name = 'Nahimic Audio'; Kind = 'latency' }
    @{ P = '(?i)^(SonicStudio|SonicRadar|SS3Svc)'; Name = 'ASUS Sonic Studio/Radar'; Kind = 'latency' }
    @{ P = '(?i)^(KillerNetworkService|KNDBWM|Killer|RivetNetworks)'; Name = 'Killer Network Suite'; Kind = 'latency' }
    @{ P = '(?i)^(iCUE|Corsair)'; Name = 'Corsair iCUE'; Kind = 'input' }
    @{ P = '(?i)^(lghub|LogiOptions|logioptionsplus|LogiOverlay)'; Name = 'Logitech G HUB / Options+'; Kind = 'input' }
    @{ P = '(?i)^(Razer|RzSynapse|RzSDKService)'; Name = 'Razer Synapse'; Kind = 'input' }
    @{ P = '(?i)^(SteelSeriesGG|SteelSeriesEngine|SteelSeriesSonar)'; Name = 'SteelSeries GG'; Kind = 'input' }
    @{ P = '(?i)^NZXT'; Name = 'NZXT CAM'; Kind = 'latency' }
    @{ P = '(?i)^(MSI\.CentralServer|MSI_Central|MSICenter|Dragon ?Center|MysticLight|MSI\.TerminalServer)'; Name = 'MSI Center / Dragon Center'; Kind = 'latency' }
    @{ P = '(?i)^(SignalRgb|OpenRGB)'; Name = 'RGB-Steuerung'; Kind = 'latency' }
    @{ P = '(?i)^(IObit|DriverBooster|ASCService|SmartDefrag|IMFsrv)'; Name = 'IObit "Optimierer"'; Kind = 'bloat' }
    @{ P = '(?i)^(CCleaner|CCleanerPerformanceOptimizerService)'; Name = 'CCleaner (Hintergrunddienst)'; Kind = 'bloat' }
    @{ P = '(?i)^(wallpaper32|wallpaper64|webwallpaper32|Lively)$'; Name = 'Animierter Hintergrund (Wallpaper Engine/Lively)'; Kind = 'bloat' }
    @{ P = '(?i)^(RTSS|MSIAfterburner)$'; Name = 'MSI Afterburner / RivaTuner (Overlay)'; Kind = 'input' }
    @{ P = '(?i)^Overwolf'; Name = 'Overwolf (Overlay)'; Kind = 'input' }
    @{ P = '(?i)^(SupportAssistAgent|DellSupportAssist|Dell\.TechHub)'; Name = 'Dell SupportAssist'; Kind = 'bloat' }
    @{ P = '(?i)^(LenovoVantageService|ImControllerService)'; Name = 'Lenovo Vantage'; Kind = 'bloat' }
    @{ P = '(?i)^(HPAudioSwitch|HpTouchpointAnalyticsClient|HPAnalytics)'; Name = 'HP Telemetrie/Audio-Tools'; Kind = 'bloat' }
)

$script:AvProcesses = '(?i)^(MsMpEng|NisSrv|MpDefenderCoreService|avp|avpui|AvastSvc|AvastUI|AVGSvc|mcshield|mfemms|mfevtps|ModuleCoreService|bdservicehost|bdagent|vsserv|ekrn|egui|NortonSecurity|ccSvcHst|SophosHealth|SavService|WRSA|aswEngSrv|360Tray|ZhuDongFangYu)$'
$script:CloudSync = @{
    'OneDrive' = 'OneDrive'; 'Dropbox' = 'Dropbox'; 'GoogleDriveFS' = 'Google Drive'; 'iCloudDrive' = 'iCloud';
    'iCloudServices' = 'iCloud'; 'MEGAsync' = 'MEGA'; 'nextcloud' = 'Nextcloud'; 'owncloud' = 'ownCloud';
    'pCloud' = 'pCloud'; 'SynologyDrive' = 'Synology Drive'; 'cloud-drive-ui' = 'Synology Drive'
}
#endregion

#region ---------------------------------------------------------------- Collector: system
function Get-SystemInfo {
    $s = [ordered]@{}
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $s.OS = $os.Caption
        $s.Version = $os.Version
        $s.Build = $os.BuildNumber
        $s.LastBoot = Format-Date $os.LastBootUpTime
        $s.UptimeHours = Get-Rounded (((Get-Date) - $os.LastBootUpTime).TotalHours) 1
        $s.RamTotalGB = Get-Rounded ($os.TotalVisibleMemorySize / 1MB) 1
    } catch { Add-Err 'System/OS' $_ }
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $s.Manufacturer = $cs.Manufacturer
        $s.Model = $cs.Model
        $s.IsLaptop = ($cs.PCSystemType -eq 2)
        $s.IsVM = (($cs.Model -match '(?i)virtual|vmware|kvm|hvm') -or ($cs.Manufacturer -match '(?i)qemu|xen|innotek|parallels'))
    } catch { Add-Err 'System/Computer' $_ }
    try {
        $cpu = @(Get-CimInstance Win32_Processor -ErrorAction Stop)
        $s.CPU = ([string]$cpu[0].Name).Trim()
        $s.Cores = ($cpu | Measure-Object -Property NumberOfCores -Sum).Sum
        $s.LogicalProcessors = ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
        $s.CpuMaxMHz = $cpu[0].MaxClockSpeed
    } catch { Add-Err 'System/CPU' $_ }
    if (-not $s.LogicalProcessors) { $s.LogicalProcessors = [Environment]::ProcessorCount }
    try {
        $b = Get-CimInstance Win32_BIOS -ErrorAction Stop
        $s.BIOS = '{0} ({1})' -f $b.SMBIOSBIOSVersion, (Format-Date $b.ReleaseDate 'yyyy-MM-dd')
    } catch {}
    try {
        $s.GPU = @(Get-CimInstance Win32_VideoController -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Name = $_.Name; DriverVersion = $_.DriverVersion; DriverDate = (Format-Date $_.DriverDate 'yyyy-MM-dd') }
            })
    } catch {}
    try {
        $out = (& powercfg.exe /getactivescheme 2>$null) -join ' '
        $m = [regex]::Match($out, '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s*\((.+?)\)')
        if ($m.Success) { $s.PowerPlanGuid = $m.Groups[1].Value.ToLower(); $s.PowerPlan = $m.Groups[2].Value }
    } catch {}
    try {
        $overlay = @{
            '961cc777-2547-4f9d-8174-7d86181b8a7a' = 'Beste Energieeffizienz'
            '00000000-0000-0000-0000-000000000000' = 'Ausbalanciert'
            '3af9b8d9-7c97-431d-ad78-34a8bfea439f' = 'Bessere Leistung'
            'ded574b5-45a0-4f42-8737-46345c09c238' = 'Beste Leistung'
        }
        $pk = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes' -ErrorAction Stop
        foreach ($pair in @(@('PowerModeAC', $pk.ActiveOverlayAcPowerScheme), @('PowerModeDC', $pk.ActiveOverlayDcPowerScheme))) {
            $g = ([string]$pair[1]).ToLower()
            if ($g) { if ($overlay.ContainsKey($g)) { $s[$pair[0]] = $overlay[$g] } else { $s[$pair[0]] = $g } }
        }
    } catch {}
    try {
        $bat = @(Get-CimInstance Win32_Battery -ErrorAction Stop)
        if ($bat.Count -gt 0) {
            $s.HasBattery = $true
            $s.OnBattery = ($bat[0].BatteryStatus -eq 1)
            $s.BatteryPct = $bat[0].EstimatedChargeRemaining
        } else { $s.HasBattery = $false; $s.OnBattery = $false }
    } catch {}
    try { $s.FastStartup = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction Stop).HiberbootEnabled -eq 1) } catch {}
    $s.PendingReboot = ((Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
        (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'))
    try {
        $dg = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop
        $s.VBS = ($dg.VirtualizationBasedSecurityStatus -eq 2)
        $s.HVCI = (@($dg.SecurityServicesRunning) -contains 2)
    } catch {}
    try {
        $ex = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | Select-Object -First 1
        if ($ex) { $o = Invoke-CimMethod -InputObject $ex -MethodName GetOwner -ErrorAction Stop; $s.ExplorerUser = $o.User }
    } catch {}
    $s.ScriptUser = $env:USERNAME
    $s.PSVersion = $PSVersionTable.PSVersion.ToString()
    $s.Is64BitProcess = [Environment]::Is64BitProcess
    return $s
}
#endregion

#region ---------------------------------------------------------------- Collector: live sampling
function Invoke-Sampling {
    param([int]$Seconds, [int]$LogicalCpu, [bool]$NativeOk)

    $res = [ordered]@{
        Available = $false; Seconds = $Seconds; SamplesTaken = 0; EndedEarly = $false
        Counters = [ordered]@{}; Disks = @(); TopCpu = @(); TopIo = @()
        CpuPerfUnderLoad = $null; LoadSeconds = 0
        BadSeconds = @(); BadSecondCounts = $null; Marks = @(); Stalls = $null; HotkeyInfo = ''
    }
    $timeline = New-Object System.Collections.Generic.List[object]
    if (-not $NativeOk) {
        Add-Err 'Live-Messung' 'C#-Hilfsmodul nicht verfuegbar - Messung uebersprungen'
        return @{ Result = $res; Timeline = $timeline }
    }
    if ($LogicalCpu -le 0) { $LogicalCpu = 1 }

    $defs = [ordered]@{
        cpu_total      = '\Processor(_Total)\% Processor Time'
        cpu_priv       = '\Processor(_Total)\% Privileged Time'
        cpu_dpc        = '\Processor(_Total)\% DPC Time'
        cpu_int        = '\Processor(_Total)\% Interrupt Time'
        dpc_rate       = '\Processor(_Total)\DPCs Queued/sec'
        int_rate       = '\Processor(_Total)\Interrupts/sec'
        cpu_perf       = '\Processor Information(_Total)\% Processor Performance'
        cpu_freq_pct   = '\Processor Information(_Total)\% of Maximum Frequency'
        run_queue      = '\System\Processor Queue Length'
        ctx_switch     = '\System\Context Switches/sec'
        mem_avail_mb   = '\Memory\Available MBytes'
        mem_commit_pct = '\Memory\% Committed Bytes In Use'
        mem_pages_in   = '\Memory\Pages Input/sec'
        mem_page_reads = '\Memory\Page Reads/sec'
        mem_faults     = '\Memory\Page Faults/sec'
        mem_npp_mb     = '\Memory\Pool Nonpaged Bytes'
        mem_pp_mb      = '\Memory\Pool Paged Bytes'
        pagefile_pct   = '\Paging File(_Total)\% Usage'
        core_dpc       = '\Processor(*)\% DPC Time'
        core_int       = '\Processor(*)\% Interrupt Time'
        disk_lat       = '\PhysicalDisk(*)\Avg. Disk sec/Transfer'
        disk_queue     = '\PhysicalDisk(*)\Current Disk Queue Length'
        disk_idle      = '\PhysicalDisk(*)\% Idle Time'
        disk_bytes     = '\PhysicalDisk(*)\Disk Bytes/sec'
        proc_cpu       = '\Process(*)\% Processor Time'
        proc_io        = '\Process(*)\IO Data Bytes/sec'
        gpu_eng        = '\GPU Engine(*engtype_3D)\Utilization Percentage'
        gpu_mem        = '\GPU Adapter Memory(*)\Dedicated Usage'
    }
    $singleKeys = @('cpu_total', 'cpu_priv', 'cpu_dpc', 'cpu_int', 'dpc_rate', 'int_rate', 'cpu_perf', 'cpu_freq_pct',
        'run_queue', 'ctx_switch', 'mem_avail_mb', 'mem_commit_pct', 'mem_pages_in', 'mem_page_reads', 'mem_faults',
        'mem_npp_mb', 'mem_pp_mb', 'pagefile_pct')
    $optionalCounterKeys = @('gpu_eng', 'gpu_mem')
    $derivedKeys = @('core_dpc_max', 'core_int_max', 'disk_lat_max_ms', 'disk_busy_max', 'lag_max_ms', 'gpu_3d_pct', 'gpu_vram_mb')
    $allKeys = $singleKeys + $derivedKeys

    $pdh = $null
    $lag = $null
    try {
        $pdh = New-Object PerfDiagV1.Pdh
        try {
            $names = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\009' -Name Counter -ErrorAction Stop).Counter
            $pdh.SetEnglishNames([string[]]$names)
        } catch { Add-Err 'Perflib-Namensliste' $_ }
        foreach ($k in $defs.Keys) {
            $e = $pdh.Add($k, $defs[$k])
            if ($e -and ($optionalCounterKeys -notcontains $k)) { Add-Err ('Leistungsindikator {0}' -f $defs[$k]) $e }
        }
    } catch { Add-Err 'PDH (Leistungsindikatoren)' $_; $pdh = $null }
    try { $lag = New-Object PerfDiagV1.LagMonitor; $lag.Start() } catch { Add-Err 'Haenger-Detektor' $_; $lag = $null }
    if (-not $pdh -and -not $lag) { return @{ Result = $res; Timeline = $timeline } }
    $res.Available = [bool]$pdh

    Start-Sleep -Milliseconds 300
    if ($lag) { $res.HotkeyInfo = $lag.HotkeyInfo }
    if ($res.HotkeyInfo -and $res.HotkeyInfo -notmatch '^Hotkeys nicht') {
        Write-Host ('      Hänger gespürt? Drücke {0} (oder M im Fenster) - der Moment wird markiert (Piepton).' -f $res.HotkeyInfo) -ForegroundColor Yellow
    }
    else {
        Write-Host '      Globale Markier-Tasten belegt - drücke M direkt im Konsolenfenster zum Markieren.' -ForegroundColor DarkYellow
    }
    Write-Host '      Q im Konsolenfenster beendet die Messung vorzeitig. Arbeite ansonsten ganz normal weiter.' -ForegroundColor DarkGray

    $series = @{}
    foreach ($k in $allKeys) { $series[$k] = New-Object System.Collections.Generic.List[double] }
    $diskAgg = @{}
    $procCpuSum = @{}; $procCpuMax = @{}; $procIoSum = @{}; $procIoMax = @{}
    $perfUnderLoad = New-Object System.Collections.Generic.List[double]
    $recent = New-Object System.Collections.Generic.Queue[object]
    $bad = New-Object System.Collections.Generic.List[object]
    $badCounts = [ordered]@{ CPU = 0; DPC = 0; Interrupt = 0; Disk = 0; Paging = 0; Haenger = 0; GPU = 0 }
    $markList = New-Object System.Collections.Generic.List[object]
    $stallList = New-Object System.Collections.Generic.List[object]
    $samples = 0
    $quit = $false

    try {
        if ($pdh) { [void]$pdh.Collect() }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        for ($i = 1; ($i -le $Seconds) -and (-not $quit); $i++) {
            $wait = [int]($i * 1000 - $sw.ElapsedMilliseconds)
            if ($wait -gt 0) { Start-Sleep -Milliseconds $wait }
            $now = Get-Date
            $row = [ordered]@{ Zeit = $now.ToString('HH:mm:ss') }
            foreach ($k in $allKeys) { $row[$k] = $null }
            $cpuNow = $null; $dpcMax = $null; $intMax = $null; $latMax = $null; $busyMax = $null
            $pagesIn = $null; $availMb = $null; $lagMax = $null; $gpu3d = $null; $gpuVram = $null
            $topCpuTxt = ''; $topIoTxt = ''

            if ($pdh) {
                [void]$pdh.Collect()
                foreach ($k in $singleKeys) {
                    $dict = $pdh.Read($k)
                    if ($dict.Count -gt 0) {
                        $v = 0.0
                        foreach ($val in $dict.Values) { $v = [double]$val; break }
                        if ($k -eq 'mem_npp_mb' -or $k -eq 'mem_pp_mb') { $v = $v / 1MB }
                        $series[$k].Add($v)
                        $row[$k] = [math]::Round($v, 2)
                    }
                }
                $cpuNow = $row['cpu_total']; $pagesIn = $row['mem_pages_in']; $availMb = $row['mem_avail_mb']
                $dpcMax = Get-MaxExcept ($pdh.Read('core_dpc'))
                $intMax = Get-MaxExcept ($pdh.Read('core_int'))

                if ($pdh.Has('gpu_eng')) {
                    $ge = $pdh.Read('gpu_eng')
                    if ($ge.Count -gt 0) {
                        $gsum = 0.0
                        foreach ($gv in $ge.Values) { $gsum += [double]$gv }
                        $gpu3d = [math]::Min(100.0, $gsum)
                    }
                }
                if ($pdh.Has('gpu_mem')) {
                    $gm = $pdh.Read('gpu_mem')
                    if ($gm.Count -gt 0) {
                        $vmax = 0.0
                        foreach ($mv in $gm.Values) { if ([double]$mv -gt $vmax) { $vmax = [double]$mv } }
                        $gpuVram = $vmax / 1MB
                    }
                }

                $lat = $pdh.Read('disk_lat'); $que = $pdh.Read('disk_queue'); $idle = $pdh.Read('disk_idle'); $byt = $pdh.Read('disk_bytes')
                foreach ($inst in @($lat.Keys)) {
                    if ($inst -eq '_Total') { continue }
                    if (-not $diskAgg.ContainsKey($inst)) {
                        $diskAgg[$inst] = @{
                            lat   = New-Object System.Collections.Generic.List[double]
                            queue = New-Object System.Collections.Generic.List[double]
                            busy  = New-Object System.Collections.Generic.List[double]
                            mbs   = New-Object System.Collections.Generic.List[double]
                        }
                    }
                    $a = $diskAgg[$inst]
                    $l = [double]$lat[$inst] * 1000.0
                    $a.lat.Add($l)
                    if ($null -eq $latMax -or $l -gt $latMax) { $latMax = $l }
                    if ($que.ContainsKey($inst)) { $a.queue.Add([double]$que[$inst]) }
                    if ($idle.ContainsKey($inst)) {
                        $b = [math]::Max(0.0, [math]::Min(100.0, 100.0 - [double]$idle[$inst]))
                        $a.busy.Add($b)
                        if ($null -eq $busyMax -or $b -gt $busyMax) { $busyMax = $b }
                    }
                    if ($byt.ContainsKey($inst)) { $a.mbs.Add([double]$byt[$inst] / 1MB) }
                }

                $cpuBy = @{}
                foreach ($kv in $pdh.Read('proc_cpu').GetEnumerator()) {
                    $n = $kv.Key -replace '#\d+$', ''
                    if ($n -eq '_Total' -or $n -eq 'Idle') { continue }
                    $cpuBy[$n] = [double]$cpuBy[$n] + ($kv.Value / $LogicalCpu)
                }
                foreach ($n in @($cpuBy.Keys)) {
                    $v = $cpuBy[$n]
                    $procCpuSum[$n] = [double]$procCpuSum[$n] + $v
                    if ($v -gt [double]$procCpuMax[$n]) { $procCpuMax[$n] = $v }
                }
                $ioBy = @{}
                foreach ($kv in $pdh.Read('proc_io').GetEnumerator()) {
                    $n = $kv.Key -replace '#\d+$', ''
                    if ($n -eq '_Total' -or $n -eq 'Idle') { continue }
                    $ioBy[$n] = [double]$ioBy[$n] + ($kv.Value / 1MB)
                }
                foreach ($n in @($ioBy.Keys)) {
                    $v = $ioBy[$n]
                    $procIoSum[$n] = [double]$procIoSum[$n] + $v
                    if ($v -gt [double]$procIoMax[$n]) { $procIoMax[$n] = $v }
                }
                $topCpuTxt = Get-TopText $cpuBy '{0} {1:N0}%' 3 1
                $topIoTxt = Get-TopText $ioBy '{0} {1:N1} MB/s' 3 0.5
            }

            if ($null -ne $dpcMax) { $series['core_dpc_max'].Add($dpcMax); $row['core_dpc_max'] = [math]::Round($dpcMax, 2) }
            if ($null -ne $intMax) { $series['core_int_max'].Add($intMax); $row['core_int_max'] = [math]::Round($intMax, 2) }
            if ($null -ne $latMax) { $series['disk_lat_max_ms'].Add($latMax); $row['disk_lat_max_ms'] = [math]::Round($latMax, 1) }
            if ($null -ne $busyMax) { $series['disk_busy_max'].Add($busyMax); $row['disk_busy_max'] = [math]::Round($busyMax, 0) }
            if ($null -ne $gpu3d) { $series['gpu_3d_pct'].Add($gpu3d); $row['gpu_3d_pct'] = [math]::Round($gpu3d, 1) }
            if ($null -ne $gpuVram) { $series['gpu_vram_mb'].Add($gpuVram); $row['gpu_vram_mb'] = [math]::Round($gpuVram, 0) }
            if ($lag) {
                $lagMax = $lag.TakeWindowMax()
                $series['lag_max_ms'].Add($lagMax)
                $row['lag_max_ms'] = [math]::Round($lagMax, 1)
                foreach ($ev in $lag.DrainEvents()) {
                    if ($ev.GapMs -ge 100 -and $stallList.Count -lt 500) {
                        $stallList.Add([pscustomobject]@{ Zeit = $ev.Time.ToString('HH:mm:ss.fff'); Ms = [math]::Round($ev.GapMs, 0) })
                    }
                }
            }
            if ($null -ne $cpuNow -and $cpuNow -ge 50 -and $null -ne $row['cpu_perf']) { $perfUnderLoad.Add([double]$row['cpu_perf']) }

            $sum = [pscustomobject]@{
                Zeit = $row.Zeit; CPU = (Get-Rounded $cpuNow 0); GPU = (Get-Rounded $gpu3d 0); DPCKern = (Get-Rounded $dpcMax 1); IntKern = (Get-Rounded $intMax 1)
                DiskMs = (Get-Rounded $latMax 0); DiskAktiv = (Get-Rounded $busyMax 0); RAMfreiMB = (Get-Rounded $availMb 0); SeitenEin = (Get-Rounded $pagesIn 0)
                HaengerMs = (Get-Rounded $lagMax 0); TopCPU = $topCpuTxt; TopIO = $topIoTxt
            }
            $recent.Enqueue($sum)
            while ($recent.Count -gt 5) { [void]$recent.Dequeue() }

            $reasons = New-Object System.Collections.Generic.List[string]
            if ($null -ne $cpuNow -and $cpuNow -ge 90) { $reasons.Add(('CPU {0:N0} %' -f $cpuNow)); $badCounts.CPU++ }
            if ($null -ne $gpu3d -and $gpu3d -ge 95) { $reasons.Add(('GPU 3D {0:N0} %' -f $gpu3d)); $badCounts.GPU++ }
            if ($null -ne $dpcMax -and $dpcMax -ge 15) { $reasons.Add(('DPC {0:N0} % auf einem Kern' -f $dpcMax)); $badCounts.DPC++ }
            if ($null -ne $intMax -and $intMax -ge 15) { $reasons.Add(('Interrupts {0:N0} % auf einem Kern' -f $intMax)); $badCounts.Interrupt++ }
            if ($null -ne $latMax -and $latMax -ge 100) { $reasons.Add(('Disk-Latenz {0:N0} ms' -f $latMax)); $badCounts.Disk++ }
            if ($null -ne $pagesIn -and $pagesIn -ge 500) { $reasons.Add(('Auslagerung {0:N0} Seiten/s' -f $pagesIn)); $badCounts.Paging++ }
            if ($null -ne $lagMax -and $lagMax -ge 100) { $reasons.Add(('System-Haenger {0:N0} ms' -f $lagMax)); $badCounts.Haenger++ }
            if ($reasons.Count -gt 0 -and $bad.Count -lt 200) {
                $b = $sum.psobject.Copy()
                $b | Add-Member -NotePropertyName Gruende -NotePropertyValue ($reasons -join '; ')
                $bad.Add($b)
            }

            if ($lag) {
                foreach ($m in $lag.DrainMarks()) {
                    $fgTxt = $(if ($m.ForegroundProcess) { '{0} ({1})' -f $m.ForegroundProcess, $m.WindowTitle } else { '' })
                    $markList.Add([pscustomobject]@{ Zeit = $m.Time.ToString('HH:mm:ss'); Fokus = $fgTxt; Kontext = @($recent.ToArray()) })
                    try { [Console]::Beep(880, 120) } catch {}
                }
            }

            $timeline.Add($row)
            $samples++

            $hangTxt = '-'
            if ($lag) { $hangTxt = [string]$lag.Over100 }
            $gpuTxt = $(if ($null -ne $gpu3d) { ('GPU {0,2:N0}% | ' -f $gpu3d) } else { '' })
            $line = ' {0,5}/{1} s | CPU {2,3:N0}% | {3}DPC max {4,4:N1}% | Disk {5,4:N0} ms | RAM frei {6,6:N0} MB | Haenger {7} | Markiert {8} ' -f `
                $i, $Seconds, $cpuNow, $gpuTxt, $dpcMax, $latMax, $availMb, $hangTxt, $markList.Count
            try { [Console]::Write("`r" + $line) } catch {}

            try {
                while ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)
                    if ($key.Key -eq [ConsoleKey]::Q) { $quit = $true; $res.EndedEarly = $true }
                    elseif ($key.Key -eq [ConsoleKey]::M) {
                        $m = [PerfDiagV1.LagMonitor]::CaptureForeground()
                        $fgTxt = $(if ($m.ForegroundProcess) { '{0} ({1})' -f $m.ForegroundProcess, $m.WindowTitle } else { 'Konsole' })
                        $markList.Add([pscustomobject]@{ Zeit = $m.Time.ToString('HH:mm:ss'); Fokus = $fgTxt; Kontext = @($recent.ToArray()) })
                        try { [Console]::Beep(880, 120) } catch {}
                    }
                }
            } catch {}
        }
    }
    finally {
        try { [Console]::WriteLine() } catch {}
        if ($lag) { try { $lag.Stop() } catch {} }
        if ($pdh) { try { $pdh.Dispose() } catch {} }
    }

    $res.SamplesTaken = $samples
    foreach ($k in $allKeys) {
        $st = Get-Stats $series[$k]
        if ($st) { $res.Counters[$k] = $st }
    }
    $res.Disks = @(foreach ($inst in ($diskAgg.Keys | Sort-Object)) {
            $a = $diskAgg[$inst]
            $l = Get-Stats $a.lat; $q = Get-Stats $a.queue; $b = Get-Stats $a.busy; $by = Get-Stats $a.mbs
            [pscustomobject]@{
                Instance = $inst
                LatAvgMs = (Get-Rounded $l.Avg 1); LatP95Ms = (Get-Rounded $l.P95 1); LatMaxMs = (Get-Rounded $l.Max 0)
                QueueAvg = (Get-Rounded $q.Avg 2); QueueMax = (Get-Rounded $q.Max 0)
                BusyAvgPct = (Get-Rounded $b.Avg 0); BusyP95Pct = (Get-Rounded $b.P95 0)
                MBsAvg = (Get-Rounded $by.Avg 2); MBsMax = (Get-Rounded $by.Max 1)
            }
        })
    $n = [math]::Max(1, $samples)
    $res.TopCpu = @($procCpuSum.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 25 | ForEach-Object {
            [pscustomobject]@{ Name = $_.Key; AvgPct = (Get-Rounded ($_.Value / $n) 1); MaxPct = (Get-Rounded $procCpuMax[$_.Key] 0) }
        })
    $res.TopIo = @($procIoSum.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15 | ForEach-Object {
            [pscustomobject]@{ Name = $_.Key; AvgMBs = (Get-Rounded ($_.Value / $n) 2); MaxMBs = (Get-Rounded $procIoMax[$_.Key] 1) }
        })
    if ($perfUnderLoad.Count -gt 0) { $res.CpuPerfUnderLoad = (Get-Rounded (Get-Stats $perfUnderLoad).Avg 0) }
    $res.LoadSeconds = $perfUnderLoad.Count
    $res.BadSeconds = $bad.ToArray()
    $res.BadSecondCounts = $badCounts
    $res.Marks = $markList.ToArray()
    if ($lag) {
        $res.Stalls = [pscustomobject]@{
            Iterations = $lag.Iterations; MaxGapMs = (Get-Rounded $lag.MaxGapMs 0)
            Over50 = $lag.Over50; Over100 = $lag.Over100; Over250 = $lag.Over250; Over1000 = $lag.Over1000
            TotalStallMs = (Get-Rounded $lag.TotalStallMs 0); GcSkipped = $lag.GcSkipped
            Events = @($stallList | Sort-Object Ms -Descending | Select-Object -First 25)
        }
    }
    return @{ Result = $res; Timeline = $timeline }
}
#endregion

#region ---------------------------------------------------------------- Collector: memory & processes
function Get-MemoryInfo {
    $m = [ordered]@{}
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $m.TotalGB = Get-Rounded ($os.TotalVisibleMemorySize / 1MB) 2
        $m.FreeGB = Get-Rounded ($os.FreePhysicalMemory / 1MB) 2
        $m.CommitLimitGB = Get-Rounded ($os.TotalVirtualMemorySize / 1MB) 2
        $m.CommitUsedGB = Get-Rounded (($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) / 1MB) 2
    } catch { Add-Err 'Arbeitsspeicher/OS' $_ }
    try { $m.AutoPagefile = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).AutomaticManagedPagefile } catch {}
    try {
        $m.PageFiles = @(Get-CimInstance Win32_PageFileUsage -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Path = $_.Name; SizeMB = $_.AllocatedBaseSize; CurrentMB = $_.CurrentUsage; PeakMB = $_.PeakUsage }
            })
    } catch { Add-Err 'Auslagerungsdatei' $_ }
    try {
        $m.Modules = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    Slot = $_.DeviceLocator; SizeGB = (Get-Rounded ($_.Capacity / 1GB) 0); SpeedMHz = $_.Speed
                    ConfiguredMHz = $_.ConfiguredClockSpeed; Manufacturer = ([string]$_.Manufacturer).Trim(); PartNumber = ([string]$_.PartNumber).Trim()
                }
            })
    } catch {}
    try { $mm = Get-MMAgent -ErrorAction Stop; $m.MemoryCompression = [bool]$mm.MemoryCompression } catch {}
    return $m
}

function Get-ProcessInfo {
    param($Sampling, [double]$TotalRamGB)
    $p = [ordered]@{}
    $procs = @(Get-Process -ErrorAction SilentlyContinue)
    $p.ProcessCount = $procs.Count
    $groups = @(foreach ($g in ($procs | Group-Object ProcessName)) {
            $priv = 0.0; $ws = 0.0; $h = 0; $th = 0
            foreach ($x in $g.Group) {
                $priv += [double]$x.PrivateMemorySize64
                $ws += [double]$x.WorkingSet64
                $h += [int]$x.HandleCount
                try { $th += $x.Threads.Count } catch {}
            }
            [pscustomobject]@{ Name = $g.Name; Instances = $g.Count; PrivateMB = (Get-Rounded ($priv / 1MB) 0); WorkingSetMB = (Get-Rounded ($ws / 1MB) 0); Handles = $h; Threads = $th }
        })
    $p.TopRam = @($groups | Sort-Object PrivateMB -Descending | Select-Object -First 15)
    $p.HighHandles = @($procs | Where-Object { $_.HandleCount -gt 10000 } | Sort-Object HandleCount -Descending | Select-Object -First 10 | ForEach-Object {
            [pscustomobject]@{ Name = $_.ProcessName; Id = $_.Id; Handles = $_.HandleCount; PrivateMB = (Get-Rounded ($_.PrivateMemorySize64 / 1MB) 0) }
        })
    $p.Browsers = @(foreach ($b in @('chrome', 'msedge', 'firefox', 'brave', 'opera', 'vivaldi')) {
            $g = $groups | Where-Object { $_.Name -eq $b } | Select-Object -First 1
            if (-not $g) { continue }
            $c = @($Sampling.TopCpu) | Where-Object { $_ -and $_.Name -eq $b } | Select-Object -First 1
            $io = @($Sampling.TopIo) | Where-Object { $_ -and $_.Name -eq $b } | Select-Object -First 1
            $share = $null
            if ($TotalRamGB -gt 0) { $share = Get-Rounded (100 * ($g.PrivateMB / 1024) / $TotalRamGB) 0 }
            [pscustomobject]@{
                Name = $b; Instances = $g.Instances; PrivateMB = $g.PrivateMB; RamSharePct = $share
                CpuAvgPct = $(if ($c) { $c.AvgPct } else { 0 }); CpuMaxPct = $(if ($c) { $c.MaxPct } else { 0 })
                IoAvgMBs = $(if ($io) { $io.AvgMBs } else { 0 })
            }
        })
    $ex = $groups | Where-Object { $_.Name -eq 'explorer' } | Select-Object -First 1
    if ($ex) { $p.Explorer = $ex }
    $p.Names = @($groups | ForEach-Object { $_.Name })
    return $p
}
#endregion

#region ---------------------------------------------------------------- Collector: disks
function Get-DiskInfo {
    param([bool]$IsAdmin)
    $d = [ordered]@{ Physical = @(); Reliability = @(); Volumes = @(); SystemDiskNumber = $null; TrimDisabled = $null }
    try {
        $sysLetter = $env:SystemDrive.TrimEnd(':')
        $d.SystemDiskNumber = [string]((Get-Partition -DriveLetter $sysLetter -ErrorAction Stop | Get-Disk -ErrorAction Stop).Number)
    } catch { Add-Err 'Systemlaufwerk ermitteln' $_ }

    $diskLetters = @{}
    try {
        foreach ($pt in @(Get-Partition -ErrorAction Stop | Where-Object { $_.DriveLetter })) {
            $dn = [string]$pt.DiskNumber
            $dl = ([string]$pt.DriveLetter) + ':'
            if (-not $diskLetters.ContainsKey($dn)) { $diskLetters[$dn] = New-Object System.Collections.Generic.List[string] }
            if (-not $diskLetters[$dn].Contains($dl)) { $diskLetters[$dn].Add($dl) }
        }
    } catch {}

    $pds = @()
    try {
        $pds = @(Get-PhysicalDisk -ErrorAction Stop | Sort-Object { [int]$_.DeviceId })
        $d.Physical = @($pds | ForEach-Object {
                $id = [string]$_.DeviceId
                $letters = $(if ($diskLetters.ContainsKey($id)) { ($diskLetters[$id] | Sort-Object) -join ', ' } else { '' })
                [pscustomobject]@{
                    DeviceId = $id; Drives = $letters; Name = $_.FriendlyName; MediaType = [string]$_.MediaType; BusType = [string]$_.BusType
                    Health = [string]$_.HealthStatus; Status = (@($_.OperationalStatus) -join ','); SizeGB = (Get-Rounded ($_.Size / 1GB) 0)
                    IsSystemDisk = ($id -eq $d.SystemDiskNumber)
                }
            })
    } catch { Add-Err 'Physische Laufwerke' $_ }
    $smartDenied = 0
    foreach ($pd in $pds) {
        try {
            $r = $pd | Get-StorageReliabilityCounter -ErrorAction Stop
            if ($r) {
                $d.Reliability += [pscustomobject]@{
                    DeviceId = [string]$pd.DeviceId; Name = $pd.FriendlyName
                    TemperatureC = $r.Temperature; TemperatureMaxC = $r.TemperatureMax; WearPct = $r.Wear
                    ReadErrorsUncorrected = $r.ReadErrorsUncorrected; WriteErrorsUncorrected = $r.WriteErrorsUncorrected
                    ReadErrorsTotal = $r.ReadErrorsTotal; PowerOnHours = $r.PowerOnHours
                }
            }
        } catch {
            if (-not $IsAdmin) { $smartDenied++ }
            else { Add-Err ('S.M.A.R.T. {0}' -f $pd.FriendlyName) $_ }
        }
    }
    if ($smartDenied -gt 0) {
        Add-Err 'S.M.A.R.T.-Werte' ('Benötigt Administratorrechte ({0} Laufwerke übersprungen)' -f $smartDenied)
    }
    try {
        $d.Volumes = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | ForEach-Object {
                $size = [double]$_.Size; $free = [double]$_.FreeSpace
                [pscustomobject]@{
                    Drive = $_.DeviceID; Label = $_.VolumeName; FileSystem = $_.FileSystem
                    SizeGB = (Get-Rounded ($size / 1GB) 1); FreeGB = (Get-Rounded ($free / 1GB) 1)
                    FreePct = $(if ($size -gt 0) { Get-Rounded (100 * $free / $size) 1 } else { $null })
                    IsSystem = ($_.DeviceID -eq $env:SystemDrive)
                }
            })
    } catch { Add-Err 'Partitionen' $_ }
    try {
        $t = (& fsutil.exe behavior query DisableDeleteNotify 2>$null) -join "`n"
        $m = [regex]::Match($t, '(?:NTFS\s+)?DisableDeleteNotify\s*=\s*(\d)')
        if ($m.Success) { $d.TrimDisabled = ($m.Groups[1].Value -eq '1') }
    } catch {}
    return $d
}
#endregion

#region ---------------------------------------------------------------- Collector: event logs
function Get-EventMeaning {
    param([string]$Provider, [int]$Id)
    foreach ($r in $script:EventRules) {
        if ($Provider -match $r.P -and ($r.Ids.Count -eq 0 -or $r.Ids -contains $Id)) { return $r }
    }
    return $null
}

function Get-EventInfo {
    param([int]$Days, [bool]$IsAdmin)
    $e = [ordered]@{ Days = $Days; SystemTotal = 0; SystemGroups = @(); AppHangs = @(); AppCrashes = @(); BootTimes = @(); BootDegraders = @() }
    $start = (Get-Date).AddDays(-$Days)

    $sys = @()
    try { $sys = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2, 3; StartTime = $start } -MaxEvents 5000 -ErrorAction Stop) }
    catch { if (-not (Test-NoEvents $_)) { Add-Err 'Ereignisprotokoll System' $_ } }
    $e.SystemTotal = $sys.Count
    $groups = @(foreach ($g in ($sys | Group-Object ProviderName, Id)) {
            $first = $g.Group[0]
            $rule = Get-EventMeaning $first.ProviderName $first.Id
            $msg = ''
            try { $msg = [string]$first.Message } catch {}
            $msg = ($msg -replace '\s+', ' ').Trim()
            if ($msg.Length -gt 220) { $msg = $msg.Substring(0, 220) + '...' }
            [pscustomobject]@{
                Provider = $first.ProviderName; Id = $first.Id; Level = [int]$first.Level; Hits = $g.Count
                Last = (Format-Date $first.TimeCreated)
                Tag = $(if ($rule) { $rule.Tag } else { '' })
                Meaning = $(if ($rule) { $rule.Text } else { '' })
                Sample = $msg
            }
        })
    $e.SystemGroups = @($groups | Sort-Object @{ Expression = { if ($_.Tag -and $_.Tag -ne 'noise') { 0 } else { 1 } } }, @{ Expression = 'Hits'; Descending = $true })

    try {
        $app = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000, 1002; StartTime = $start } -MaxEvents 3000 -ErrorAction Stop)
        $hang = @($app | Where-Object { $_.Id -eq 1002 })
        $crash = @($app | Where-Object { $_.Id -eq 1000 -and $_.ProviderName -eq 'Application Error' })
        $e.AppHangs = @($hang | Group-Object { [string]$_.Properties[0].Value } | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
                [pscustomobject]@{ App = $_.Name; Hits = $_.Count; Last = (Format-Date $_.Group[0].TimeCreated) }
            })
        $e.AppCrashes = @($crash | Group-Object { [string]$_.Properties[0].Value } | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
                $mods = (@($_.Group | ForEach-Object { [string]$_.Properties[3].Value } | Group-Object | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { $_.Name }) -join ', ')
                [pscustomobject]@{ App = $_.Name; Hits = $_.Count; Last = (Format-Date $_.Group[0].TimeCreated); Modules = $mods }
            })
    } catch { if (-not (Test-NoEvents $_)) { Add-Err 'Ereignisprotokoll Anwendung' $_ } }

    $diagLog = 'Microsoft-Windows-Diagnostics-Performance/Operational'
    try {
        $boot = @(Get-WinEvent -FilterHashtable @{ LogName = $diagLog; Id = 100 } -MaxEvents 10 -ErrorAction Stop)
        $e.BootTimes = @(foreach ($b in $boot) {
                $x = [xml]$b.ToXml()
                $bt = $null
                foreach ($n in $x.Event.EventData.Data) { if ($n.GetAttribute('Name') -eq 'BootTime') { $bt = $n.InnerText } }
                if ($bt) { [pscustomobject]@{ Datum = (Format-Date $b.TimeCreated 'yyyy-MM-dd'); Sekunden = (Get-Rounded ([double]$bt / 1000) 1) } }
            })
        $deg = @()
        try { $deg = @(Get-WinEvent -FilterHashtable @{ LogName = $diagLog; Id = 101, 102, 103, 106, 109 } -MaxEvents 80 -ErrorAction Stop) } catch {}
        $items = @(foreach ($b in $deg) {
                $x = [xml]$b.ToXml()
                $data = @{}
                foreach ($n in $x.Event.EventData.Data) { $data[$n.GetAttribute('Name')] = $n.InnerText }
                $name = @($data['FriendlyName'], $data['Name'], $data['FileName']) | Where-Object { $_ } | Select-Object -First 1
                $kind = switch ($b.Id) { 101 { 'Programm' } 102 { 'Treiber' } 103 { 'Dienst' } 106 { 'Hintergrund' } 109 { 'Gerät' } default { '' } }
                if ($name) { [pscustomobject]@{ Kind = $kind; Name = $name; DelayMs = [double]$data['DegradationTime'] } }
            })
        $e.BootDegraders = @($items | Group-Object Kind, Name | ForEach-Object {
                [pscustomobject]@{ Art = $_.Group[0].Kind; Name = $_.Group[0].Name; Hits = $_.Count; AvgDelayMs = (Get-Rounded ($_.Group | Measure-Object DelayMs -Average).Average 0) }
            } | Sort-Object AvgDelayMs -Descending | Select-Object -First 10)
    } catch {
        if (-not (Test-NoEvents $_) -and $IsAdmin) { Add-Err 'Boot-Diagnose' $_ }
    }
    return $e
}
#endregion

#region ---------------------------------------------------------------- Collector: explorer
function Get-ExplorerInfo {
    param([bool]$NativeOk, $ProcInfo)
    $x = [ordered]@{ NetworkDrives = @(); Folders = @(); WriteTest = $null; ContextMenuHandlers = @(); OverlayHandlers = @(); CloudSync = @(); SearchService = $null }

    # Netzlaufwerke (Registry des Benutzers + SMB + WMI) und Erreichbarkeit
    $drives = [ordered]@{}
    foreach ($k in @(Get-ChildItem 'HKCU:\Network' -ErrorAction SilentlyContinue)) {
        try {
            $letter = $k.PSChildName.ToUpper() + ':'
            $drives[$letter] = [pscustomobject]@{ Drive = $letter; Remote = [string]$k.GetValue('RemotePath'); Status = ''; Ms = $null }
        } catch {}
    }
    try {
        foreach ($sm in @(Get-SmbMapping -ErrorAction Stop)) {
            $letter = ([string]$sm.LocalPath).ToUpper()
            if (-not $letter) { continue }
            if (-not $drives.Contains($letter)) { $drives[$letter] = [pscustomobject]@{ Drive = $letter; Remote = [string]$sm.RemotePath; Status = ''; Ms = $null } }
            $drives[$letter].Status = 'SMB: ' + [string]$sm.Status
        }
    } catch {}
    try {
        foreach ($ld in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=4' -ErrorAction Stop)) {
            if (-not $drives.Contains($ld.DeviceID)) { $drives[$ld.DeviceID] = [pscustomobject]@{ Drive = $ld.DeviceID; Remote = [string]$ld.ProviderName; Status = ''; Ms = $null } }
        }
    } catch {}
    foreach ($dv in $drives.Values) {
        $dv | Add-Member -NotePropertyName Reachable -NotePropertyValue $null
        if ($NativeOk -and $dv.Remote) {
            $r = [PerfDiagV1.FsProbe]::TimedExists($dv.Remote, 4000)
            $dv.Reachable = [bool]$r[0]
            $dv.Ms = $r[1]
            $dv.Status = (@($dv.Status, $r[2]) | Where-Object { $_ }) -join ' / '
        }
    }
    $x.NetworkDrives = @($drives.Values)

    # Typische Ordner: Anzahl Eintraege und Zeit fuer das Auflisten
    $folders = [ordered]@{}
    try { $folders['Desktop'] = [Environment]::GetFolderPath('Desktop') } catch {}
    try { $folders['Dokumente'] = [Environment]::GetFolderPath('MyDocuments') } catch {}
    try { $folders['Bilder'] = [Environment]::GetFolderPath('MyPictures') } catch {}
    try {
        $dl = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -ErrorAction Stop).'{374DE290-123F-4565-9164-39C4925E467B}'
        if ($dl) { $folders['Downloads'] = [Environment]::ExpandEnvironmentVariables($dl) }
    } catch {}
    if ($NativeOk) {
        foreach ($k in $folders.Keys) {
            $path = $folders[$k]
            if (-not $path) { continue }
            $r = [PerfDiagV1.FsProbe]::TimedEnumerate($path, 15000)
            $x.Folders += [pscustomobject]@{ Name = $k; Path = $path; Entries = $r[0]; Ms = $r[1]; Status = $r[2]; OneDrive = ($path -match '(?i)onedrive') }
        }
        try {
            $w = [PerfDiagV1.FsProbe]::WriteLatency($env:TEMP, 20)
            $st = Get-Stats $w
            $x.WriteTest = [pscustomobject]@{ Folder = $env:TEMP; Files = 20; MedianMs = (Get-Rounded $st.P50 1); P95Ms = (Get-Rounded $st.P95 1); MaxMs = (Get-Rounded $st.Max 1) }
        } catch { Add-Err 'Schreibtest' $_ }
    }

    # Kontextmenue-Erweiterungen von Drittanbietern (klassische Bremse beim Rechtsklick/Explorer)
    $seen = @{}
    foreach ($root in @('*', 'AllFilesystemObjects', 'Directory', 'Directory\Background', 'Folder', 'Drive')) {
        $key = 'Registry::HKEY_CLASSES_ROOT\{0}\shellex\ContextMenuHandlers' -f $root
        foreach ($s in @(Get-ChildItem -LiteralPath $key -ErrorAction SilentlyContinue)) {
            try {
                $clsid = [string]$s.GetValue('')
                if ($clsid -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { $clsid = $s.PSChildName }
                if ($clsid -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { continue }
                if ($seen.ContainsKey($clsid)) { continue }
                $dll = $null
                try {
                    $ip = Get-Item -LiteralPath ('Registry::HKEY_CLASSES_ROOT\CLSID\{0}\InprocServer32' -f $clsid) -ErrorAction Stop
                    $dll = [string]$ip.GetValue('')
                } catch {}
                $path = Resolve-BinaryPath $dll
                $fi = $null
                if ($path) { $fi = Get-FileCompany $path }
                $seen[$clsid] = [pscustomobject]@{
                    Name = $s.PSChildName; Where = $root; Dll = $path
                    Company = $(if ($fi) { $fi.Company } else { '' })
                    Missing = [bool]($path -and $fi -and -not $fi.Exists)
                }
            } catch {}
        }
    }
    $x.ContextMenuHandlers = @($seen.Values | Where-Object { $_.Dll -and ($_.Missing -or -not (Test-Microsoft $_.Company)) } | Sort-Object Company, Name)

    try {
        $x.OverlayHandlers = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers' -ErrorAction Stop | ForEach-Object { $_.PSChildName.Trim() })
    } catch {}

    $names = @()
    if ($ProcInfo) { $names = @($ProcInfo.Names) }
    $x.CloudSync = @($script:CloudSync.Keys | Where-Object { $names -contains $_ } | ForEach-Object { $script:CloudSync[$_] } | Select-Object -Unique)
    try {
        $ws = Get-Service WSearch -ErrorAction Stop
        $x.SearchService = '{0} ({1})' -f $ws.Status, $ws.StartType
    } catch {}
    return $x
}
#endregion

#region ---------------------------------------------------------------- Collector: software & autostart
function Find-Autorunsc {
    param([string]$Hint)
    $cands = New-Object System.Collections.Generic.List[string]
    if ($Hint) {
        $cands.Add($Hint)
        $cands.Add((Join-Path $Hint 'autorunsc64.exe'))
        $cands.Add((Join-Path $Hint 'autorunsc.exe'))
    }
    foreach ($n in @('autorunsc64.exe', 'autorunsc.exe')) {
        $c = Get-Command $n -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { $cands.Add($c.Path) }
    }
    $dirs = @($PSScriptRoot, (Join-Path $env:USERPROFILE 'Downloads'), (Join-Path $env:USERPROFILE 'Downloads\Autoruns'),
        (Join-Path $env:USERPROFILE 'Downloads\SysinternalsSuite'), 'C:\Sysinternals', 'C:\SysinternalsSuite', 'C:\Tools',
        'C:\Tools\Sysinternals', (Join-Path $env:ProgramFiles 'Sysinternals'))
    foreach ($d in $dirs) {
        if (-not $d) { continue }
        foreach ($n in @('autorunsc64.exe', 'autorunsc.exe')) { $cands.Add((Join-Path $d $n)) }
    }
    foreach ($c in $cands) {
        if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { return $c }
    }
    return $null
}

function Invoke-Autoruns {
    param([string]$Hint, [string]$WorkDir)
    $r = [ordered]@{ Found = $false; Path = $null; Total = 0; Unsigned = @(); ByCategory = @(); Entries = @(); Note = '' }
    $exe = Find-Autorunsc $Hint
    if (-not $exe) {
        $r.Note = 'autorunsc nicht gefunden (optional: Sysinternals Autoruns herunterladen und autorunsc64.exe neben dieses Skript legen)'
        return $r
    }
    $r.Found = $true
    $r.Path = $exe
    $outF = Join-Path $WorkDir 'autoruns_roh.csv'
    $errF = Join-Path $WorkDir 'autoruns_fehler.txt'
    Write-Host '      autorunsc laeuft (Signaturpruefung, kann 1-3 Minuten dauern) ...' -ForegroundColor DarkGray
    $p = Start-Process -FilePath $exe -ArgumentList '-accepteula', '-nobanner', '-a', '*', '-c', '-m', '-s' -NoNewWindow -PassThru `
        -RedirectStandardOutput $outF -RedirectStandardError $errF
    if (-not $p.WaitForExit(300000)) {
        try { $p.Kill() } catch {}
        $r.Note = 'autorunsc: Zeitueberschreitung nach 5 Minuten'
        return $r
    }
    $bytes = [IO.File]::ReadAllBytes($outF)
    if ($bytes.Length -lt 10) { $r.Note = 'autorunsc lieferte keine Daten (Adminrechte?)'; return $r }
    if (($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) -or $bytes[1] -eq 0) { $text = [Text.Encoding]::Unicode.GetString($bytes) }
    else { $text = [Text.Encoding]::UTF8.GetString($bytes) }
    $text = $text.TrimStart([char]0xFEFF).Replace([string][char]0, '')
    $lines = @($text -split "`r?`n" | Where-Object { $_.Trim() -ne '' })
    $rows = @($lines | ConvertFrom-Csv)
    $enabled = @($rows | Where-Object { $_.Entry -and $_.Enabled -match '(?i)^enabled$' })
    $r.Total = $enabled.Count
    $r.ByCategory = @($enabled | Group-Object Category | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ Kategorie = $_.Name; Anzahl = $_.Count } })
    $r.Unsigned = @($enabled | Where-Object { $_.Signer -match '(?i)not verified' -or [string]::IsNullOrWhiteSpace($_.Signer) } | Select-Object -First 30 | ForEach-Object {
            [pscustomobject]@{ Kategorie = $_.Category; Eintrag = $_.Entry; Firma = $_.Company; Pfad = $_.'Image Path' }
        })
    $r.Entries = @($enabled | Where-Object { $_.Category -in @('Logon', 'Services', 'Scheduled Tasks', 'Explorer', 'Drivers') } | Select-Object -First 120 | ForEach-Object {
            [pscustomobject]@{ Kategorie = $_.Category; Eintrag = $_.Entry; Signatur = $_.Signer; Firma = $_.Company; Pfad = $_.'Image Path' }
        })
    return $r
}

function Get-SoftwareInfo {
    param([bool]$IsAdmin, [string]$AutorunsHint, [bool]$SkipAutoruns, [string]$WorkDir, $ProcInfo)
    $s = [ordered]@{ Antivirus = @(); Defender = $null; Startup = @(); StartupEnabledCount = 0; Autoruns = $null; ThirdPartyServices = @(); KnownTools = @(); Minifilters = @() }
    try {
        $s.Antivirus = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
                $state = [int]$_.productState
                $hex = '{0:X6}' -f $state
                $enabled = ((($state -shr 12) -band 0xF) -eq 1)
                [pscustomobject]@{ Name = $_.displayName; Enabled = $enabled; UpToDate = ($hex.Substring(4, 2) -eq '00') }
            })
    } catch {}
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $s.Defender = [pscustomobject]@{ Mode = [string]$mp.AMRunningMode; RealTime = [bool]$mp.RealTimeProtectionEnabled; AntivirusEnabled = [bool]$mp.AntivirusEnabled }
    } catch {}
    try {
        $fltOut = @(& fltmc.exe filters 2>$null)
        if ($fltOut.Count -gt 2) {
            foreach ($line in $fltOut) {
                if ($line -match '^\s*([A-Za-z0-9_.-]+)\s+(\d+)\s+(\d+(?:\.\d+)?)\s+\d+\s*$') {
                    $fn = $Matches[1]
                    $inst = [int]$Matches[2]
                    $alt = $Matches[3]
                    if ($inst -le 0) { continue }
                    $sysPath = Join-Path $env:SystemRoot ("System32\drivers\{0}.sys" -f $fn)
                    $fi = Get-FileCompany $sysPath
                    if ($fi -and $fi.Exists -and -not (Test-Microsoft $fi.Company)) {
                        $s.Minifilters += [pscustomobject]@{ Filter = $fn; Instanzen = $inst; Altitude = $alt; Firma = $fi.Company }
                    }
                }
            }
        }
        else {
            foreach ($sd in @(Get-CimInstance Win32_SystemDriver -Filter "State='Running'" -ErrorAction SilentlyContinue)) {
                $instKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$($sd.Name)\Instances"
                if (-not (Test-Path -LiteralPath $instKey)) { continue }
                $p = Resolve-BinaryPath $sd.PathName
                if (-not $p) { continue }
                $fi = Get-FileCompany $p
                if (-not ($fi -and $fi.Exists -and -not (Test-Microsoft $fi.Company))) { continue }
                $alt = ''
                $subKeys = @(Get-ChildItem -LiteralPath $instKey -ErrorAction SilentlyContinue)
                foreach ($sk in $subKeys) {
                    try {
                        $a = (Get-ItemProperty -LiteralPath $sk.PSPath -Name Altitude -ErrorAction SilentlyContinue).Altitude
                        if ($a) { $alt = [string]$a; break }
                    } catch {}
                }
                if ($alt) {
                    $s.Minifilters += [pscustomobject]@{ Filter = $sd.Name; Instanzen = $subKeys.Count; Altitude = $alt; Firma = $fi.Company }
                }
            }
        }
    } catch {}

    # Autostart (Run-Schluessel + Autostart-Ordner) inkl. "im Task-Manager deaktiviert"
    $disabled = @{}
    $base = 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
    foreach ($k in @("HKCU:\$base\Run", "HKCU:\$base\Run32", "HKCU:\$base\StartupFolder", "HKLM:\$base\Run", "HKLM:\$base\Run32", "HKLM:\$base\StartupFolder")) {
        try {
            $item = Get-Item -LiteralPath $k -ErrorAction Stop
            foreach ($n in $item.GetValueNames()) {
                $v = $item.GetValue($n)
                if ($v -is [byte[]] -and $v.Length -gt 0 -and ($v[0] % 2) -eq 1) { $disabled[$n] = $true }
            }
        } catch {}
    }
    try {
        $s.Startup = @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop | ForEach-Object {
                $dis = $disabled.ContainsKey([string]$_.Name) -or $disabled.ContainsKey([string]$_.Name + '.lnk') -or $disabled.ContainsKey([string]$_.Command)
                [pscustomobject]@{ Name = $_.Name; Befehl = $_.Command; Ort = $_.Location; Aktiv = (-not $dis) }
            })
        $s.StartupEnabledCount = @($s.Startup | Where-Object { $_.Aktiv }).Count
    } catch { Add-Err 'Autostart' $_ }

    if (-not $SkipAutoruns) {
        try { $s.Autoruns = Invoke-Autoruns -Hint $AutorunsHint -WorkDir $WorkDir } catch { Add-Err 'Autoruns' $_ }
    }

    $svcNames = @()
    try {
        $svcs = @(Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction Stop)
        $svcNames = @($svcs | ForEach-Object { $_.Name })
        $s.ThirdPartyServices = @(foreach ($sv in $svcs) {
                $path = Resolve-BinaryPath $sv.PathName
                if (-not $path) { continue }
                $fi = Get-FileCompany $path
                if ($fi -and $fi.Exists -and -not (Test-Microsoft $fi.Company)) {
                    [pscustomobject]@{ Name = $sv.Name; Anzeigename = $sv.DisplayName; Firma = $fi.Company }
                }
            })
    } catch { Add-Err 'Dienste' $_ }

    $names = @()
    if ($ProcInfo) { $names = @($ProcInfo.Names) }
    $all = @($names) + @($svcNames)
    $s.KnownTools = @(foreach ($t in $script:KnownTools) {
            $hit = @($all | Where-Object { $_ -match $t.P } | Select-Object -Unique)
            if ($hit.Count -gt 0) { [pscustomobject]@{ Name = $t.Name; Art = $t.Kind; Gefunden = ($hit -join ', ') } }
        })
    return $s
}
#endregion

#region ---------------------------------------------------------------- Collector: kernel pool tags
function Get-PoolInfo {
    $r = [ordered]@{ TopNonPaged = @(); TopPaged = @() }
    $raw = [PerfDiagV1.PoolTags]::Query()
    if (-not $raw -or $raw.Count -eq 0) { return $null }
    $rows = @(foreach ($x in $raw) {
            [pscustomobject]@{ Tag = [string]$x[0]; PagedMB = [math]::Round([double]$x[1] / 1MB, 1); NonPagedMB = [math]::Round([double]$x[2] / 1MB, 1); PagedOffen = $x[3]; NonPagedOffen = $x[4] }
        })
    $topN = @($rows | Sort-Object NonPagedMB -Descending | Select-Object -First 12)
    $topP = @($rows | Sort-Object PagedMB -Descending | Select-Object -First 12)
    $tags = @(@($topN + $topP) | ForEach-Object { $_.Tag } | Select-Object -Unique)
    $knownWinTags = @{
        'ConT' = 'ntoskrnl.exe (Contiguous Memory, Microsoft)'
        'EtwB' = 'ntoskrnl.exe (ETW-Puffer, Microsoft)'
        'File' = 'ntoskrnl.exe (Datei-Objekte, Microsoft)'
        'Thre' = 'ntoskrnl.exe (Thread-Objekte, Microsoft)'
        'MmCa' = 'ntoskrnl.exe (Memory Manager Cache, Microsoft)'
        'MmSt' = 'ntoskrnl.exe (Memory Manager Section, Microsoft)'
        'MmRe' = 'ntoskrnl.exe (Memory Manager, Microsoft)'
        'CM16' = 'ntoskrnl.exe (Registry-Cache, Microsoft)'
        'Toke' = 'ntoskrnl.exe (Zugriffstoken, Microsoft)'
        'FMsl' = 'fltmgr.sys (Filter-Manager StreamList, Microsoft)'
        'FMfn' = 'fltmgr.sys (Filter-Manager Dateinamen, Microsoft)'
        'FIcs' = 'fltmgr.sys (Filter-Manager Kontext, Microsoft)'
        'VoSm' = 'volsnap.sys (Schattenkopien-Bitmap, Microsoft)'
    }
    $map = @{}
    if ($tags.Count -gt 0) {
        Write-Host '      Ordne Speicher-Tags den Treiberdateien zu ...' -ForegroundColor DarkGray
        try {
            $drvFiles = New-Object System.Collections.Generic.List[string]
            try {
                foreach ($sd in @(Get-CimInstance Win32_SystemDriver -Filter "State='Running'" -ErrorAction SilentlyContinue)) {
                    $p = Resolve-BinaryPath $sd.PathName
                    if ($p -and (Test-Path -LiteralPath $p -PathType Leaf)) { $drvFiles.Add($p) }
                }
            } catch {}
            $sysDrvDir = Join-Path $env:SystemRoot 'System32\drivers'
            if (Test-Path -LiteralPath $sysDrvDir) {
                foreach ($f in [IO.Directory]::GetFiles($sysDrvDir, '*.sys')) { $drvFiles.Add($f) }
            }
            $found = [PerfDiagV1.PoolTags]::FindInDrivers([string[]]$tags, $drvFiles.ToArray())
            foreach ($t in $tags) {
                $tTrim = $t.Trim()
                if ($knownWinTags.ContainsKey($t) -or $knownWinTags.ContainsKey($tTrim)) {
                    $wTxt = $(if ($knownWinTags.ContainsKey($t)) { $knownWinTags[$t] } else { $knownWinTags[$tTrim] })
                    $map[$t] = [pscustomobject]@{ Text = $wTxt; ThirdParty = $false }
                    continue
                }
                $cands = @(foreach ($f in $found[$t]) {
                        $fi = Get-FileCompany $f
                        $co = ''
                        if ($fi) { $co = $fi.Company }
                        [pscustomobject]@{ File = (Split-Path $f -Leaf); Company = $co; Ms = (Test-Microsoft $co) }
                    })
                $third = @($cands | Where-Object { -not $_.Ms })
                $txt = ''
                if ($third.Count -gt 0 -and $third.Count -le 6) { $txt = (@($third | Select-Object -First 4 | ForEach-Object { '{0} ({1})' -f $_.File, $_.Company }) -join ', ') }
                elseif ($cands.Count -gt 0 -and $cands.Count -le 4) { $txt = (@($cands | ForEach-Object { '{0} (Microsoft)' -f $_.File }) -join ', ') }
                elseif ($cands.Count -gt 0) { $txt = ('unspezifisch ({0} Treiber enthalten den Tag)' -f $cands.Count) }
                $map[$t] = [pscustomobject]@{ Text = $txt; ThirdParty = ($third.Count -gt 0 -and $third.Count -le 6) }
            }
        } catch { Add-Err 'Pool-Tag-Zuordnung' $_ }
    }
    foreach ($row in ($topN + $topP)) {
        if ($row.psobject.Properties['Treiber']) { continue }
        $m = $map[$row.Tag]
        $txt = ''; $tp = $false
        if ($m) { $txt = $m.Text; $tp = [bool]$m.ThirdParty }
        $row | Add-Member -NotePropertyName Treiber -NotePropertyValue $txt
        $row | Add-Member -NotePropertyName Drittanbieter -NotePropertyValue $tp
    }
    $r.TopNonPaged = $topN
    $r.TopPaged = $topP
    $r.TotalNonPagedMB = [math]::Round((($rows | Measure-Object NonPagedMB -Sum).Sum), 0)
    $r.TotalPagedMB = [math]::Round((($rows | Measure-Object PagedMB -Sum).Sum), 0)
    return $r
}
#endregion

#region ---------------------------------------------------------------- Collector: drivers & input
function Get-DriverInfo {
    $d = [ordered]@{ Devices = @(); ProblemDevices = @(); ThirdPartyKernel = @(); NetAdapters = @() }
    try {
        $q = "SELECT DeviceName, DeviceClass, DriverProviderName, DriverVersion, DriverDate FROM Win32_PnPSignedDriver WHERE " +
        "DeviceClass='NET' OR DeviceClass='DISPLAY' OR DeviceClass='MEDIA' OR DeviceClass='SCSIADAPTER' OR DeviceClass='HDC' OR DeviceClass='BLUETOOTH' OR DeviceClass='USB'"
        $d.Devices = @(Get-CimInstance -Query $q -ErrorAction Stop | Where-Object { $_.DeviceName } | ForEach-Object {
                [pscustomobject]@{ Klasse = $_.DeviceClass; Gerät = $_.DeviceName; Anbieter = $_.DriverProviderName; Version = $_.DriverVersion; Datum = (Format-Date $_.DriverDate 'yyyy-MM-dd') }
            } | Sort-Object Klasse, Gerät, Version -Unique)
    } catch { Add-Err 'Treiberliste' $_ }
    try {
        $d.ProblemDevices = @(Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0' -ErrorAction Stop | Where-Object { $_.ConfigManagerErrorCode -ne 45 } | ForEach-Object {
                [pscustomobject]@{ Name = $_.Name; Klasse = $_.PNPClass; Fehlercode = $_.ConfigManagerErrorCode }
            })
    } catch { Add-Err 'Geraete mit Problemen' $_ }
    try {
        $d.ThirdPartyKernel = @(Get-CimInstance Win32_SystemDriver -Filter "State='Running'" -ErrorAction Stop | ForEach-Object {
                $path = Resolve-BinaryPath $_.PathName
                $fi = $null
                if ($path) { $fi = Get-FileCompany $path }
                if ($fi -and $fi.Exists -and -not (Test-Microsoft $fi.Company)) {
                    [pscustomobject]@{ Name = $_.Name; Beschreibung = $_.Description; Firma = $fi.Company; Datei = (Split-Path $path -Leaf); Dateidatum = $fi.Date }
                }
            } | Sort-Object Firma, Name)
    } catch { Add-Err 'Kernel-Treiber' $_ }
    try {
        $d.NetAdapters = @(Get-NetAdapter -Physical -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ Name = $_.Name; Adapter = $_.InterfaceDescription; Status = [string]$_.Status; Tempo = $_.LinkSpeed; Anbieter = $_.DriverProvider; Version = $_.DriverVersionString; Datum = $_.DriverDate }
            })
    } catch {}
    return $d
}

function Get-InputInfo {
    $i = [ordered]@{}
    try {
        $kr = Get-ItemProperty 'HKCU:\Control Panel\Accessibility\Keyboard Response' -ErrorAction Stop
        $flags = [int]$kr.Flags
        $i.FilterKeysOn = (($flags -band 1) -eq 1)
        $i.FilterKeysFlags = $flags
        $i.FilterDelayMs = $kr.DelayBeforeAcceptance
        $i.FilterBounceMs = $kr.BounceTime
    } catch {}
    try { $i.StickyKeysOn = (([int](Get-ItemProperty 'HKCU:\Control Panel\Accessibility\StickyKeys' -ErrorAction Stop).Flags -band 1) -eq 1) } catch {}
    try { $i.ToggleKeysOn = (([int](Get-ItemProperty 'HKCU:\Control Panel\Accessibility\ToggleKeys' -ErrorAction Stop).Flags -band 1) -eq 1) } catch {}
    try {
        $kb = Get-ItemProperty 'HKCU:\Control Panel\Keyboard' -ErrorAction Stop
        $i.KeyboardDelay = [int]$kb.KeyboardDelay
        $i.KeyboardSpeed = [int]$kb.KeyboardSpeed
    } catch {}
    try { $i.Languages = @(Get-WinUserLanguageList -ErrorAction Stop | ForEach-Object { $_.LanguageTag }) } catch {}
    return $i
}
#endregion

#region ---------------------------------------------------------------- Optional: WPR trace
function Start-WprTrace {
    param([bool]$IsAdmin)
    if (-not $IsAdmin) { Add-Err 'WPR-Trace' 'Benoetigt Administratorrechte - uebersprungen'; return $false }
    $wpr = Join-Path $env:SystemRoot 'System32\wpr.exe'
    if (-not (Test-Path $wpr)) { Add-Err 'WPR-Trace' 'wpr.exe nicht gefunden'; return $false }
    & $wpr -cancel 2>&1 | Out-Null
    $o = & $wpr -start CPU -start DiskIO -filemode 2>&1
    if ($LASTEXITCODE -ne 0) { Add-Err 'WPR-Start' ($o -join ' '); return $false }
    return $true
}

function Stop-WprTrace {
    param([string]$OutDir)
    $res = [ordered]@{ Etl = $null; DpcIsrFile = $null; DpcIsrExcerpt = '' }
    $wpr = Join-Path $env:SystemRoot 'System32\wpr.exe'
    $etl = Join-Path $OutDir 'trace.etl'
    Write-Host '      WPR-Aufzeichnung wird gespeichert ...' -ForegroundColor DarkGray
    $o = & $wpr -stop $etl 2>&1
    if ($LASTEXITCODE -ne 0) { Add-Err 'WPR-Stop' ($o -join ' '); return $res }
    $res.Etl = $etl
    $xp = $null
    $c = Get-Command xperf.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { $xp = $c.Path }
    foreach ($cand in @((Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Windows Performance Toolkit\xperf.exe'), (Join-Path $env:ProgramFiles 'Windows Kits\10\Windows Performance Toolkit\xperf.exe'))) {
        if (-not $xp -and $cand -and (Test-Path $cand)) { $xp = $cand }
    }
    if ($xp) {
        $txt = Join-Path $OutDir 'dpcisr.txt'
        & $xp -i $etl -o $txt -a dpcisr 2>&1 | Out-Null
        if (Test-Path $txt) {
            $res.DpcIsrFile = $txt
            $res.DpcIsrExcerpt = (@(Get-Content $txt -TotalCount 160) -join "`n")
        }
    }
    return $res
}
#endregion

#region ---------------------------------------------------------------- Analyzer
function Add-Finding {
    param([string]$Category, [int]$Severity, [int]$Score, [string]$Title, [string]$Detail = '', [string]$Recommendation = '')
    $script:Findings.Add([pscustomobject]@{
            Category = $Category; Severity = $Severity; Score = $Score
            Title = $Title; Detail = $Detail; Recommendation = $Recommendation
        })
}

function Format-Top {
    param($List, [string]$Prop, [string]$Unit, [int]$N = 3, [double]$Min = 0)
    $items = @(@($List) | Where-Object { $_ -and [double]$_.$Prop -ge $Min } | Select-Object -First $N)
    if ($items.Count -eq 0) { return 'keine auffälligen Prozesse' }
    return (@($items | ForEach-Object { '{0} ({1:N1}{2})' -f $_.Name, [double]$_.$Prop, $Unit }) -join ', ')
}

function Get-TagHits {
    param($Groups, [string]$Tag)
    $sum = 0
    foreach ($g in @($Groups)) { if ($g -and $g.Tag -eq $Tag) { $sum += [int]$g.Hits } }
    return $sum
}

function Get-TagText {
    param($Groups, [string]$Tag)
    return (@(@($Groups) | Where-Object { $_ -and $_.Tag -eq $Tag } | ForEach-Object { '{0} ID {1}: {2}x, zuletzt {3}' -f $_.Provider, $_.Id, $_.Hits, $_.Last }) -join '; ')
}

function Invoke-Analysis {
    param($D)
    $script:Findings.Clear()
    $S = $D.Sampling
    $C = $null
    if ($S) { $C = $S.Counters }
    $live = [bool]($S -and $S.Available -and $C)
    $sys = $D.System
    $mem = $D.Memory
    $ramGB = [double]$mem.TotalGB
    if ($ramGB -le 0) { $ramGB = [double]$sys.RamTotalGB }
    $ev = @()
    if ($D.Events) { $ev = @($D.Events.SystemGroups) }
    $kernelDrv = @()
    if ($D.Drivers) { $kernelDrv = @(@($D.Drivers.ThirdPartyKernel) | Where-Object { $_ }) }
    $drvHint = ''
    if ($kernelDrv.Count -gt 0) {
        $drvHint = ' Aktive Nicht-Microsoft-Treiber u. a.: ' + ((@($kernelDrv | Select-Object -First 12 | ForEach-Object { '{0} ({1})' -f $_.Datei, $_.Firma })) -join ', ') + '.'
    }

    # ---------------- CPU
    if ($live -and $C.cpu_total) {
        $avg = [double]$C.cpu_total.Avg
        $p95 = [double]$C.cpu_total.P95
        $tops = Format-Top $S.TopCpu 'AvgPct' ' %' 3 1
        if ($avg -ge 80) {
            Add-Finding 'CPU' 3 85 ('Prozessor dauerhaft ausgelastet (Ø {0:N0} %)' -f $avg) ('Hauptverursacher: {0}' -f $tops) `
                'Verursachenden Prozess prüfen/beenden. Browser: Tabs und Erweiterungen reduzieren (Chrome-Task-Manager: Umschalt+Esc). Unbekannte Dauerlast: auf Malware/Miner prüfen.'
        }
        elseif ($avg -ge 50) {
            Add-Finding 'CPU' 2 60 ('Hohe CPU-Grundlast (Ø {0:N0} %)' -f $avg) ('Hauptverursacher: {0}' -f $tops) `
                'Hintergrundprogramme der Liste prüfen und unnötige beenden bzw. aus dem Autostart nehmen.'
        }
        elseif ($p95 -ge 95) {
            Add-Finding 'CPU' 2 45 ('Kurze CPU-Lastspitzen bis 100 % (P95 {0:N0} %)' -f $p95) ('Zeitweise Verursacher: {0}' -f $tops) `
                'Spitzen sind normal bei Programmstarts. Wenn sie mit den Hängern zusammenfallen, siehe "Kritische Sekunden" im Anhang.'
        }
        else {
            Add-Finding 'CPU' 0 5 ('CPU-Auslastung unauffällig (Ø {0:N0} %, P95 {1:N0} %)' -f $avg, $p95) ('Größte Verbraucher: {0}' -f $tops) ''
        }
        if ($C.cpu_priv -and $avg -ge 15) {
            $ratio = [double]$C.cpu_priv.Avg / $avg
            if ($ratio -ge 0.5) {
                $fltHint = ''
                if ($D.Software -and (Get-Count $D.Software.Minifilters) -gt 0) {
                    $fltHint = ' Aktive Dateisystem-Minifilter (Drittanbieter): ' + ((@($D.Software.Minifilters | ForEach-Object { '{0} ({1})' -f $_.Filter, $_.Firma })) -join ', ') + '.'
                }
                Add-Finding 'CPU' 2 55 ('Hoher Kernel-Anteil an der CPU-Zeit ({0:N0} %)' -f (100 * $ratio)) `
                    ('Mehr als die Hälfte der Rechenzeit läuft im Kernel (Treiber, Virenscanner, Dateisystem-Filter) statt in Programmen.' + $fltHint) `
                    'Virenscanner-Last, Dateisystem-Filter und Treiber prüfen (siehe Kategorie "Treiber & Latenz"). Drittanbieter-Sicherheitssoftware testweise deinstallieren.'
            }
        }
        $lp = [int]$sys.LogicalProcessors
        if ($lp -gt 0 -and $C.run_queue -and $avg -ge 60 -and ([double]$C.run_queue.Avg / $lp) -ge 2) {
            Add-Finding 'CPU' 2 50 ('Lange Warteschlange für die CPU (Ø {0:N1} Threads pro Kern)' -f ([double]$C.run_queue.Avg / $lp)) `
                'Mehr Threads wollen rechnen als Kerne frei sind - Eingaben müssen warten.' 'Hauptverursacher (siehe CPU-Liste) reduzieren.'
        }
    }

    # ---------------- Treiber & Latenz
    if ($live) {
        $dpcAvg = [double]$C.cpu_dpc.Avg
        $intAvg = [double]$C.cpu_int.Avg
        $dpcCoreP95 = $(if ($C.core_dpc_max) { [double]$C.core_dpc_max.P95 } else { 0 })
        $dpcCoreMax = $(if ($C.core_dpc_max) { [double]$C.core_dpc_max.Max } else { 0 })
        $intCoreP95 = $(if ($C.core_int_max) { [double]$C.core_int_max.P95 } else { 0 })
        $intCoreMax = $(if ($C.core_int_max) { [double]$C.core_int_max.Max } else { 0 })
        $recDpc = 'Ursache ist fast immer ein Treiber. LatencyMon (resplendence.com, kostenlos) 5-10 Minuten laufen lassen und im Reiter "Drivers" nach "Highest execution" sortieren. ' +
        'Typische Verursacher: WLAN/LAN (Netwtw*, rt*, Killer), Audio (Realtek, Nahimic), Grafik (nvlddmkm, amdkmdag), ACPI.sys/Akku bei Laptops, USB-Geräte/Hubs. ' +
        'Treiber direkt vom Hersteller aktualisieren (nicht nur Windows Update), testweise WLAN/Bluetooth im Geräte-Manager deaktivieren, BIOS und Chipsatztreiber aktualisieren.'
        if ($dpcAvg -ge 5 -or $dpcCoreP95 -ge 30) {
            Add-Finding 'Treiber & Latenz' 3 90 ('Sehr hohe DPC-Last durch Treiber (Ø {0:N1} %, ein Kern bis {1:N0} %)' -f $dpcAvg, $dpcCoreMax) `
                ('DPCs sind Treiber-Routinen mit Vorrang vor allem anderen - auch vor Tastatur und Maus.' + $drvHint) $recDpc
        }
        elseif ($dpcAvg -ge 2 -or $dpcCoreP95 -ge 10) {
            Add-Finding 'Treiber & Latenz' 2 70 ('Erhöhte DPC-Last durch Treiber (Ø {0:N1} %, ein Kern bis {1:N0} %)' -f $dpcAvg, $dpcCoreMax) `
                ('Treiber blockieren zeitweise einzelne Kerne.' + $drvHint) $recDpc
        }
        if ($intAvg -ge 5 -or $intCoreP95 -ge 30) {
            Add-Finding 'Treiber & Latenz' 3 85 ('Sehr hohe Interrupt-Last (Ø {0:N1} %, ein Kern bis {1:N0} %)' -f $intAvg, $intCoreMax) `
                'Hardware unterbricht die CPU extrem oft - typisch für defekte/fehlerhafte Geräte, USB-Probleme oder korrigierte PCIe-Fehler (WHEA).' `
                'USB-Geräte nacheinander abstecken und Wirkung prüfen; Ereignisse "WHEA-Logger" beachten; BIOS/Chipsatz aktualisieren.'
        }
        elseif ($intAvg -ge 2 -or $intCoreP95 -ge 10) {
            Add-Finding 'Treiber & Latenz' 2 60 ('Erhöhte Interrupt-Last (Ø {0:N1} %, ein Kern bis {1:N0} %)' -f $intAvg, $intCoreMax) `
                'Ein Gerät oder Treiber erzeugt viele Hardware-Unterbrechungen.' 'USB-Geräte/Hubs testweise abstecken, Treiber aktualisieren.'
        }
        if ($C.int_rate -and [double]$C.int_rate.Avg -ge 40000) {
            Add-Finding 'Treiber & Latenz' 2 45 ('Sehr viele Hardware-Interrupts ({0:N0} pro Sekunde)' -f [double]$C.int_rate.Avg) '' 'Wie oben: Geräte/Treiber prüfen.'
        }
        $st = $S.Stalls
        if ($st) {
            $longest = [double]$st.MaxGapMs
            $detail = ('In {0} s gemessen: {1}x ≥ 100 ms, {2}x ≥ 250 ms, {3}x ≥ 1 s; längster Aussetzer {4:N0} ms. Der Messthread hat hohe Priorität - ein Aussetzer heißt: das ganze System hat nicht reagiert.' -f `
                    $S.SamplesTaken, $st.Over100, $st.Over250, $st.Over1000, $longest)
            $hangRec = 'Wenn gleichzeitig DPC/Interrupts hoch sind: Treiber (siehe oben). Wenn nicht: BIOS- und Chipsatz-Update, Energiesparplan "Ausbalanciert/Höchstleistung", ' +
            'im BIOS testweise C-States/ASPM ändern, Hersteller-Tools (RGB, Tuning, Audio-Effekte) deinstallieren. Zeitpunkte siehe Anhang "Haenger".'
            if ($st.Over1000 -gt 0 -or $st.Over250 -ge 3) {
                Add-Finding 'Treiber & Latenz' 3 92 ('Das System friert regelmäßig ein (längster Hänger {0:N0} ms)' -f $longest) $detail $hangRec
            }
            elseif ($st.Over250 -ge 1 -or $st.Over100 -ge 5) {
                Add-Finding 'Treiber & Latenz' 2 75 ('Spürbare System-Hänger gemessen ({0}x ≥ 100 ms)' -f $st.Over100) $detail $hangRec
            }
            elseif ($st.Over50 -ge 10) {
                Add-Finding 'Treiber & Latenz' 2 45 ('Gelegentliche Mikro-Hänger ({0}x ≥ 50 ms)' -f $st.Over50) $detail $hangRec
            }
            else {
                Add-Finding 'Treiber & Latenz' 0 5 ('Keine System-Hänger gemessen (längster Aussetzer {0:N0} ms)' -f $longest) 'Während der Messung lief das System ohne Aussetzer.' ''
            }
        }
        if ($dpcAvg -lt 2 -and $dpcCoreP95 -lt 10 -and $intAvg -lt 2 -and $intCoreP95 -lt 10) {
            Add-Finding 'Treiber & Latenz' 0 5 ('DPC-/Interrupt-Last unauffällig (DPC Ø {0:N1} %, Interrupts Ø {1:N1} %)' -f $dpcAvg, $intAvg) '' ''
        }
    }

    # ---------------- Arbeitsspeicher
    $availGB = $null
    if ($live -and $C.mem_avail_mb) { $availGB = [double]$C.mem_avail_mb.Avg / 1024 }
    elseif ($mem.FreeGB) { $availGB = [double]$mem.FreeGB }
    $ramTop = ''
    if ($D.Processes) { $ramTop = Format-Top $D.Processes.TopRam 'PrivateMB' ' MB' 4 }
    if ($null -ne $availGB -and $ramGB -gt 0) {
        $pct = 100 * $availGB / $ramGB
        if ($pct -lt 10 -or $availGB -lt 1) {
            Add-Finding 'Arbeitsspeicher' 3 85 ('Arbeitsspeicher fast voll (nur {0:N1} GB von {1:N0} GB frei)' -f $availGB, $ramGB) ('Größte Verbraucher: {0}' -f $ramTop) `
                'Große Verbraucher schließen; dauerhaft: RAM aufrüsten. Bei Browsern: Tabs schließen oder "Memory Saver"/Energiesparmodus für Tabs aktivieren.'
        }
        elseif ($pct -lt 20) {
            Add-Finding 'Arbeitsspeicher' 2 60 ('Arbeitsspeicher knapp ({0:N1} GB von {1:N0} GB frei)' -f $availGB, $ramGB) ('Größte Verbraucher: {0}' -f $ramTop) `
                'Große Verbraucher reduzieren; bei regelmäßiger Knappheit RAM aufrüsten.'
        }
        else {
            Add-Finding 'Arbeitsspeicher' 0 5 ('Genug freier Arbeitsspeicher (Ø {0:N1} GB von {1:N0} GB frei)' -f $availGB, $ramGB) ('Größte Verbraucher: {0}' -f $ramTop) ''
        }
    }
    if ($live -and $C.mem_commit_pct) {
        $cm = [double]$C.mem_commit_pct.Max
        if ($cm -ge 90) { Add-Finding 'Arbeitsspeicher' 3 75 ('Zugesicherter Speicher am Limit ({0:N0} %)' -f $cm) 'RAM + Auslagerungsdatei sind fast komplett vergeben. Programme können abstürzen oder einfrieren.' 'Auslagerungsdatei auf "automatisch verwalten" stellen, Verbraucher schließen, RAM aufrüsten.' }
        elseif ($cm -ge 80) { Add-Finding 'Arbeitsspeicher' 2 50 ('Zugesicherter Speicher hoch ({0:N0} %)' -f $cm) '' 'Auslagerungsdatei automatisch verwalten lassen; Verbraucher reduzieren.' }
    }
    if ($live -and $C.mem_pages_in) {
        $pin = [double]$C.mem_pages_in.Avg
        $pin95 = [double]$C.mem_pages_in.P95
        $ramPlenty = ($null -ne $availGB -and $availGB -ge 3 -and ($ramGB -le 0 -or (100 * $availGB / $ramGB) -ge 25))
        if ($ramPlenty) {
            if ($pin -ge 200) {
                Add-Finding 'Arbeitsspeicher' 1 20 ('Hohe Seiten-Laderate trotz freiem RAM (' + [char]0x00D8 + ' {0:N0} Seiten/s)' -f $pin) ('Kein RAM-Mangel: Windows l' + [char]0x00E4 + 'dt hier Programmcode oder speicherabgebildete Dateien (Memory-Mapped Files, z. B. beim Programmstart, Indexer oder IDE) von der Platte nach.') ''
            }
        }
        else {
            if ($pin -ge 200) { Add-Finding 'Arbeitsspeicher' 3 80 ('Starkes Auslagern auf die Festplatte (' + [char]0x00D8 + ' {0:N0} Seiten/s)' -f $pin) ('Windows muss st' + [char]0x00E4 + 'ndig Speicher von der Platte nachladen - das f' + [char]0x00FC + 'hlt sich wie H' + [char]0x00E4 + 'nger an, vor allem mit HDD.') ('RAM-Verbrauch senken oder RAM aufr' + [char]0x00FC + 'sten.') }
            elseif ($pin -ge 50 -or $pin95 -ge 1000) { Add-Finding 'Arbeitsspeicher' 2 55 ('Zeitweise starkes Nachladen von der Platte (' + [char]0x00D8 + ' {0:N0}, Spitzen {1:N0} Seiten/s)' -f $pin, $pin95) 'Kann auch von Programmstarts kommen; dauerhaft hohe Werte deuten auf RAM-Mangel.' 'RAM-Verbrauch beobachten.' }
        }
    }
    if ($live -and $C.mem_npp_mb) {
        $npp = [double]$C.mem_npp_mb.Max
        $nppPoolHint = ''
        if ($D.Pool -and (Get-Count $D.Pool.TopNonPaged) -gt 0) {
            $nppPoolHint = ' Größte Non-Paged-Tags: ' + ((@($D.Pool.TopNonPaged | Select-Object -First 4 | ForEach-Object { '{0} ({1:N0} MB{2})' -f $_.Tag.Trim(), $_.NonPagedMB, $(if ($_.Treiber) { ', ' + $_.Treiber } else { '' }) })) -join ', ') + '.'
        }
        if ($npp -ge 2048) { Add-Finding 'Arbeitsspeicher' 3 75 ('Verdacht auf Treiber-Speicherleck (Non-Paged Pool {0:N0} MB)' -f $npp) ('Normal sind 200-800 MB. Ein Treiber belegt immer mehr Kernel-Speicher.' + $nppPoolHint + $drvHint) 'Siehe Tabelle "Kernel-Speicher je Pool-Tag" im Anhang; zugehörige Netzwerk-, VPN-, Hypervisor- oder Virenscanner-Treiber aktualisieren. Neustart schafft vorübergehend Abhilfe.' }
        elseif ($npp -ge 1024) { Add-Finding 'Arbeitsspeicher' 2 45 ('Non-Paged Pool erhöht ({0:N0} MB)' -f $npp) ('Kann auf ein Treiber-Speicherleck hindeuten, vor allem wenn der Wert mit der Laufzeit wächst.' + $nppPoolHint) 'Nach einigen Tagen Laufzeit erneut messen; Treiber aktualisieren.' }
    }
    if ($live -and $C.mem_pp_mb -and [double]$C.mem_pp_mb.Max -ge 4096) {
        $ppPoolHint = ''
        if ($D.Pool -and (Get-Count $D.Pool.TopPaged) -gt 0) {
            $ppPoolHint = ' Größte Paged-Tags: ' + ((@($D.Pool.TopPaged | Select-Object -First 4 | ForEach-Object { '{0} ({1:N0} MB{2})' -f $_.Tag.Trim(), $_.PagedMB, $(if ($_.Treiber) { ', ' + $_.Treiber } else { '' }) })) -join ', ') + '.'
        }
        Add-Finding 'Arbeitsspeicher' 2 40 ('Paged Pool sehr groß ({0:N0} MB)' -f [double]$C.mem_pp_mb.Max) ('Mögliches Leck in Treiber oder Dateisystem-/Registry-lastigen Programmen.' + $ppPoolHint) 'Neustart und Beobachtung; siehe Tabelle "Kernel-Speicher je Pool-Tag".'
    }
    if ($ramGB -gt 0 -and $ramGB -lt 7.5) {
        Add-Finding 'Arbeitsspeicher' 2 55 ('Wenig RAM installiert ({0:N0} GB)' -f $ramGB) 'Mit Windows 11 + Browser sind 8 GB das Minimum, 16 GB angenehm.' 'RAM aufrüsten, falls möglich.'
    }
    if ($null -ne $mem.PageFiles -and (Get-Count $mem.PageFiles) -eq 0) {
        Add-Finding 'Arbeitsspeicher' 2 40 'Keine Auslagerungsdatei aktiv' 'Ohne Auslagerungsdatei gibt es weniger zusicherbaren Speicher; manche Programme verhalten sich dann schlecht.' 'Systemsteuerung > System > Erweitert > Leistung > Virtueller Arbeitsspeicher: "automatisch verwalten".'
    }
    if ((Get-Count $mem.Modules) -eq 1 -and -not $sys.IsVM) {
        Add-Finding 'Arbeitsspeicher' 1 20 'Nur ein RAM-Modul erkannt (vermutlich Single-Channel)' 'Single-Channel halbiert die Speicherbandbreite - vor allem mit integrierter Grafik spürbar.' 'Bei freiem Steckplatz ein baugleiches zweites Modul ergänzen.'
    }

    # Pool-Tags: welcher Treiber belegt den Kernel-Speicher?
    if ($D.Pool) {
        foreach ($kind in @(@('NonPagedMB', 'TopNonPaged', 'Non-Paged'), @('PagedMB', 'TopPaged', 'Paged'))) {
            $big = @(@($D.Pool.($kind[1])) | Where-Object { $_ -and [double]$_.($kind[0]) -ge 200 })
            if ($big.Count -eq 0) { continue }
            $third = @($big | Where-Object { $_.Drittanbieter })
            $txt = (@($big | Select-Object -First 5 | ForEach-Object {
                        $drv = 'unbekannt'
                        if ($_.Treiber) { $drv = $_.Treiber }
                        'Tag "{0}" {1:N0} MB -> {2}' -f $_.Tag.Trim(), [double]$_.($kind[0]), $drv
                    }) -join '; ')
            if ($third.Count -gt 0) {
                $top = $third[0]
                $sev = 2; $sc = 70
                if ([double]$top.($kind[0]) -ge 1000) { $sev = 3; $sc = 82 }
                Add-Finding 'Arbeitsspeicher' $sev $sc ('{0} Pool: {1:N0} MB belegt durch Drittanbieter-Treiber {2}' -f $kind[2], [double]$top.($kind[0]), $top.Treiber) $txt `
                    'Den genannten Treiber bzw. das zugehörige Programm aktualisieren oder testweise deinstallieren und nach einem Tag Laufzeit erneut messen. Wächst der Wert weiter, ist es ein Speicherleck.'
            }
            else {
                Add-Finding 'Arbeitsspeicher' 1 30 ('Größte {0}-Pool-Belegung durch Windows-Komponenten' -f $kind[2]) $txt 'Windows-interne Tags (z. B. Dateisystem, Netzwerk) werden oft von Programmen ausgelöst, die viele Dateien oder Verbindungen offen halten (Sync-Tools, Indexer, Virenscanner, VPN).'
            }
        }
    }

    # ---------------- Datentraeger
    $phys = @()
    if ($D.Disks) { $phys = @($D.Disks.Physical) }
    $ioTop = ''
    if ($live) { $ioTop = Format-Top $S.TopIo 'AvgMBs' ' MB/s' 3 0.1 }
    $diskIssue = $false
    if ($live) {
        foreach ($dk in @($S.Disks)) {
            $num = ([string]$dk.Instance -split ' ')[0]
            $pd = $phys | Where-Object { $_.DeviceId -eq $num } | Select-Object -First 1
            $label = $dk.Instance
            if ($pd) { $label = '{0} ({1}, {2})' -f $dk.Instance, $pd.Name, $pd.MediaType }
            $lat = [double]$dk.LatAvgMs; $lat95 = [double]$dk.LatP95Ms; $busy = [double]$dk.BusyAvgPct
            if ($lat -ge 50) { $diskIssue = $true; Add-Finding 'Datenträger' 3 88 ('Laufwerk {0} sehr langsam: Ø {1:N0} ms pro Zugriff' -f $label, $lat) ('Gut sind < 5 ms (SSD) bzw. < 20 ms (HDD). Meiste Zugriffe: {0}' -f $ioTop) 'Verursachende Prozesse prüfen (Virenscan, Indexer, Cloud-Sync, Updates). Bei HDD als Systemlaufwerk: SSD einbauen. Laufwerkszustand prüfen (siehe unten).' }
            elseif ($lat -ge 20) { $diskIssue = $true; Add-Finding 'Datenträger' 2 65 ('Laufwerk {0} langsam: Ø {1:N0} ms pro Zugriff' -f $label, $lat) ('Meiste Zugriffe: {0}' -f $ioTop) 'Hintergrund-Zugriffe reduzieren; Laufwerk prüfen.' }
            elseif ($lat95 -ge 100) { $diskIssue = $true; Add-Finding 'Datenträger' 2 55 ('Laufwerk {0} hat Latenz-Spitzen (P95 {1:N0} ms, max {2:N0} ms)' -f $label, $lat95, [double]$dk.LatMaxMs) ('Meiste Zugriffe: {0}' -f $ioTop) 'Kurze Spitzen erklären einzelne Hänger beim Öffnen/Speichern. Laufwerk und Ereignisse (ID 129/153) prüfen.' }
            if ($busy -ge 80) { $diskIssue = $true; Add-Finding 'Datenträger' 3 85 ('Laufwerk {0} dauerhaft ausgelastet ({1:N0} % aktiv)' -f $label, $busy) ('Meiste Zugriffe: {0}' -f $ioTop) 'Den Hauptverursacher stoppen/pausieren; bei HDD: SSD.' }
            elseif ($busy -ge 50) { $diskIssue = $true; Add-Finding 'Datenträger' 2 55 ('Laufwerk {0} stark beschäftigt ({1:N0} % aktiv)' -f $label, $busy) ('Meiste Zugriffe: {0}' -f $ioTop) 'Hintergrund-Zugriffe reduzieren.' }
        }
    }
    foreach ($pd in $phys) {
        if ($pd.IsSystemDisk -and $pd.MediaType -eq 'HDD') {
            $sc = 70; $sv = 2
            if ($diskIssue) { $sc = 93; $sv = 3 }
            Add-Finding 'Datenträger' $sv $sc ('Windows läuft auf einer klassischen Festplatte (HDD): {0}' -f $pd.Name) 'HDDs sind bei vielen kleinen Zugriffen 50-100x langsamer als SSDs - typisch sind träge Explorer, langsame Starts und Hänger.' 'Auf eine SSD umsteigen (größter Einzel-Effekt auf die gefühlte Geschwindigkeit).'
        }
        if ($pd.Health -and $pd.Health -notmatch '(?i)healthy|^0$') {
            Add-Finding 'Datenträger' 3 95 ('Laufwerk meldet Problemzustand: {0} ({1}, {2})' -f $pd.Name, $pd.Health, $pd.Status) '' 'SOFORT Datensicherung machen, Laufwerk mit Herstellertool/CrystalDiskInfo prüfen und ggf. tauschen.'
        }
    }
    if ($D.Disks) {
        foreach ($r in @($D.Disks.Reliability)) {
            if (-not $r) { continue }
            if ([double]$r.ReadErrorsUncorrected -gt 0) { Add-Finding 'Datenträger' 3 85 ('Nicht korrigierbare Lesefehler auf {0} ({1})' -f $r.Name, $r.ReadErrorsUncorrected) 'Das Laufwerk konnte Daten nicht lesen - Vorbote eines Ausfalls.' 'Datensicherung, Laufwerk prüfen/tauschen.' }
            if ($null -ne $r.WearPct -and [double]$r.WearPct -ge 90) { Add-Finding 'Datenträger' 3 80 ('SSD {0} ist zu {1} % verschlissen' -f $r.Name, $r.WearPct) '' 'Datensicherung und Austausch planen.' }
            elseif ($null -ne $r.WearPct -and [double]$r.WearPct -ge 70) { Add-Finding 'Datenträger' 2 45 ('SSD {0} ist zu {1} % verschlissen' -f $r.Name, $r.WearPct) '' 'Austausch mittelfristig einplanen.' }
            if ($null -ne $r.TemperatureC -and [double]$r.TemperatureC -ge 70) { Add-Finding 'Datenträger' 2 50 ('Laufwerk {0} ist heiß ({1} °C)' -f $r.Name, $r.TemperatureC) 'Ab ca. 70 °C drosseln viele NVMe-SSDs massiv.' 'Kühlkörper für die SSD, Gehäuselüftung verbessern.' }
        }
        foreach ($v in @($D.Disks.Volumes)) {
            if (-not $v -or $null -eq $v.FreePct) { continue }
            if ($v.IsSystem -and ([double]$v.FreePct -lt 10 -or [double]$v.FreeGB -lt 15)) { Add-Finding 'Datenträger' 3 70 ('Systemlaufwerk {0} fast voll ({1:N1} GB / {2:N0} % frei)' -f $v.Drive, $v.FreeGB, $v.FreePct) 'Windows braucht Platz für Updates, Auslagerung und Cache. Volle SSDs werden zudem deutlich langsamer.' 'Datenträgerbereinigung (cleanmgr, "Systemdateien bereinigen"), Downloads/Temp leeren, große Dateien verschieben.' }
            elseif ($v.IsSystem -and [double]$v.FreePct -lt 15) { Add-Finding 'Datenträger' 2 45 ('Systemlaufwerk {0} wird knapp ({1:N0} % frei)' -f $v.Drive, $v.FreePct) '' 'Aufräumen (Speicheroptimierung in den Einstellungen aktivieren).' }
            elseif (-not $v.IsSystem -and [double]$v.FreePct -lt 5) { Add-Finding 'Datenträger' 1 20 ('Laufwerk {0} fast voll ({1:N0} % frei)' -f $v.Drive, $v.FreePct) '' 'Aufräumen.' }
        }
        $hasSsd = @($phys | Where-Object { $_.MediaType -eq 'SSD' -or $_.BusType -eq 'NVMe' }).Count -gt 0
        if ($D.Disks.TrimDisabled -eq $true -and $hasSsd) { Add-Finding 'Datenträger' 2 40 'TRIM ist deaktiviert' 'Ohne TRIM werden SSDs mit der Zeit langsamer.' 'Als Admin: fsutil behavior set DisableDeleteNotify 0' }
    }
    $h = Get-TagHits $ev 'disk-bad'
    if ($h -gt 0) {
        $badTxt = Get-TagText $ev 'disk-bad'
        $affectedDrives = New-Object System.Collections.Generic.List[string]
        foreach ($g in @($ev | Where-Object { $_ -and $_.Tag -eq 'disk-bad' })) {
            if ($g.Sample -match 'Harddisk(\d+)') {
                $hdNum = $Matches[1]
                $pdMatch = $phys | Where-Object { $_.DeviceId -eq $hdNum } | Select-Object -First 1
                if ($pdMatch) {
                    $drvInfo = ('Harddisk{0} = {1}{2}' -f $hdNum, $pdMatch.Name, $(if ($pdMatch.Drives) { ' (' + $pdMatch.Drives + ')' } else { '' }))
                    if (-not $affectedDrives.Contains($drvInfo)) { $affectedDrives.Add($drvInfo) }
                }
                else {
                    $drvInfo = ('Harddisk{0} (vermutlich externes/entferntes Laufwerk)' -f $hdNum)
                    if (-not $affectedDrives.Contains($drvInfo)) { $affectedDrives.Add($drvInfo) }
                }
            }
        }
        if ($affectedDrives.Count -gt 0) { $badTxt += ' · Betroffen: ' + ($affectedDrives -join ', ') }
        Add-Finding 'Datenträger' 3 95 ('Laufwerksfehler im Ereignisprotokoll ({0}x)' -f $h) $badTxt 'SOFORT Datensicherung des betroffenen Laufwerks. Mit CrystalDiskInfo/Herstellertool prüfen und tauschen.'
    }
    $h = Get-TagHits $ev 'disk-reset'
    if ($h -gt 0) {
        $sv = 2; $sc = 75
        if ($h -ge 3) { $sv = 3; $sc = 90 }
        Add-Finding 'Datenträger' $sv $sc ('Laufwerk/Controller hing und wurde zurückgesetzt ({0}x)' -f $h) ((Get-TagText $ev 'disk-reset') + ' - jedes Ereignis bedeutet typischerweise 30-60 s Stillstand bei Dateizugriffen.') 'SSD-Firmware und Chipsatz-/Storage-Treiber (Intel RST/AMD SATA) aktualisieren, SATA-Kabel/Port tauschen, Energiesparoption "AHCI Link Power Management" bzw. "PCI Express Link State" auf "Aus".'
    }
    $h = Get-TagHits $ev 'disk-retry'
    if ($h -gt 0) {
        $sv = 2; $sc = 70
        if ($h -ge 10) { $sv = 3; $sc = 85 }
        Add-Finding 'Datenträger' $sv $sc ('Laufwerk antwortete nicht rechtzeitig ({0}x)' -f $h) (Get-TagText $ev 'disk-retry') 'Laufwerk/Kabel prüfen, Firmware aktualisieren, Datensicherung.'
    }
    $h = Get-TagHits $ev 'ntfs'
    if ($h -gt 0) { Add-Finding 'Datenträger' 2 50 ('Dateisystem-Warnungen ({0}x)' -f $h) (Get-TagText $ev 'ntfs') 'Als Admin "chkdsk C: /scan" ausführen.' }
    if ($live -and -not $diskIssue -and (Get-Count $S.Disks) -gt 0) {
        Add-Finding 'Datenträger' 0 5 'Laufwerks-Antwortzeiten während der Messung unauffällig' ('Meiste Zugriffe: {0}' -f $ioTop) ''
    }

    # ---------------- Explorer & Dateien
    $X = $D.Explorer
    if ($X) {
        foreach ($nd in @($X.NetworkDrives)) {
            if (-not $nd) { continue }
            if ($nd.Reachable -eq $false -or $nd.Status -match '(?i)unavailable|disconnected|Timeout') {
                Add-Finding 'Explorer & Dateien' 3 85 ('Netzlaufwerk {0} ist nicht erreichbar ({1})' -f $nd.Drive, $nd.Remote) ('Status: {0}. Explorer wartet bei jedem Öffnen von "Dieser PC", Speichern-Dialogen usw. auf einen Timeout.' -f $nd.Status) ('Laufwerk trennen, wenn nicht gebraucht: im Explorer Rechtsklick > Trennen oder "net use {0} /delete". Sonst Server/NAS erreichbar machen.' -f $nd.Drive)
            }
        }
        foreach ($f in @($X.Folders)) {
            if (-not $f) { continue }
            if ($f.Status -eq 'Timeout') { Add-Finding 'Explorer & Dateien' 3 70 ('Ordner "{0}" lässt sich nicht in 15 s auflisten' -f $f.Name) $f.Path 'Ordnerinhalt prüfen (Netz-/Cloud-Pfad?), Unterordner anlegen, Cloud-Sync prüfen.' }
            elseif ([double]$f.Ms -ge 2000) { Add-Finding 'Explorer & Dateien' 2 55 ('Ordner "{0}" lädt langsam ({1:N1} s für {2} Einträge)' -f $f.Name, ([double]$f.Ms / 1000), $f.Entries) $f.Path 'Ordner aufräumen; Virenscanner/Cloud-Sync prüfen.' }
            if ([int]$f.Entries -ge 5000) { Add-Finding 'Explorer & Dateien' 2 40 ('Ordner "{0}" enthält {1} Einträge' -f $f.Name, $f.Entries) 'Explorer muss beim Öffnen alle Einträge lesen, Vorschaubilder erzeugen und Details abfragen.' 'In Unterordner aufteilen bzw. alte Dateien archivieren.' }
            elseif ($f.Name -eq 'Desktop' -and [int]$f.Entries -ge 150) { Add-Finding 'Explorer & Dateien' 1 20 ('Viele Dateien auf dem Desktop ({0})' -f $f.Entries) 'Der Desktop wird ständig von Explorer überwacht.' 'Desktop aufräumen.' }
        }
        if ($X.WriteTest) {
            $wt = $X.WriteTest
            if ([double]$wt.MedianMs -ge 20) { Add-Finding 'Explorer & Dateien' 2 60 ('Kleine Dateien zu schreiben ist langsam (Median {0:N0} ms pro Datei)' -f $wt.MedianMs) 'Gut sind < 5 ms auf SSD. Ursache meist Virenscanner-Echtzeitprüfung, eine HDD oder ein überlastetes Laufwerk.' 'Virenscanner prüfen (Drittanbieter testweise deinstallieren), Laufwerk prüfen.' }
            elseif ([double]$wt.MaxMs -ge 500) { Add-Finding 'Explorer & Dateien' 2 45 ('Einzelne Schreibvorgänge hängen (bis {0:N0} ms)' -f $wt.MaxMs) '' 'Laufwerk/Virenscanner prüfen.' }
        }
        $cmh = @(@($X.ContextMenuHandlers) | Where-Object { $_ })
        $missing = @($cmh | Where-Object { $_.Missing })
        if ($missing.Count -gt 0) { Add-Finding 'Explorer & Dateien' 2 50 ('Defekte Kontextmenü-Erweiterung(en): {0}' -f ((@($missing | ForEach-Object { $_.Name })) -join ', ')) 'Die registrierte DLL fehlt - Rechtsklick kann hängen.' 'Mit ShellExView (NirSoft) deaktivieren bzw. Reste des Programms entfernen.' }
        if ($cmh.Count -ge 8) {
            Add-Finding 'Explorer & Dateien' 1 30 ('{0} Kontextmenü-Erweiterungen von Drittanbietern' -f $cmh.Count) ((@($cmh | Select-Object -First 15 | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Company })) -join ', ') 'Langsamer Rechtsklick/Explorer? Mit ShellExView (NirSoft) alle Nicht-Microsoft-Erweiterungen deaktivieren, testen, dann einzeln wieder einschalten.'
        }
        if ((Get-Count $X.OverlayHandlers) -gt 15) { Add-Finding 'Explorer & Dateien' 1 20 ('{0} Symbol-Overlays registriert (Windows nutzt nur 15)' -f (Get-Count $X.OverlayHandlers)) 'Viele Cloud-/Versionsverwaltungs-Tools registrieren Overlays.' 'Ungenutzte Sync-Programme deinstallieren.' }
        if ((Get-Count $X.CloudSync) -gt 0) {
            $syncCpu = 0.0; $syncIo = 0.0
            foreach ($t in @($S.TopCpu)) { if ($t -and $script:CloudSync.ContainsKey($t.Name)) { $syncCpu += [double]$t.AvgPct } }
            foreach ($t in @($S.TopIo)) { if ($t -and $script:CloudSync.ContainsKey($t.Name)) { $syncIo += [double]$t.AvgMBs } }
            if ($syncCpu -ge 10 -or $syncIo -ge 5) { Add-Finding 'Explorer & Dateien' 2 55 ('Cloud-Synchronisation arbeitet stark ({0}: Ø {1:N0} % CPU, {2:N1} MB/s)' -f (@($X.CloudSync) -join ', '), $syncCpu, $syncIo) '' 'Synchronisation pausieren und vergleichen; große/viele Dateien aus synchronisierten Ordnern auslagern.' }
            else { Add-Finding 'Explorer & Dateien' 1 10 ('Cloud-Sync aktiv: {0}' -f (@($X.CloudSync) -join ', ')) 'Während der Messung unauffällig.' 'Bei langsamen Ordnern Sync testweise pausieren.' }
        }
        $idx = 0.0
        foreach ($t in @($S.TopCpu)) { if ($t -and $t.Name -match '^(SearchIndexer|SearchProtocolHost|SearchFilterHost)$') { $idx += [double]$t.AvgPct } }
        if ($idx -ge 10) { Add-Finding 'Explorer & Dateien' 2 50 ('Windows-Suche indiziert gerade stark (Ø {0:N0} % CPU)' -f $idx) '' 'Indizierungsoptionen: weniger Orte indizieren; nach großen Dateimengen-Änderungen abwarten.' }
    }
    if ($D.Events) {
        $exHang = @($D.Events.AppHangs) | Where-Object { $_ -and $_.App -match '(?i)^explorer\.exe$' } | Select-Object -First 1
        if ($exHang) {
            $sv = 2; $sc = 55
            if ([int]$exHang.Hits -ge 5) { $sv = 3; $sc = 75 }
            Add-Finding 'Explorer & Dateien' $sv $sc ('Explorer hat in {0} Tagen {1}x nicht reagiert' -f $D.Events.Days, $exHang.Hits) ('Zuletzt {0}.' -f $exHang.Last) 'Typisch: Netzlaufwerke, Shell-Erweiterungen, Cloud-Sync, langsames Laufwerk (siehe übrige Befunde).'
        }
    }
    if ($D.Processes -and $D.Processes.Explorer) {
        $e = $D.Processes.Explorer
        if ([int]$e.Handles -ge 10000 -or [double]$e.PrivateMB -ge 1500) {
            Add-Finding 'Explorer & Dateien' 2 40 ('Explorer belegt ungewöhnlich viel ({0:N0} MB, {1} Handles)' -f $e.PrivateMB, $e.Handles) 'Deutet auf eine Erweiterung mit Speicherleck.' 'Explorer im Task-Manager neu starten; Shell-Erweiterungen prüfen.'
        }
    }

    # ---------------- Eingabe
    $I = $D.Input
    if ($I) {
        if ($I.FilterKeysOn) { Add-Finding 'Eingabe' 3 97 'Anschlagverzögerung (Filtertasten) ist eingeschaltet' ('Tastendrücke werden absichtlich verzögert oder ignoriert (Verzögerung {0} ms). Wird oft versehentlich durch 8 s langes Halten der rechten Umschalttaste aktiviert.' -f $I.FilterDelayMs) 'Einstellungen > Barrierefreiheit > Tastatur > "Anschlagverzögerung" ausschalten (auch das Tastenkürzel dort deaktivieren).' }
        if ($I.KeyboardDelay -eq 3) { Add-Finding 'Eingabe' 1 15 'Lange Verzögerung vor Tastenwiederholung eingestellt' 'Gedrückt gehaltene Tasten wiederholen erst spät - fühlt sich träge an.' 'Systemsteuerung > Tastatur > Verzögerung kürzer stellen.' }
        if ($I.StickyKeysOn) { Add-Finding 'Eingabe' 1 15 'Einrastfunktion ist aktiv' '' 'Bei Bedarf unter Barrierefreiheit > Tastatur ausschalten.' }
    }
    if ($sys.ExplorerUser -and $sys.ScriptUser -and $sys.ExplorerUser -ne $sys.ScriptUser) {
        Add-Finding 'Eingabe' 1 10 ('Skript lief als "{0}", angemeldet ist "{1}"' -f $sys.ScriptUser, $sys.ExplorerUser) 'Tastatur-, Explorer- und Autostart-Einstellungen des angemeldeten Benutzers wurden daher evtl. nicht geprüft.' 'Skript als angemeldeter Benutzer (Admin-Konto) starten.'
    }
    $inputTools = @()
    if ($D.Software) { $inputTools = @(@($D.Software.KnownTools) | Where-Object { $_ -and $_.Art -eq 'input' }) }
    if ($inputTools.Count -gt 0) {
        Add-Finding 'Eingabe' 1 25 ('Peripherie-/Overlay-Software aktiv: {0}' -f ((@($inputTools | ForEach-Object { $_.Name })) -join ', ')) 'Solche Tools hängen sich in jede Eingabe ein; fehlerhafte Versionen verzögern Tastatur/Maus.' 'Testweise beenden und Tipp-Gefühl vergleichen; auf aktuelle Version bringen.'
    }
    $marks = @()
    if ($S) { $marks = @(@($S.Marks) | Where-Object { $_ }) }
    if ($marks.Count -gt 0) {
        $cnt = [ordered]@{ CPU = 0; GPU = 0; DPC = 0; Disk = 0; RAM = 0; Haenger = 0 }
        $culprits = @{}
        foreach ($mk in $marks) {
            $ctx = @($mk.Kontext)
            $fl = @{}
            foreach ($cx in $ctx) {
                if (-not $cx) { continue }
                if ([double]$cx.CPU -ge 85) { $fl.CPU = $true; foreach ($t in ([string]$cx.TopCPU -split ', ')) { if ($t) { $nm = ($t -split ' ')[0]; $culprits[$nm] = [int]$culprits[$nm] + 1 } } }
                if ($null -ne $cx.GPU -and [double]$cx.GPU -ge 95) { $fl.GPU = $true }
                if ([double]$cx.DPCKern -ge 15 -or [double]$cx.IntKern -ge 15) { $fl.DPC = $true }
                if ([double]$cx.DiskMs -ge 50 -or [double]$cx.DiskAktiv -ge 90) { $fl.Disk = $true }
                if ([double]$cx.SeitenEin -ge 300) { $fl.RAM = $true }
                if ([double]$cx.HaengerMs -ge 100) { $fl.Haenger = $true }
            }
            foreach ($k in @($fl.Keys)) { $cnt[$k]++ }
        }
        $parts = @()
        if ($cnt.CPU) { $parts += ('{0}x CPU-Vollast ({1})' -f $cnt.CPU, ((@($culprits.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3 | ForEach-Object { $_.Key })) -join ', ')) }
        if ($cnt.GPU) { $parts += ('{0}x GPU-Vollast' -f $cnt.GPU) }
        if ($cnt.DPC) { $parts += ('{0}x hohe Treiberlast (DPC/Interrupt)' -f $cnt.DPC) }
        if ($cnt.Disk) { $parts += ('{0}x Laufwerk überlastet/langsam' -f $cnt.Disk) }
        if ($cnt.RAM) { $parts += ('{0}x starkes Auslagern' -f $cnt.RAM) }
        if ($cnt.Haenger) { $parts += ('{0}x System-Hänger' -f $cnt.Haenger) }
        if ($parts.Count -gt 0) {
            Add-Finding 'Eingabe' 2 80 ('Bei deinen {0} Markierung(en) war messbar: {1}' -f $marks.Count, ($parts -join '; ')) 'Die gespürten Hänger fallen mit diesen Messwerten zusammen - das ist die wahrscheinlichste Ursache. Details im Anhang "Markierte Momente".' 'Siehe Empfehlungen der passenden Kategorie.'
        }
        else {
            Add-Finding 'Eingabe' 2 60 ('Bei deinen {0} Markierung(en) war systemweit nichts auffällig' -f $marks.Count) 'CPU, Treiber, Laufwerk und RAM waren in diesen Momenten unauffällig. Das spricht für ein Problem in der jeweiligen Anwendung (z. B. Browser-Tab, Erweiterung) oder im Eingabeweg selbst.' 'Funk-/Bluetooth-Tastatur: Empfänger näher und an USB-2.0-Port (USB 3 stört 2,4 GHz), Batterien prüfen; kabelgebunden gegentesten. Im Browser: Hardwarebeschleunigung umschalten, Erweiterungen deaktivieren.'
        }
    }
    if (@($script:Findings | Where-Object { $_.Category -eq 'Eingabe' }).Count -eq 0 -and $I) {
        Add-Finding 'Eingabe' 0 5 'Tastatur- und Eingabeeinstellungen unauffällig' 'Anschlagverzögerung (Filtertasten) und Einrastfunktion sind aus.' ''
    }

    # ---------------- Energie & Thermik
    if ($sys.PowerPlanGuid -eq 'a1841308-3541-4fab-bc81-f71556f20b4a') {
        Add-Finding 'Energie & Thermik' 2 60 ('Energiesparplan "{0}" aktiv' -f $sys.PowerPlan) 'Der Prozessor wird stark heruntergetaktet.' 'Systemsteuerung > Energieoptionen > "Ausbalanciert" (oder "Höchstleistung").'
    }
    if ($sys.PowerModeAC -eq 'Beste Energieeffizienz') {
        Add-Finding 'Energie & Thermik' 2 50 'Energiemodus "Beste Energieeffizienz" im Netzbetrieb' 'Windows drosselt den Prozessor auch am Netzteil.' 'Einstellungen > System > Netzbetrieb und Akku > Energiemodus: "Ausbalanciert" oder "Beste Leistung".'
    }
    if ($sys.OnBattery) {
        Add-Finding 'Energie & Thermik' 1 30 'Messung lief im Akkubetrieb' 'Im Akkubetrieb drosseln Laptops oft deutlich.' 'Zum Vergleich am Netzteil messen.'
    }
    if ($S -and $S.LoadSeconds -ge 5 -and $null -ne $S.CpuPerfUnderLoad) {
        $pf = [double]$S.CpuPerfUnderLoad
        if ($pf -lt 60) {
            Add-Finding 'Energie & Thermik' 2 65 ('CPU läuft unter Last nur mit {0:N0} % der Nennleistung' -f $pf) ('Gemessen in {0} Sekunden mit mehr als 50 % Auslastung. Hinweis auf Drosselung durch Hitze, Energieeinstellungen oder Netzteil.' -f $S.LoadSeconds) 'Lüfter/Kühlkörper reinigen, Wärmeleitpaste (bei älteren Geräten), Energiemodus prüfen, Original-Netzteil verwenden.'
        }
    }
    $h = Get-TagHits $ev 'throttle'
    if ($h -gt 0) {
        $sv = 2; $sc = 60
        if ($h -ge 20) { $sv = 3; $sc = 75 }
        Add-Finding 'Energie & Thermik' $sv $sc ('Prozessor wurde von der Firmware gedrosselt ({0}x)' -f $h) (Get-TagText $ev 'throttle') 'Meist Überhitzung oder schwaches Netzteil: Lüfter reinigen, Unterlage frei halten, BIOS aktualisieren.'
    }
    if (@($script:Findings | Where-Object { $_.Category -eq 'Energie & Thermik' }).Count -eq 0 -and $sys.PowerPlan) {
        Add-Finding 'Energie & Thermik' 0 5 ('Energieeinstellungen unauffällig ({0})' -f $sys.PowerPlan) '' ''
    }
    if ($sys.UptimeHours -and [double]$sys.UptimeHours -ge 168) {
        $extra = ''
        if ($sys.FastStartup) { $extra = ' Wegen "Schnellstart" setzt Herunterfahren den Kernel NICHT zurück - nur "Neu starten" tut das.' }
        Add-Finding 'Energie & Thermik' 1 25 ('Seit {0:N0} Tagen nicht neu gestartet' -f ([double]$sys.UptimeHours / 24)) ('Speicherlecks von Treibern/Programmen sammeln sich an.' + $extra) 'Regelmäßig "Neu starten" wählen.'
    }

    # ---------------- Software & Autostart
    $W = $D.Software
    if ($W) {
        $avOn = @(@($W.Antivirus) | Where-Object { $_ -and $_.Enabled })
        $third = @($avOn | Where-Object { $_.Name -notmatch '(?i)defender' })
        $thirdOff = @(@($W.Antivirus) | Where-Object { $_ -and -not $_.Enabled -and $_.Name -notmatch '(?i)defender' })
        if ($avOn.Count -ge 2) {
            Add-Finding 'Software & Autostart' 3 80 ('Mehrere Virenscanner gleichzeitig aktiv: {0}' -f ((@($avOn | ForEach-Object { $_.Name })) -join ', ')) 'Zwei Echtzeitscanner prüfen jeden Dateizugriff doppelt und behindern sich gegenseitig.' 'Nur einen behalten - Microsoft Defender reicht für die meisten.'
        }
        elseif ($third.Count -gt 0) {
            Add-Finding 'Software & Autostart' 1 30 ('Drittanbieter-Virenschutz aktiv: {0}' -f ((@($third | ForEach-Object { $_.Name })) -join ', ')) 'Drittanbieter-Suiten bremsen Dateizugriffe oft stärker als der eingebaute Defender.' 'Testweise deinstallieren (mit Removal-Tool des Herstellers) und Defender nutzen.'
        }
        elseif ($thirdOff.Count -gt 0) {
            Add-Finding 'Software & Autostart' 1 30 ('Drittanbieter-Virenschutz installiert (Echtzeitschutz aus, Dienste/Treiber laufen): {0}' -f ((@($thirdOff | ForEach-Object { $_.Name })) -join ', ')) 'Auch wenn der Schutz im Tray pausiert ist, bleiben Kernel-Filter und Hintergrunddienste aktiv (und Windows Defender bleibt deaktiviert).' 'Falls nicht mehr genutzt: vollständig deinstallieren, damit Kernel-Filter entladen werden und Windows Defender wieder übernimmt.'
        }
        if ((Get-Count $W.Minifilters) -ge 4) {
            $mfTxt = (@($W.Minifilters | ForEach-Object { '{0} ({1}, {2} Inst.)' -f $_.Filter, $_.Firma, $_.Instanzen }) -join ', ')
            Add-Finding 'Software & Autostart' 1 25 ('{0} aktive Dateisystem-Minifilter von Drittanbietern' -f (Get-Count $W.Minifilters)) ('Jeder Filter klinkt sich in Dateioperationen ein: ' + $mfTxt) 'Unnötige Backup-, Schutz- oder Kopierschutz-Treiber deinstallieren, falls Dateizugriffe oder Kernel-CPU-Last auffällig sind.'
        }
        $avCpu = 0.0; $avIo = 0.0; $avNames = @()
        foreach ($t in @($S.TopCpu)) { if ($t -and $t.Name -match $script:AvProcesses) { $avCpu += [double]$t.AvgPct; $avNames += $t.Name } }
        foreach ($t in @($S.TopIo)) { if ($t -and $t.Name -match $script:AvProcesses) { $avIo += [double]$t.AvgMBs; $avNames += $t.Name } }
        if ($avCpu -ge 10 -or $avIo -ge 10) {
            Add-Finding 'Software & Autostart' 2 65 ('Virenscanner verursacht hohe Last (Ø {0:N0} % CPU, {1:N1} MB/s)' -f $avCpu, $avIo) ('Prozesse: {0}' -f ((@($avNames | Select-Object -Unique)) -join ', ')) 'Läuft gerade ein vollständiger Scan? Sonst: Ordner mit vielen kleinen Dateien (Entwicklung, Spiele-Bibliotheken, VMs) als Ausnahme eintragen.'
        }
        $sc = [int]$W.StartupEnabledCount
        if ($sc -ge 25) { Add-Finding 'Software & Autostart' 2 45 ('{0} aktive Autostart-Einträge' -f $sc) 'Viele Programme starten mit Windows und laufen dauerhaft im Hintergrund.' 'Task-Manager > Autostart-Apps: alles Unnötige deaktivieren.' }
        elseif ($sc -ge 15) { Add-Finding 'Software & Autostart' 1 30 ('{0} aktive Autostart-Einträge' -f $sc) '' 'Task-Manager > Autostart-Apps: Unnötiges deaktivieren.' }
        if ($W.Autoruns -and (Get-Count $W.Autoruns.Unsigned) -gt 0) {
            $un = @($W.Autoruns.Unsigned)
            Add-Finding 'Software & Autostart' 2 40 ('{0} unsignierte Autostart-Einträge (Autoruns)' -f $un.Count) ((@($un | Select-Object -First 10 | ForEach-Object { '{0} [{1}]' -f $_.Eintrag, $_.Kategorie })) -join ', ') 'Unbekannte Einträge recherchieren; Unnötiges in Autoruns deaktivieren (Haken entfernen statt löschen).'
        }
        $tools = @(@($W.KnownTools) | Where-Object { $_ -and $_.Art -ne 'input' })
        if ($tools.Count -gt 0) {
            $lat = @($tools | Where-Object { $_.Art -eq 'latency' })
            $sv = 1; $scr = 30
            if ($lat.Count -gt 0) { $sv = 2; $scr = 50 }
            Add-Finding 'Software & Autostart' $sv $scr ('Bekannte Bremsen/Latenz-Verursacher installiert: {0}' -f ((@($tools | ForEach-Object { $_.Name })) -join ', ')) 'Hersteller-Tools für RGB, Audio-Effekte, Netzwerk-Priorisierung und "Optimierer" verursachen häufig DPC-Latenzen und Hintergrundlast.' 'Testweise deinstallieren (nicht nur beenden) und erneut messen.'
        }
    }
    if ($D.Processes) {
        foreach ($hh in @($D.Processes.HighHandles)) {
            if (-not $hh) { continue }
            if ([int]$hh.Handles -ge 50000) { Add-Finding 'Software & Autostart' 2 50 ('{0} hält {1} Handles (Leck)' -f $hh.Name, $hh.Handles) 'Ein Programm gibt Systemressourcen nicht mehr frei.' 'Programm neu starten/aktualisieren.' }
        }
        foreach ($b in @($D.Processes.Browsers)) {
            if (-not $b) { continue }
            $issues = @()
            if ([double]$b.CpuAvgPct -ge 25) { $issues += ('Ø {0:N0} % CPU' -f $b.CpuAvgPct) }
            if ($null -ne $b.RamSharePct -and [double]$b.RamSharePct -ge 40) { $issues += ('{0:N1} GB RAM = {1} % des Speichers' -f ([double]$b.PrivateMB / 1024), $b.RamSharePct) }
            if ($issues.Count -gt 0) {
                Add-Finding 'Software & Autostart' 2 60 ('Browser {0} belastet das System ({1})' -f $b.Name, ($issues -join ', ')) ('{0} Prozesse.' -f $b.Instances) 'Browser-Task-Manager (Umschalt+Esc in Chrome/Edge) öffnen und Tabs/Erweiterungen mit hoher Last schließen. "Memory Saver" aktivieren.'
            }
            else {
                Add-Finding 'Software & Autostart' 0 5 ('Browser {0} ist derzeit nicht der Flaschenhals' -f $b.Name) ('{0} Prozesse, {1:N1} GB RAM, Ø {2:N1} % CPU, {3:N1} MB/s Datenträger.' -f $b.Instances, ([double]$b.PrivateMB / 1024), [double]$b.CpuAvgPct, [double]$b.IoAvgMBs) ''
            }
        }
    }
    if ($sys.PendingReboot) {
        Add-Finding 'Software & Autostart' 1 30 'Ein Neustart für Updates steht aus' 'Halb installierte Updates können im Hintergrund Last erzeugen.' 'Neu starten.'
    }
    if ($sys.HVCI -and ($sys.CPU -match '(?i)i[3579]-[2-7]\d{3}|Ryzen \d 1\d{3}|FX-|Athlon|Pentium|Celeron')) {
        Add-Finding 'Software & Autostart' 1 25 'Speicherintegrität (HVCI) auf älterer CPU aktiv' ('Auf CPUs vor Intel 8. Gen./AMD Zen 2 kostet HVCI spürbar Leistung ({0}).' -f $sys.CPU) 'Sicherheitsabwägung: Windows-Sicherheit > Gerätesicherheit > Kernisolierung testweise ausschalten und vergleichen.'
    }

    # ---------------- Stabilitaet & Hardware
    if ($live -and $C.gpu_3d_pct) {
        $gAvg = [double]$C.gpu_3d_pct.Avg
        $gP95 = [double]$C.gpu_3d_pct.P95
        if ($gAvg -ge 90) {
            Add-Finding 'Stabilität & Hardware' 2 65 ('Grafikkarte dauerhaft am Limit (3D-Last Ø {0:N0} %)' -f $gAvg) 'Bei voller GPU-Auslastung können Fenster, Maus und Browser-Rendering ruckeln.' 'Grafiklast reduzieren, Hardwarebeschleunigung in Hintergrund-Apps prüfen oder Framerate begrenzen.'
        }
        elseif ($gP95 -ge 95) {
            Add-Finding 'Stabilität & Hardware' 1 30 ('Zeitweise hohe GPU-3D-Auslastung (P95 {0:N0} %)' -f $gP95) '' ''
        }
    }
    $h = Get-TagHits $ev 'whea-corrected'
    if ($h -gt 0) {
        $sv = 2; $sc = 70
        if ($h -ge 50) { $sv = 3; $sc = 85 }
        Add-Finding 'Stabilität & Hardware' $sv $sc ('Korrigierte Hardwarefehler (WHEA) {0}x' -f $h) ((Get-TagText $ev 'whea-corrected') + '. Jeder Fehler unterbricht das System kurz - in Massen führt das zu Rucklern und Hängern.') 'Im Ereignis steht das betroffene PCIe-Gerät. BIOS und Chipsatz aktualisieren, Grafikkarte/NVMe neu stecken, im BIOS PCIe auf Gen3 oder ASPM aus testen.'
    }
    $h = Get-TagHits $ev 'whea'
    if ($h -gt 0) { Add-Finding 'Stabilität & Hardware' 3 85 ('Schwere Hardwarefehler (WHEA) {0}x' -f $h) (Get-TagText $ev 'whea') 'RAM testen (Windows-Speicherdiagnose oder MemTest86), Übertaktung/XMP testweise aus, BIOS aktualisieren.' }
    $h = Get-TagHits $ev 'lowmem'
    if ($h -gt 0) { Add-Finding 'Stabilität & Hardware' 3 75 ('Windows meldete Speichermangel ({0}x)' -f $h) (Get-TagText $ev 'lowmem') 'Siehe Kategorie Arbeitsspeicher; Auslagerungsdatei automatisch verwalten lassen.' }
    $h = Get-TagHits $ev 'bugcheck'
    if ($h -gt 0) { Add-Finding 'Stabilität & Hardware' 2 60 ('Bluescreens in den letzten {0} Tagen: {1}' -f $D.Events.Days, $h) (Get-TagText $ev 'bugcheck') 'Mit WhoCrashed oder BlueScreenView den verursachenden Treiber ermitteln.' }
    $h = Get-TagHits $ev 'kernel-power'
    if ($h -gt 0) { Add-Finding 'Stabilität & Hardware' 2 45 ('Unerwartete Neustarts/Abschaltungen: {0}' -f $h) (Get-TagText $ev 'kernel-power') 'Netzteil, Temperaturen, Bluescreens prüfen.' }
    $h = Get-TagHits $ev 'gpu-tdr'
    if ($h -gt 0) { Add-Finding 'Stabilität & Hardware' 2 60 ('Grafiktreiber-Probleme: {0}x' -f $h) ((Get-TagText $ev 'gpu-tdr') + '. Jeder Reset friert das Bild für Sekunden ein.') 'Grafiktreiber sauber neu installieren (DDU), Übertaktung entfernen.' }
    $h = Get-TagHits $ev 'svc-timeout'
    if ($h -ge 3) { Add-Finding 'Stabilität & Hardware' 1 25 ('Dienste reagierten nicht rechtzeitig ({0}x)' -f $h) (Get-TagText $ev 'svc-timeout') 'Kann auf ein langsames System beim Start hindeuten; betroffene Dienste prüfen.' }
    if ($D.Events -and (Get-Count $D.Events.AppCrashes) -gt 0) {
        $top = @($D.Events.AppCrashes | Select-Object -First 4)
        Add-Finding 'Stabilität & Hardware' 1 20 ('Programmabstürze: {0}' -f ((@($top | ForEach-Object { '{0} ({1}x)' -f $_.App, $_.Hits })) -join ', ')) '' 'Betroffene Programme aktualisieren.'
    }
    if ($D.Drivers) {
        $pdv = @(@($D.Drivers.ProblemDevices) | Where-Object { $_ -and $_.Fehlercode -ne 22 })
        if ($pdv.Count -gt 0) {
            Add-Finding 'Stabilität & Hardware' 2 50 ('{0} Gerät(e) mit Treiberproblemen' -f $pdv.Count) ((@($pdv | Select-Object -First 8 | ForEach-Object { '{0} (Code {1})' -f $_.Name, $_.Fehlercode })) -join ', ') 'Geräte-Manager öffnen, Treiber für die markierten Geräte installieren/aktualisieren.'
        }
    }
    if ($D.Events -and (Get-Count $D.Events.BootTimes) -gt 0) {
        $bavg = (@($D.Events.BootTimes) | Measure-Object -Property Sekunden -Average).Average
        $degr = ((@($D.Events.BootDegraders) | Select-Object -First 5 | ForEach-Object { '{0}: {1} (+{2:N1} s)' -f $_.Art, $_.Name, ([double]$_.AvgDelayMs / 1000) })) -join '; '
        if ($bavg -ge 90) { Add-Finding 'Stabilität & Hardware' 2 40 ('Windows-Start dauert lange (Ø {0:N0} s)' -f $bavg) ('Bremsen beim Start: {0}' -f $degr) 'Autostart reduzieren, genannte Treiber/Dienste aktualisieren.' }
        elseif ($bavg -ge 60) { Add-Finding 'Stabilität & Hardware' 1 20 ('Windows-Start mäßig schnell (Ø {0:N0} s)' -f $bavg) ('Bremsen beim Start: {0}' -f $degr) 'Autostart reduzieren.' }
    }
    if (@($script:Findings | Where-Object { $_.Category -eq 'Stabilität & Hardware' }).Count -eq 0) {
        Add-Finding 'Stabilität & Hardware' 0 5 'Keine Hardware- oder Stabilitätsprobleme protokolliert' '' ''
    }
}
#endregion

#region ---------------------------------------------------------------- Reporter
function Get-SevLabel { param([int]$Sev) switch ($Sev) { 3 { 'ROT' } 2 { 'GELB' } 1 { 'HINWEIS' } default { 'OK' } } }
function Get-SevIcon { param([int]$Sev) switch ($Sev) { 3 { '🔴' } 2 { '🟡' } 1 { '🔵' } default { '🟢' } } }
function Get-SevColor { param([int]$Sev) switch ($Sev) { 3 { 'Red' } 2 { 'Yellow' } 1 { 'Cyan' } default { 'Green' } } }

function Get-CategoryStatus {
    $list = @()
    foreach ($cat in $script:Categories) {
        $f = @($script:Findings | Where-Object { $_.Category -eq $cat })
        if ($f.Count -eq 0) {
            $list += [pscustomobject]@{ Category = $cat; Status = 'KEINE DATEN'; Icon = '⚪'; Color = 'DarkGray'; Top = '' ; Sev = -1 }
            continue
        }
        $max = ($f | Measure-Object -Property Severity -Maximum).Maximum
        $top = $f | Sort-Object @{ Expression = 'Severity'; Descending = $true }, @{ Expression = 'Score'; Descending = $true } | Select-Object -First 1
        if ($max -ge 3) { $st = 'ROT'; $ic = '🔴'; $co = 'Red' }
        elseif ($max -eq 2) { $st = 'GELB'; $ic = '🟡'; $co = 'Yellow' }
        else { $st = 'GRÜN'; $ic = '🟢'; $co = 'Green' }
        $list += [pscustomobject]@{ Category = $cat; Status = $st; Icon = $ic; Color = $co; Top = $top.Title; Sev = $max }
    }
    return $list
}

function Get-Ranking {
    $r = @($script:Findings | Where-Object { $_.Severity -ge 2 } | Sort-Object @{ Expression = 'Score'; Descending = $true }, @{ Expression = 'Severity'; Descending = $true } | Select-Object -First 10)
    if ($r.Count -eq 0) { $r = @($script:Findings | Where-Object { $_.Severity -eq 1 } | Sort-Object Score -Descending | Select-Object -First 5) }
    return $r
}

function Write-ConsoleReport {
    param($D, [string]$OutDir)
    Write-Host ''
    Write-Host '==================================================================' -ForegroundColor White
    Write-Host '  ERGEBNIS' -ForegroundColor White
    Write-Host '==================================================================' -ForegroundColor White
    foreach ($c in (Get-CategoryStatus)) {
        Write-Host ('  {0,-24}' -f $c.Category) -NoNewline
        Write-Host ('{0,-12}' -f $c.Status) -ForegroundColor $c.Color -NoNewline
        $t = [string]$c.Top
        if ($t.Length -gt 70) { $t = $t.Substring(0, 67) + '...' }
        Write-Host $t -ForegroundColor DarkGray
    }
    Write-Host ''
    Write-Host '  Was bremst am wahrscheinlichsten? (sortiert nach Wahrscheinlichkeit)' -ForegroundColor White
    $rank = Get-Ranking
    if ($rank.Count -eq 0) { Write-Host '  Keine auffälligen Engpässe gefunden.' -ForegroundColor Green }
    $i = 0
    foreach ($f in $rank) {
        $i++
        Write-Host ('  {0,2}. ' -f $i) -NoNewline
        Write-Host ('[{0}] ' -f (Get-SevLabel $f.Severity)) -ForegroundColor (Get-SevColor $f.Severity) -NoNewline
        Write-Host $f.Title
        if ($f.Recommendation) {
            $rec = [string]$f.Recommendation
            if ($rec.Length -gt 220) { $rec = $rec.Substring(0, 217) + '...' }
            Write-Host ('      -> {0}' -f $rec) -ForegroundColor DarkGray
        }
    }
    if ($script:Errors.Count -gt 0) {
        Write-Host ''
        Write-Host ('  {0} Teil-Abfrage(n) nicht möglich (Details im Bericht).' -f $script:Errors.Count) -ForegroundColor DarkYellow
    }
    Write-Host ''
    Write-Host ('  Berichte: {0}' -f $OutDir) -ForegroundColor White
    Write-Host '  Schick die Datei "Bericht.md" an Claude, um die Ergebnisse gemeinsam auszuwerten.' -ForegroundColor White
    Write-Host ''
}

function ConvertTo-MdCell {
    param($v)
    if ($null -eq $v) { return '' }
    if ($v -is [bool]) { if ($v) { return 'ja' } else { return 'nein' } }
    return (([string]$v) -replace '\|', '\|' -replace "`r?`n", ' ')
}

function ConvertTo-MdTable {
    param($Rows, [string[]]$Props, [string[]]$Headers)
    $rows = @(@($Rows) | Where-Object { $null -ne $_ })
    if ($rows.Count -eq 0) { return "_keine Einträge_`n" }
    if (-not $Headers) { $Headers = $Props }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('| ' + ($Headers -join ' | ') + ' |')
    [void]$sb.AppendLine('|' + ((@($Headers | ForEach-Object { '---' })) -join '|') + '|')
    foreach ($r in $rows) {
        $vals = foreach ($p in $Props) { ConvertTo-MdCell $r.$p }
        [void]$sb.AppendLine('| ' + ($vals -join ' | ') + ' |')
    }
    return $sb.ToString()
}

function New-MarkdownReport {
    param($D)
    $sb = New-Object System.Text.StringBuilder
    $L = { param($t) [void]$sb.AppendLine($t) }
    $M = $D.Meta; $sys = $D.System; $S = $D.Sampling

    & $L '# PC-Leistungsdiagnose'
    & $L ''
    & $L ('Erstellt {0} mit PerfDiag {1} · Messdauer {2} s · Administrator: {3} · {4}' -f $M.Created, $M.Version, $M.MeasuredSeconds, $(if ($M.IsAdmin) { 'ja' } else { 'nein (eingeschränkt)' }), $M.Mode)
    & $L ''
    & $L ('**System:** {0} (Build {1}) · {2} · {3} Kerne/{4} Threads · {5} GB RAM · {6} {7}' -f $sys.OS, $sys.Build, $sys.CPU, $sys.Cores, $sys.LogicalProcessors, $sys.RamTotalGB, $sys.Manufacturer, $sys.Model)
    & $L ''
    & $L '## Ergebnis auf einen Blick'
    & $L ''
    & $L '| Kategorie | Status | Wichtigster Befund |'
    & $L '|---|---|---|'
    foreach ($c in (Get-CategoryStatus)) { & $L ('| {0} | {1} {2} | {3} |' -f $c.Category, $c.Icon, $c.Status, (ConvertTo-MdCell $c.Top)) }
    & $L ''
    & $L '## Was bremst am wahrscheinlichsten?'
    & $L ''
    $rank = Get-Ranking
    if ($rank.Count -eq 0) { & $L '_Keine auffälligen Engpässe gefunden._' }
    $i = 0
    foreach ($f in $rank) {
        $i++
        & $L ('{0}. {1} **{2}** (Score {3}, {4})' -f $i, (Get-SevIcon $f.Severity), $f.Title, $f.Score, $f.Category)
        if ($f.Detail) { & $L ('   - {0}' -f $f.Detail) }
        if ($f.Recommendation) { & $L ('   - **Empfehlung:** {0}' -f $f.Recommendation) }
    }
    & $L ''
    & $L '## Alle Befunde nach Kategorie'
    foreach ($cat in $script:Categories) {
        $fs = @($script:Findings | Where-Object { $_.Category -eq $cat } | Sort-Object @{ Expression = 'Severity'; Descending = $true }, @{ Expression = 'Score'; Descending = $true })
        if ($fs.Count -eq 0) { continue }
        & $L ''
        & $L ('### {0}' -f $cat)
        & $L ''
        foreach ($f in $fs) {
            & $L ('- {0} **{1}**' -f (Get-SevIcon $f.Severity), $f.Title)
            if ($f.Detail) { & $L ('  - {0}' -f $f.Detail) }
            if ($f.Recommendation) { & $L ('  - Empfehlung: {0}' -f $f.Recommendation) }
        }
    }

    & $L ''
    & $L '---'
    & $L '# Anhang: Messdaten'
    & $L ''
    & $L '## System'
    & $L ''
    $sysRows = @(
        @('Windows', ('{0} {1} (Build {2})' -f $sys.OS, $sys.Version, $sys.Build)),
        @('Gerät', ('{0} {1}{2}' -f $sys.Manufacturer, $sys.Model, $(if ($sys.IsLaptop) { ' (Laptop)' } else { '' }))),
        @('BIOS', $sys.BIOS),
        @('CPU', ('{0} ({1} Kerne / {2} Threads, {3} MHz)' -f $sys.CPU, $sys.Cores, $sys.LogicalProcessors, $sys.CpuMaxMHz)),
        @('Grafik', ((@($sys.GPU) | Where-Object { $_ } | ForEach-Object { '{0} (Treiber {1}, {2})' -f $_.Name, $_.DriverVersion, $_.DriverDate }) -join '; ')),
        @('Laufzeit seit Neustart', ('{0} h (seit {1})' -f $sys.UptimeHours, $sys.LastBoot)),
        @('Schnellstart', $sys.FastStartup),
        @('Energieplan', ('{0} · Modus Netz: {1} · Akku: {2}' -f $sys.PowerPlan, $sys.PowerModeAC, $sys.PowerModeDC)),
        @('Akku', $(if ($sys.HasBattery) { 'vorhanden, Akkubetrieb: {0}, {1} %' -f $(if ($sys.OnBattery) { 'ja' } else { 'nein' }), $sys.BatteryPct } else { 'keiner' })),
        @('VBS / HVCI', ('{0} / {1}' -f $sys.VBS, $sys.HVCI)),
        @('Neustart ausstehend', $sys.PendingReboot),
        @('PowerShell', ('{0} (64-Bit: {1})' -f $sys.PSVersion, $sys.Is64BitProcess))
    )
    & $L '| Eigenschaft | Wert |'
    & $L '|---|---|'
    foreach ($r in $sysRows) { & $L ('| {0} | {1} |' -f $r[0], (ConvertTo-MdCell $r[1])) }

    if ($S -and $S.Available) {
        & $L ''
        & $L ('## Live-Messung ({0} Sekunden{1})' -f $S.SamplesTaken, $(if ($S.EndedEarly) { ', vorzeitig beendet' } else { '' }))
        & $L ''
        $labels = [ordered]@{
            cpu_total = 'CPU gesamt (%)'; cpu_priv = 'CPU Kernel-Anteil (%)'; cpu_dpc = 'DPC-Zeit gesamt (%)'; cpu_int = 'Interrupt-Zeit gesamt (%)'
            core_dpc_max = 'DPC-Zeit höchster Kern (%)'; core_int_max = 'Interrupt-Zeit höchster Kern (%)'; dpc_rate = 'DPCs/s'; int_rate = 'Interrupts/s'
            cpu_perf = 'CPU-Leistung (% von Nenntakt)'; cpu_freq_pct = 'CPU-Frequenz (% von Max)'; run_queue = 'CPU-Warteschlange'; ctx_switch = 'Kontextwechsel/s'
            lag_max_ms = 'Größter Aussetzer je Sekunde (ms)'; mem_avail_mb = 'RAM verfügbar (MB)'; mem_commit_pct = 'Zugesichert (%)'; mem_pages_in = 'Seiten eingelesen/s'
            mem_page_reads = 'Lesevorgänge Auslagerung/s'; mem_faults = 'Seitenfehler/s'; mem_npp_mb = 'Non-Paged Pool (MB)'; mem_pp_mb = 'Paged Pool (MB)'
            pagefile_pct = 'Auslagerungsdatei belegt (%)'; disk_lat_max_ms = 'Disk-Latenz langsamstes Laufwerk (ms)'; disk_busy_max = 'Disk aktiv höchstes Laufwerk (%)'
            gpu_3d_pct = 'GPU 3D-Auslastung (%)'; gpu_vram_mb = 'GPU VRAM belegt (MB)'
        }
        & $L '| Kennzahl | Ø | Median | P95 | Max |'
        & $L '|---|---|---|---|---|'
        foreach ($k in $labels.Keys) {
            $st = $S.Counters.$k
            if (-not $st) { continue }
            & $L ('| {0} | {1:N1} | {2:N1} | {3:N1} | {4:N1} |' -f $labels[$k], [double]$st.Avg, [double]$st.P50, [double]$st.P95, [double]$st.Max)
        }
        & $L ''
        & $L '### Laufwerke (live)'
        & $L ''
        & $L (ConvertTo-MdTable $S.Disks @('Instance', 'LatAvgMs', 'LatP95Ms', 'LatMaxMs', 'BusyAvgPct', 'BusyP95Pct', 'QueueAvg', 'QueueMax', 'MBsAvg', 'MBsMax') @('Laufwerk', 'Ø ms', 'P95 ms', 'Max ms', 'Ø aktiv %', 'P95 aktiv %', 'Ø Warteschl.', 'Max Warteschl.', 'Ø MB/s', 'Max MB/s'))
        & $L '### Prozesse nach CPU (Anteil an der gesamten CPU)'
        & $L ''
        & $L (ConvertTo-MdTable @($S.TopCpu | Select-Object -First 15) @('Name', 'AvgPct', 'MaxPct') @('Prozess', 'Ø %', 'Max %'))
        & $L '### Prozesse nach Datenträger-/Netz-I/O'
        & $L ''
        & $L (ConvertTo-MdTable @($S.TopIo | Select-Object -First 10) @('Name', 'AvgMBs', 'MaxMBs') @('Prozess', 'Ø MB/s', 'Max MB/s'))
    }
    elseif ($S) {
        & $L ''
        & $L '_Live-Messung nicht verfügbar (siehe Fehlerliste)._'
    }
    if ($S -and $S.Stalls) {
        $st = $S.Stalls
        & $L ''
        & $L '## Haenger (System-Aussetzer)'
        & $L ''
        & $L ('Messthread-Durchläufe: {0} · ≥ 50 ms: {1} · ≥ 100 ms: {2} · ≥ 250 ms: {3} · ≥ 1 s: {4} · längster: {5} ms · Summe: {6} ms · wegen .NET-GC ignoriert: {7}' -f `
                $st.Iterations, $st.Over50, $st.Over100, $st.Over250, $st.Over1000, $st.MaxGapMs, $st.TotalStallMs, $st.GcSkipped)
        & $L ''
        if ((Get-Count $st.Events) -gt 0) { & $L (ConvertTo-MdTable $st.Events @('Zeit', 'Ms') @('Zeitpunkt', 'Dauer ms')) }
    }
    if ($S -and (Get-Count $S.Marks) -gt 0) {
        & $L '## Markierte Momente (von dir per Tastenkombination gesetzt)'
        & $L ''
        foreach ($mk in @($S.Marks)) {
            $fok = $(if ($mk.Fokus) { ' · Aktives Fenster: {0}' -f (ConvertTo-MdCell $mk.Fokus) } else { '' })
            & $L ('### Markierung {0}{1} (die 5 Sekunden davor)' -f $mk.Zeit, $fok)
            & $L ''
            & $L (ConvertTo-MdTable $mk.Kontext @('Zeit', 'CPU', 'GPU', 'DPCKern', 'IntKern', 'DiskMs', 'DiskAktiv', 'RAMfreiMB', 'SeitenEin', 'HaengerMs', 'TopCPU', 'TopIO') @('Zeit', 'CPU %', 'GPU %', 'DPC Kern %', 'Int Kern %', 'Disk ms', 'Disk aktiv %', 'RAM frei MB', 'Seiten/s', 'Hänger ms', 'Top CPU', 'Top I/O'))
        }
    }
    if ($S -and (Get-Count $S.BadSeconds) -gt 0) {
        & $L ('## Kritische Sekunden ({0} insgesamt, max. 40 gezeigt)' -f (Get-Count $S.BadSeconds))
        & $L ''
        $bc = $S.BadSecondCounts
        if ($bc) { & $L ('Anzahl nach Grund: CPU {0} · GPU {1} · DPC {2} · Interrupt {3} · Disk {4} · Auslagerung {5} · Hänger {6}' -f $bc.CPU, ([int]$bc.GPU), $bc.DPC, $bc.Interrupt, $bc.Disk, $bc.Paging, $bc.Haenger); & $L '' }
        & $L (ConvertTo-MdTable @($S.BadSeconds | Select-Object -First 40) @('Zeit', 'Gruende', 'TopCPU', 'TopIO') @('Zeit', 'Gründe', 'Top CPU', 'Top I/O'))
    }

    $mem = $D.Memory
    if ($mem) {
        & $L '## Arbeitsspeicher'
        & $L ''
        & $L ('Gesamt {0} GB · frei {1} GB · zugesichert {2} / {3} GB · Auslagerung automatisch: {4} · Speicherkomprimierung: {5}' -f $mem.TotalGB, $mem.FreeGB, $mem.CommitUsedGB, $mem.CommitLimitGB, $mem.AutoPagefile, $mem.MemoryCompression)
        & $L ''
        & $L (ConvertTo-MdTable $mem.PageFiles @('Path', 'SizeMB', 'CurrentMB', 'PeakMB') @('Auslagerungsdatei', 'Größe MB', 'Belegt MB', 'Spitze MB'))
        & $L (ConvertTo-MdTable $mem.Modules @('Slot', 'SizeGB', 'SpeedMHz', 'ConfiguredMHz', 'Manufacturer', 'PartNumber') @('Steckplatz', 'GB', 'MHz', 'Konfig. MHz', 'Hersteller', 'Teilenummer'))
    }
    $P = $D.Processes
    if ($P) {
        & $L ('## Prozesse ({0} laufend)' -f $P.ProcessCount)
        & $L ''
        & $L '### Größte Speicherverbraucher (zusammengefasst nach Name)'
        & $L ''
        & $L (ConvertTo-MdTable $P.TopRam @('Name', 'Instances', 'PrivateMB', 'WorkingSetMB', 'Handles', 'Threads') @('Prozess', 'Anzahl', 'Privat MB', 'Arbeitssatz MB', 'Handles', 'Threads'))
        if ((Get-Count $P.Browsers) -gt 0) {
            & $L '### Browser'
            & $L ''
            & $L (ConvertTo-MdTable $P.Browsers @('Name', 'Instances', 'PrivateMB', 'RamSharePct', 'CpuAvgPct', 'CpuMaxPct', 'IoAvgMBs') @('Browser', 'Prozesse', 'RAM MB', 'RAM-Anteil %', 'Ø CPU %', 'Max CPU %', 'Ø I/O MB/s'))
        }
        if ((Get-Count $P.HighHandles) -gt 0) {
            & $L '### Prozesse mit sehr vielen Handles'
            & $L ''
            & $L (ConvertTo-MdTable $P.HighHandles @('Name', 'Id', 'Handles', 'PrivateMB'))
        }
    }
    $Dk = $D.Disks
    if ($Dk) {
        & $L '## Laufwerke'
        & $L ''
        & $L (ConvertTo-MdTable $Dk.Physical @('DeviceId', 'Drives', 'Name', 'MediaType', 'BusType', 'Health', 'Status', 'SizeGB', 'IsSystemDisk') @('Nr.', 'LW', 'Modell', 'Typ', 'Bus', 'Zustand', 'Status', 'GB', 'System'))
        & $L (ConvertTo-MdTable $Dk.Reliability @('DeviceId', 'Name', 'TemperatureC', 'TemperatureMaxC', 'WearPct', 'ReadErrorsUncorrected', 'WriteErrorsUncorrected', 'PowerOnHours') @('Nr.', 'Modell', 'Temp °C', 'Max °C', 'Verschleiß %', 'Lesefehler unkorr.', 'Schreibfehler unkorr.', 'Betriebsstunden'))
        & $L (ConvertTo-MdTable $Dk.Volumes @('Drive', 'Label', 'FileSystem', 'SizeGB', 'FreeGB', 'FreePct') @('LW', 'Name', 'Dateisystem', 'GB', 'frei GB', 'frei %'))
        & $L ('TRIM deaktiviert: {0}' -f (ConvertTo-MdCell $Dk.TrimDisabled))
        & $L ''
    }
    $E = $D.Events
    if ($E) {
        & $L ('## Ereignisprotokolle (letzte {0} Tage)' -f $E.Days)
        & $L ''
        & $L ('System: {0} Warnungen/Fehler, gruppiert (bekannte Ereignisse zuerst, max. 30):' -f $E.SystemTotal)
        & $L ''
        & $L (ConvertTo-MdTable @($E.SystemGroups | Select-Object -First 30) @('Provider', 'Id', 'Hits', 'Last', 'Meaning', 'Sample') @('Quelle', 'ID', 'Anzahl', 'Zuletzt', 'Bedeutung', 'Meldung (gekürzt)'))
        & $L '### Hängende Programme (Application Hang)'
        & $L ''
        & $L (ConvertTo-MdTable $E.AppHangs @('App', 'Hits', 'Last') @('Programm', 'Anzahl', 'Zuletzt'))
        & $L '### Abstürze (Application Error)'
        & $L ''
        & $L (ConvertTo-MdTable $E.AppCrashes @('App', 'Hits', 'Last', 'Modules') @('Programm', 'Anzahl', 'Zuletzt', 'Fehlermodul'))
        if ((Get-Count $E.BootTimes) -gt 0) {
            & $L '### Startzeiten'
            & $L ''
            & $L (ConvertTo-MdTable $E.BootTimes @('Datum', 'Sekunden'))
            & $L (ConvertTo-MdTable $E.BootDegraders @('Art', 'Name', 'Hits', 'AvgDelayMs') @('Art', 'Name', 'Anzahl', 'Ø Verzögerung ms'))
        }
    }
    $X = $D.Explorer
    if ($X) {
        & $L '## Explorer & Dateien'
        & $L ''
        & $L '### Netzlaufwerke'
        & $L ''
        & $L (ConvertTo-MdTable $X.NetworkDrives @('Drive', 'Remote', 'Reachable', 'Ms', 'Status') @('LW', 'Ziel', 'erreichbar', 'ms', 'Status'))
        & $L '### Ordner-Test'
        & $L ''
        & $L (ConvertTo-MdTable $X.Folders @('Name', 'Path', 'Entries', 'Ms', 'Status', 'OneDrive') @('Ordner', 'Pfad', 'Einträge', 'ms', 'Status', 'OneDrive'))
        if ($X.WriteTest) { & $L ('Schreibtest (20 x 4 KB mit WriteThrough in {0}): Median {1} ms · P95 {2} ms · Max {3} ms' -f $X.WriteTest.Folder, $X.WriteTest.MedianMs, $X.WriteTest.P95Ms, $X.WriteTest.MaxMs); & $L '' }
        & $L '### Kontextmenü-Erweiterungen (nicht von Microsoft)'
        & $L ''
        & $L (ConvertTo-MdTable $X.ContextMenuHandlers @('Name', 'Company', 'Where', 'Missing', 'Dll') @('Name', 'Firma', 'Bereich', 'DLL fehlt', 'Datei'))
        & $L ('Symbol-Overlays: {0} · Cloud-Sync: {1} · Windows-Suche: {2}' -f (Get-Count $X.OverlayHandlers), ((@($X.CloudSync)) -join ', '), $X.SearchService)
        & $L ''
    }
    $W = $D.Software
    if ($W) {
        & $L '## Software & Autostart'
        & $L ''
        & $L (ConvertTo-MdTable $W.Antivirus @('Name', 'Enabled', 'UpToDate') @('Virenschutz', 'aktiv', 'aktuell'))
        if ($W.Defender) { & $L ('Defender: Modus {0}, Echtzeitschutz {1}' -f $W.Defender.Mode, (ConvertTo-MdCell $W.Defender.RealTime)); & $L '' }
        if ((Get-Count $W.Minifilters) -gt 0) {
            & $L '### Aktive Dateisystem-Minifilter (Drittanbieter)'
            & $L ''
            & $L (ConvertTo-MdTable $W.Minifilters @('Filter', 'Firma', 'Instanzen', 'Altitude') @('Filter-Treiber', 'Firma', 'Instanzen', 'Altitude'))
        }
        & $L ('### Autostart ({0} aktiv)' -f $W.StartupEnabledCount)
        & $L ''
        & $L (ConvertTo-MdTable $W.Startup @('Name', 'Aktiv', 'Ort', 'Befehl'))
        if ((Get-Count $W.KnownTools) -gt 0) {
            & $L '### Bekannte Bremsen / Latenz-Verursacher'
            & $L ''
            & $L (ConvertTo-MdTable $W.KnownTools @('Name', 'Art', 'Gefunden'))
        }
        & $L '### Laufende Dienste von Drittanbietern'
        & $L ''
        & $L (ConvertTo-MdTable $W.ThirdPartyServices @('Name', 'Anzeigename', 'Firma'))
        if ($W.Autoruns) {
            & $L '### Sysinternals Autoruns'
            & $L ''
            if ($W.Autoruns.Found) {
                & $L ('{0} aktive Nicht-Microsoft-Einträge.' -f $W.Autoruns.Total)
                & $L ''
                & $L (ConvertTo-MdTable $W.Autoruns.ByCategory @('Kategorie', 'Anzahl'))
                & $L '**Unsigniert / nicht verifiziert:**'
                & $L ''
                & $L (ConvertTo-MdTable $W.Autoruns.Unsigned @('Kategorie', 'Eintrag', 'Firma', 'Pfad'))
                & $L '**Anmeldung, Dienste, Aufgaben, Explorer, Treiber:**'
                & $L ''
                & $L (ConvertTo-MdTable $W.Autoruns.Entries @('Kategorie', 'Eintrag', 'Firma', 'Signatur'))
            }
            if ($W.Autoruns.Note) { & $L ('_{0}_' -f $W.Autoruns.Note); & $L '' }
        }
    }
    if ($D.Pool) {
        & $L ('## Kernel-Speicher je Pool-Tag (gesamt: Non-Paged {0} MB, Paged {1} MB)' -f $D.Pool.TotalNonPagedMB, $D.Pool.TotalPagedMB)
        & $L ''
        & $L (ConvertTo-MdTable $D.Pool.TopNonPaged @('Tag', 'NonPagedMB', 'PagedMB', 'NonPagedOffen', 'Treiber') @('Tag', 'Non-Paged MB', 'Paged MB', 'offene Allokationen', 'Treiber (Kandidaten)'))
        & $L (ConvertTo-MdTable $D.Pool.TopPaged @('Tag', 'PagedMB', 'NonPagedMB', 'PagedOffen', 'Treiber') @('Tag', 'Paged MB', 'Non-Paged MB', 'offene Allokationen', 'Treiber (Kandidaten)'))
    }
    $Dr = $D.Drivers
    if ($Dr) {
        & $L '## Treiber & Geräte'
        & $L ''
        & $L '### Geräte mit Problemen'
        & $L ''
        & $L (ConvertTo-MdTable $Dr.ProblemDevices @('Name', 'Klasse', 'Fehlercode'))
        & $L '### Netzwerkadapter'
        & $L ''
        & $L (ConvertTo-MdTable $Dr.NetAdapters @('Name', 'Adapter', 'Status', 'Tempo', 'Anbieter', 'Version', 'Datum'))
        & $L '### Aktive Kernel-Treiber von Drittanbietern (typische DPC-Verdächtige)'
        & $L ''
        & $L (ConvertTo-MdTable $Dr.ThirdPartyKernel @('Datei', 'Firma', 'Beschreibung', 'Dateidatum'))
        & $L '### Treiber wichtiger Geräteklassen'
        & $L ''
        & $L (ConvertTo-MdTable $Dr.Devices @('Klasse', 'Gerät', 'Anbieter', 'Version', 'Datum'))
    }
    $In = $D.Input
    if ($In) {
        & $L '## Tastatur-Einstellungen'
        & $L ''
        & $L ('Anschlagverzögerung (Filtertasten): {0} (Flags {1}, Verzögerung {2} ms) · Einrastfunktion: {3} · Wiederholverzögerung: {4} (0-3) · Wiederholrate: {5} (0-31) · Sprachen: {6}' -f `
                (ConvertTo-MdCell $In.FilterKeysOn), $In.FilterKeysFlags, $In.FilterDelayMs, (ConvertTo-MdCell $In.StickyKeysOn), $In.KeyboardDelay, $In.KeyboardSpeed, ((@($In.Languages)) -join ', '))
        & $L ''
    }
    if ($D.Trace) {
        & $L '## WPR-Aufzeichnung'
        & $L ''
        & $L ('ETL-Datei: {0} (mit Windows Performance Analyzer öffnen)' -f $D.Trace.Etl)
        if ($D.Trace.DpcIsrExcerpt) { & $L ''; & $L '```'; & $L $D.Trace.DpcIsrExcerpt; & $L '```' }
        elseif ($D.Trace.Etl) { & $L ''; & $L '_xperf (Windows ADK) nicht gefunden - kein automatischer DPC/ISR-Bericht._' }
        & $L ''
    }
    $errs = @($D.CollectionErrors)
    & $L ('## Nicht verfügbare Daten ({0})' -f $errs.Count)
    & $L ''
    if ($errs.Count -eq 0) { & $L '_Alle Abfragen erfolgreich._' }
    foreach ($er in $errs) { & $L ('- {0}' -f (ConvertTo-MdCell $er)) }
    & $L ''
    & $L '---'
    & $L '_Tipp: Diese Datei kannst du Claude schicken, um die Ergebnisse auszuwerten. Benutzer- und Computername sind anonymisiert (abschaltbar mit -NoAnonymize)._'
    return $sb.ToString()
}

function Protect-Text {
    param([string]$Text, [bool]$Enabled)
    if (-not $Enabled -or -not $Text) { return $Text }
    $t = [regex]::Replace($Text, '(?i)(\\{1,2}Users\\{1,2})[^\\"/|<>\r\n]+', '$1<USER>')
    $t = [regex]::Replace($t, '(?i)(\\{1,2}Benutzer\\{1,2})[^\\"/|<>\r\n]+', '$1<USER>')
    foreach ($n in @($env:USERNAME, $env:COMPUTERNAME)) {
        if ($n -and $n.Length -ge 4) {
            $rep = $(if ($n -eq $env:COMPUTERNAME) { '<PC>' } else { '<USER>' })
            $t = [regex]::Replace($t, ('(?i)\b{0}\b' -f [regex]::Escape($n)), $rep)
        }
    }
    return $t
}

function Write-Reports {
    param($D, [string]$OutDir, $Timeline, [bool]$Anonymize)
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $paths = [ordered]@{}
    try {
        $md = Protect-Text (New-MarkdownReport $D) $Anonymize
        $p = Join-Path $OutDir 'Bericht.md'
        [IO.File]::WriteAllText($p, $md, $utf8)
        $paths.Markdown = $p
    } catch { Write-Host ('Markdown-Bericht fehlgeschlagen: {0}' -f $_.Exception.Message) -ForegroundColor Red }
    try {
        $export = [ordered]@{}
        foreach ($k in $D.Keys) { $export[$k] = $D[$k] }
        $export['Findings'] = $script:Findings.ToArray()
        $json = Protect-Text ($export | ConvertTo-Json -Depth 8) $Anonymize
        $p = Join-Path $OutDir 'daten.json'
        [IO.File]::WriteAllText($p, $json, $utf8)
        $paths.Json = $p
    } catch { Write-Host ('JSON-Export fehlgeschlagen: {0}' -f $_.Exception.Message) -ForegroundColor Red }
    if ($Timeline -and $Timeline.Count -gt 0) {
        try {
            $p = Join-Path $OutDir 'zeitverlauf.csv'
            $Timeline | ForEach-Object { [pscustomobject]$_ } | Export-Csv -Path $p -NoTypeInformation -Delimiter ';' -Encoding UTF8
            $paths.Csv = $p
        } catch { Write-Host ('CSV-Export fehlgeschlagen: {0}' -f $_.Exception.Message) -ForegroundColor Red }
    }
    return $paths
}
#endregion

#region ---------------------------------------------------------------- Main
$isAdmin = Test-Admin
$anonymize = -not $NoAnonymize

Write-Host ''
Write-Host ('  PerfDiag {0} - Leistungs- und Flaschenhals-Analyse' -f $script:Version) -ForegroundColor White
Write-Host '  ---------------------------------------------------' -ForegroundColor DarkGray

# Re-Auswertung einer frueheren Messung
if ($FromJson) {
    try {
        $raw = Get-Content -LiteralPath $FromJson -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
        $D = [ordered]@{}
        foreach ($prop in $raw.psobject.Properties) { if ($prop.Name -ne 'Findings') { $D[$prop.Name] = $prop.Value } }
        if (-not $D.Contains('CollectionErrors')) { $D['CollectionErrors'] = @() }
        foreach ($e in @($D.CollectionErrors)) { if ($e) { $script:Errors.Add([string]$e) } }
        $D['Meta'] | Add-Member -NotePropertyName Mode -NotePropertyValue 'Neu-Auswertung' -Force
        Invoke-Analysis $D
        if (-not $OutputDir) { $OutputDir = Join-Path (Split-Path -Parent (Resolve-Path -LiteralPath $FromJson)) 'neu_ausgewertet' }
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        $paths = Write-Reports $D $OutputDir $null $false
        Write-ConsoleReport $D $OutputDir
    } catch { Write-Host ('Neu-Auswertung fehlgeschlagen: {0}' -f $_.Exception.Message) -ForegroundColor Red }
    return
}

if ($env:OS -ne 'Windows_NT') { Write-Host '  Hinweis: Dieses Skript ist für Windows gedacht - die meisten Abfragen werden fehlschlagen.' -ForegroundColor Yellow }

# Administratorrechte anbieten
if (-not $isAdmin -and -not $NoElevate) {
    Write-Host '  Ohne Administratorrechte fehlen u. a. S.M.A.R.T.-Werte, Boot-Diagnose und Autoruns.' -ForegroundColor Yellow
    $answer = ''
    try { $answer = Read-Host '  Als Administrator neu starten? [J/n]' } catch {}
    if ($answer -eq '' -or $answer -match '^(j|y)') {
        if ($PSCommandPath) {
            $argList = New-Object System.Collections.Generic.List[string]
            foreach ($a in @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))) { $argList.Add($a) }
            foreach ($kv in $PSBoundParameters.GetEnumerator()) {
                if ($kv.Value -is [System.Management.Automation.SwitchParameter]) { if ($kv.Value.IsPresent) { $argList.Add('-' + $kv.Key) } }
                else { $argList.Add('-' + $kv.Key); $argList.Add(('"{0}"' -f $kv.Value)) }
            }
            $argList.Add('-NoElevate')
            try {
                $exe = (Get-Process -Id $PID).Path
                Start-Process -FilePath $exe -ArgumentList $argList.ToArray() -Verb RunAs | Out-Null
                Write-Host '  Ein neues Fenster mit Administratorrechten wurde geöffnet.' -ForegroundColor Green
                return
            } catch { Write-Host '  Neustart als Administrator abgebrochen - fahre ohne Adminrechte fort.' -ForegroundColor Yellow }
        }
        else { Write-Host '  Skriptpfad unbekannt - bitte die Konsole selbst "Als Administrator" öffnen.' -ForegroundColor Yellow }
    }
}

if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
    Write-Host '  Hinweis: 32-Bit-PowerShell erkannt - bitte die normale (64-Bit) PowerShell verwenden.' -ForegroundColor Yellow
}

# Ausgabeordner
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $OutputDir) {
    $desk = $null
    try { $desk = [Environment]::GetFolderPath('Desktop') } catch {}
    if (-not $desk -or -not (Test-Path -LiteralPath $desk)) { $desk = $env:TEMP }
    if (-not $desk) { $desk = (Get-Location).Path }
    $OutputDir = Join-Path $desk ('PerfDiag_{0}' -f $stamp)
}
try { New-Item -ItemType Directory -Path $OutputDir -Force -ErrorAction Stop | Out-Null }
catch {
    $OutputDir = Join-Path ([IO.Path]::GetTempPath()) ('PerfDiag_{0}' -f $stamp)
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Host ('  Administrator: {0} · Messdauer: {1} s · Ausgabe: {2}' -f $(if ($isAdmin) { 'ja' } else { 'nein' }), $Seconds, $OutputDir) -ForegroundColor DarkGray
if ($Trace -and $Seconds -gt 300) {
    Write-Host '  -Trace ist nur bis 300 s sinnvoll (Dateigröße) und wird ignoriert.' -ForegroundColor Yellow
    $Trace = $false
}

$nativeOk = $false
if ($env:OS -eq 'Windows_NT') {
    if ('PerfDiagV1.Pdh' -as [type]) { $nativeOk = $true }
    else {
        try { Add-Type -TypeDefinition $script:NativeCode -Language CSharp -IgnoreWarnings -ErrorAction Stop; $nativeOk = $true }
        catch { Add-Err 'C#-Hilfsmodul' $_ }
    }
}

$D = [ordered]@{
    Meta = [pscustomobject]@{
        Tool = 'PerfDiag'; Version = $script:Version; Created = (Get-Date -Format 'yyyy-MM-dd HH:mm')
        IsAdmin = $isAdmin; MeasuredSeconds = $Seconds; EventDays = $EventDays; Mode = 'Messung'
    }
}
Write-Host ''
Write-Host '  [0/3] Systeminformationen ...' -ForegroundColor White
$D.System = Invoke-Collector 'System' { Get-SystemInfo }
if (-not $D.System) { $D.System = [ordered]@{ LogicalProcessors = [Environment]::ProcessorCount } }

$traceOn = $false
if ($Trace) { $traceOn = Start-WprTrace $isAdmin }

Write-Host ''
Write-Host ('  [1/3] Live-Messung über {0} Sekunden' -f $Seconds) -ForegroundColor White
$smp = $null
try { $smp = Invoke-Sampling -Seconds $Seconds -LogicalCpu ([int]$D.System.LogicalProcessors) -NativeOk $nativeOk }
catch { Add-Err 'Live-Messung' $_ }
if ($smp) {
    $D.Sampling = $smp.Result
    $D.Meta.MeasuredSeconds = $smp.Result.SamplesTaken
}
if ($traceOn) { $D.Trace = Stop-WprTrace $OutputDir }

Write-Host ''
Write-Host '  [2/3] Systemzustand wird gesammelt ...' -ForegroundColor White
$D.Memory = Invoke-Collector 'Arbeitsspeicher' { Get-MemoryInfo }
if (-not $D.Memory) { $D.Memory = [ordered]@{} }
$D.Processes = Invoke-Collector 'Prozesse' { Get-ProcessInfo -Sampling $D.Sampling -TotalRamGB ([double]$D.Memory.TotalGB) }
$D.Disks = Invoke-Collector 'Laufwerke & S.M.A.R.T.' { Get-DiskInfo -IsAdmin $isAdmin }
$D.Events = Invoke-Collector ('Ereignisprotokolle ({0} Tage)' -f $EventDays) { Get-EventInfo -Days $EventDays -IsAdmin $isAdmin }
$D.Explorer = Invoke-Collector 'Explorer, Netzlaufwerke, Ordner' { Get-ExplorerInfo -NativeOk $nativeOk -ProcInfo $D.Processes }
$D.Software = Invoke-Collector 'Virenschutz, Autostart, Dienste' { Get-SoftwareInfo -IsAdmin $isAdmin -AutorunsHint $AutorunsPath -SkipAutoruns ([bool]$SkipAutoruns) -WorkDir $OutputDir -ProcInfo $D.Processes }
if ($nativeOk) { $D.Pool = Invoke-Collector 'Kernel-Speicher je Treiber (Pool-Tags)' { Get-PoolInfo } }
if (-not $SkipDrivers) { $D.Drivers = Invoke-Collector 'Treiber & Geräte' { Get-DriverInfo } }
$D.Input = Invoke-Collector 'Tastatur-Einstellungen' { Get-InputInfo }

Write-Host ''
Write-Host '  [3/3] Auswertung ...' -ForegroundColor White
$D.CollectionErrors = $script:Errors.ToArray()
try { Invoke-Analysis $D } catch { Add-Err 'Auswertung' $_; Write-Host ('  Auswertung teilweise fehlgeschlagen: {0}' -f $_.Exception.Message) -ForegroundColor Red }
$D.CollectionErrors = $script:Errors.ToArray()
if ($D.Processes) { $D.Processes.Remove('Names') }

$timeline = $null
if ($smp) { $timeline = $smp.Timeline }
$paths = Write-Reports $D $OutputDir $timeline $anonymize
Write-ConsoleReport $D $OutputDir

if (-not $NoOpen -and $env:OS -eq 'Windows_NT') {
    try { if ($paths.Markdown) { Start-Process notepad.exe -ArgumentList ('"{0}"' -f $paths.Markdown) } } catch {}
    try { Start-Process explorer.exe -ArgumentList ('"{0}"' -f $OutputDir) } catch {}
}
if (-not $NoPause) {
    try { [void](Read-Host '  Fertig. Enter drücken zum Schließen') } catch {}
}
#endregion
