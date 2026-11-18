#Requires -Version 5.1
<#
.SYNOPSIS
    Error code converter (decimal <-> hexadecimal) with GUI and bulk conversion.

.DESCRIPTION
    - Quick conversion (live, as you type) of a single code.
    - Bulk conversion: paste a list, a whole log, or import TXT/CSV/LOG files
      (drag & drop supported). Codes are extracted from the text automatically.
    - Accepts signed decimal (-2145844844), unsigned decimal (2149122452) and hexadecimal
      (0x80190194, &H80190194, or 80190194 when it contains letters A-F).
    - 64-bit values (e.g. FFFFFFFF80190194) are reduced to the lower 32 bits,
      same as the original script.
    - Decodes the HRESULT (Severity / Facility / Code) and shows the error description in English.
    - Descriptions come from every English message table installed on the machine
      (System32\en-US\*.mui), the ConfigMgr/SCCM client and console (when present),
      plus a built-in table. The whole index can be exported to CSV.
    - Filter, CSV export and clipboard copy.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -STA -File .\ConversorCodigosErro.ps1
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Special characters built from char codes, so the file is pure ASCII (no encoding/BOM issues)
$Sym = @{
    Dash  = [string][char]0x2014   # em dash
    LR    = [string][char]0x21C4   # left-right arrows
    Arrow = [string][char]0x2192   # right arrow
    Dot   = [string][char]0x2022   # bullet
}

# ----------------------------------------------------------------------------------------
#  Color palette (Accenture-inspired)
# ----------------------------------------------------------------------------------------

function New-Color([string]$Hex) { [System.Drawing.ColorTranslator]::FromHtml($Hex) }

$Theme = @{
    Purple      = New-Color '#A100FF'   # core purple (primary accent)
    PurpleDark  = New-Color '#7500C0'   # hover / selection
    PurpleDeep  = New-Color '#460073'   # grid header
    PurpleLight = New-Color '#BE82FF'
    PurplePale  = New-Color '#F6EBFF'   # alternating rows
    Black       = New-Color '#000000'
    White       = New-Color '#FFFFFF'
    GrayBg      = New-Color '#F2F2F2'
    GrayText    = New-Color '#5A5A5A'
    GrayLine    = New-Color '#D0D0D0'
    ErrorBg     = New-Color '#FFE3E3'
    ErrorText   = New-Color '#C00000'
    WarnBg      = New-Color '#FFF4CC'
}

# ----------------------------------------------------------------------------------------
#  Native helpers: English FormatMessage + message-table index
# ----------------------------------------------------------------------------------------

if (-not ('ErrorCodeConverterV3.ErrorIndex' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace ErrorCodeConverterV3
{

// FormatMessage with an explicit en-US language id (never falls back to the OS language).
public static class EnglishErrorMessage
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int FormatMessageW(int dwFlags, IntPtr lpSource, int dwMessageId, int dwLanguageId,
                                             StringBuilder lpBuffer, int nSize, IntPtr arguments);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryExW(string lpFileName, IntPtr hFile, int dwFlags);

    private const int FORMAT_MESSAGE_IGNORE_INSERTS  = 0x0200;
    private const int FORMAT_MESSAGE_FROM_HMODULE    = 0x0800;
    private const int FORMAT_MESSAGE_FROM_SYSTEM     = 0x1000;
    private const int LOAD_LIBRARY_AS_DATAFILE       = 0x0002;
    private const int LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x0020;
    private const int LANG_EN_US                     = 0x0409;

    private static readonly Dictionary<string, IntPtr> Modules =
        new Dictionary<string, IntPtr>(StringComparer.OrdinalIgnoreCase);

    public static string FromSystem(int id)
    {
        return Format(FORMAT_MESSAGE_FROM_SYSTEM, IntPtr.Zero, id);
    }

    public static string FromModule(string path, int id)
    {
        IntPtr h;
        if (!Modules.TryGetValue(path, out h))
        {
            h = LoadLibraryExW(path, IntPtr.Zero, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            Modules[path] = h;
        }
        if (h == IntPtr.Zero) return null;
        return Format(FORMAT_MESSAGE_FROM_HMODULE, h, id);
    }

    private static string Format(int source, IntPtr module, int id)
    {
        var sb = new StringBuilder(4096);
        int n = FormatMessageW(source | FORMAT_MESSAGE_IGNORE_INSERTS, module, id, LANG_EN_US, sb, sb.Capacity, IntPtr.Zero);
        return n > 0 ? sb.ToString().Trim() : null;
    }
}

// Reads every RT_MESSAGETABLE resource of a module into one in-memory dictionary.
public static class ErrorIndex
{
    private delegate bool EnumResNameProc(IntPtr hModule, IntPtr lpType, IntPtr lpName, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryExW(string lpFileName, IntPtr hFile, int dwFlags);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FreeLibrary(IntPtr hModule);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool EnumResourceNamesW(IntPtr hModule, IntPtr lpType, EnumResNameProc proc, IntPtr lParam);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindResourceExW(IntPtr hModule, IntPtr lpType, IntPtr lpName, ushort wLanguage);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr FindResourceW(IntPtr hModule, IntPtr lpName, IntPtr lpType);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);
    [DllImport("kernel32.dll")]
    private static extern IntPtr LockResource(IntPtr hResData);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);

    private const int LOAD_LIBRARY_AS_DATAFILE       = 0x0002;
    private const int LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x0020;
    private static readonly IntPtr RT_MESSAGETABLE   = new IntPtr(11);

    public class Entry
    {
        public uint   Id;
        public string Text;
        public string Source;
    }

    private static readonly Dictionary<uint, Entry> Map = new Dictionary<uint, Entry>();
    public static int ModulesWithMessages = 0;
    public static int Count { get { return Map.Count; } }

    public static int AddModule(string path, string sourceName)
    {
        IntPtr h = LoadLibraryExW(path, IntPtr.Zero, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        if (h == IntPtr.Zero) return 0;
        int added = 0;
        try
        {
            EnumResNameProc proc = (m, t, n, p) => { added += ReadTable(h, n, sourceName); return true; };
            EnumResourceNamesW(h, RT_MESSAGETABLE, proc, IntPtr.Zero);
            GC.KeepAlive(proc);
        }
        catch { }
        finally { FreeLibrary(h); }
        if (added > 0) ModulesWithMessages++;
        return added;
    }

    private static int ReadTable(IntPtr h, IntPtr name, string source)
    {
        IntPtr res = FindResourceExW(h, RT_MESSAGETABLE, name, 0x0409);
        if (res == IntPtr.Zero) res = FindResourceW(h, name, RT_MESSAGETABLE);
        if (res == IntPtr.Zero) return 0;

        uint size = SizeofResource(h, res);
        IntPtr hData = LoadResource(h, res);
        if (hData == IntPtr.Zero || size < 4) return 0;
        IntPtr ptr = LockResource(hData);
        if (ptr == IntPtr.Zero) return 0;

        byte[] d = new byte[size];
        Marshal.Copy(ptr, d, 0, (int)size);

        int added = 0;
        int blocks = BitConverter.ToInt32(d, 0);
        for (int b = 0; b < blocks; b++)
        {
            int bo = 4 + b * 12;
            if (bo + 12 > d.Length) break;
            uint low  = BitConverter.ToUInt32(d, bo);
            uint high = BitConverter.ToUInt32(d, bo + 4);
            int  pos  = BitConverter.ToInt32(d, bo + 8);

            for (long id = low; id <= high; id++)
            {
                if (pos < 0 || pos + 4 > d.Length) break;
                int len   = BitConverter.ToUInt16(d, pos);
                int flags = BitConverter.ToUInt16(d, pos + 2);
                if (len < 4 || pos + len > d.Length) break;

                string text;
                if ((flags & 0x1) != 0)      text = Encoding.Unicode.GetString(d, pos + 4, len - 4);
                else if ((flags & 0x2) != 0) text = Encoding.UTF8.GetString(d, pos + 4, len - 4);
                else                         text = Encoding.Default.GetString(d, pos + 4, len - 4);
                text = text.Replace("\0", "").Trim();

                uint key = (uint)id;
                if (text.Length > 2 && !Map.ContainsKey(key))
                {
                    Map[key] = new Entry { Id = key, Text = text, Source = source };
                    added++;
                }
                pos += len;
            }
        }
        return added;
    }

    public static void Add(uint id, string text, string source)
    {
        if (!Map.ContainsKey(id)) Map[id] = new Entry { Id = id, Text = text, Source = source };
    }

    public static Entry Lookup(int id)
    {
        Entry e;
        return Map.TryGetValue(unchecked((uint)id), out e) ? e : null;
    }

    public static int ExportCsv(string path, string sep)
    {
        var keys = new List<uint>(Map.Keys);
        keys.Sort();
        using (var w = new StreamWriter(path, false, new UTF8Encoding(true)))
        {
            w.WriteLine(string.Join(sep, new[] { Q("Hex"), Q("Int32"), Q("UInt32"), Q("Description"), Q("Source") }));
            foreach (var k in keys)
            {
                var e = Map[k];
                string text = e.Text.Replace("\r\n", " ").Replace("\n", " ").Replace("\r", " ");
                w.WriteLine(string.Join(sep, new[] {
                    Q("0x" + k.ToString("X8")), Q(unchecked((int)k).ToString()), Q(k.ToString()), Q(text), Q(e.Source) }));
            }
        }
        return keys.Count;
    }

    private static string Q(string s) { return "\"" + s.Replace("\"", "\"\"") + "\""; }
}

}
'@
}

# ----------------------------------------------------------------------------------------
#  Description sources
# ----------------------------------------------------------------------------------------

$script:Facilities = @{
    0='NULL'; 1='RPC'; 2='DISPATCH'; 3='STORAGE'; 4='ITF'; 7='WIN32'; 8='WINDOWS'; 9='SECURITY/SSPI'
    10='CONTROL'; 11='CERT'; 12='INTERNET'; 13='MEDIASERVER'; 14='MSMQ'; 15='SETUPAPI'; 16='SCARD'
    17='COMPLUS'; 18='AAF'; 19='URT (.NET)'; 20='ACS'; 21='DPLAY'; 22='UMI'; 23='SXS'; 24='WINDOWS_CE'
    25='HTTP / BITS'; 26='USERMODE_COMMONLOG'; 31='USERMODE_FILTER_MANAGER'; 32='BACKGROUNDCOPY'
    33='CONFIGURATION'; 34='STATE_MANAGEMENT'; 35='METADIRECTORY'; 36='WINDOWSUPDATE'
    37='DIRECTORYSERVICE'; 38='GRAPHICS'; 39='SHELL'; 40='TPM_SERVICES'; 41='TPM_SOFTWARE'
    48='PLA'; 49='FVE (BitLocker)'; 50='FWP'; 51='WINRM'; 52='NDIS'; 53='USERMODE_HYPERVISOR'
    54='CMI'; 55='USERMODE_VIRTUALIZATION'; 56='USERMODE_VOLMGR'; 57='BCD'; 58='USERMODE_VHD'
    60='SDIAG'; 61='WEBSERVICES'; 80='WINDOWS_DEFENDER'; 81='OPC'; 112='WINPE'
    208='DELIVERY_OPTIMIZATION'; 1792='WIN32K'
}

$script:DescCache  = @{}
$script:IndexReady = $false
$script:SrsReady   = $false
$script:SrsPath    = $null

# Components queried directly with FormatMessage (also used for Win32 codes such as WinINet 12xxx).
$script:MessageModules = @('wuaueng.dll', 'qmgr.dll', 'winhttp.dll', 'wininet.dll', 'dosvc.dll') |
    ForEach-Object { Join-Path "$env:SystemRoot\System32" $_ } |
    Where-Object { Test-Path -LiteralPath $_ }

# Built-in English texts, used when the English message resources are not installed.
# Win32 codes are stored as 0x0000xxxx.
$script:KnownErrors = @{
    '0x00000000' = 'The operation completed successfully.'
    '0x00000001' = 'Incorrect function.'
    '0x00000002' = 'The system cannot find the file specified.'
    '0x00000003' = 'The system cannot find the path specified.'
    '0x00000005' = 'Access is denied.'
    '0x00000006' = 'The handle is invalid.'
    '0x00000008' = 'Not enough memory resources are available to process this command.'
    '0x0000000E' = 'Not enough memory resources are available to complete this operation.'
    '0x00000020' = 'The process cannot access the file because it is being used by another process.'
    '0x00000057' = 'The parameter is incorrect.'
    '0x00000070' = 'There is not enough space on the disk.'
    '0x000000C1' = '%1 is not a valid Win32 application.'
    '0x00000422' = 'The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.'
    '0x000005B4' = 'This operation returned because the timeout period expired.'
    '0x00000643' = 'Fatal error during installation.'
    '0x00000652' = 'Another installation is already in progress. Complete that installation before proceeding with this install.'
    '0x00000653' = 'This installation package could not be opened. Verify that the package exists and that you can access it.'
    '0x00000669' = 'The requested operation completed successfully. The system will be restarted so the changes can take effect.'
    '0x00000BC2' = 'The requested operation is successful. Changes will not be effective until the system is rebooted.'
    '0x00002EE2' = 'The operation timed out.'
    '0x00002EE7' = 'The server name or address could not be resolved.'
    '0x00002EFD' = 'A connection with the server could not be established.'
    '0x00002EFE' = 'The connection with the server was terminated abnormally.'
    '0x00002F8F' = 'A security error occurred.'
    '0x80004001' = 'Not implemented.'
    '0x80004002' = 'No such interface supported.'
    '0x80004003' = 'Invalid pointer.'
    '0x80004004' = 'Operation aborted.'
    '0x80004005' = 'Unspecified error.'
    '0x8000FFFF' = 'Catastrophic failure.'
    '0x8024000B' = 'WU_E_CALL_CANCELLED: Operation was cancelled.'
    '0x80240016' = 'WU_E_INSTALL_NOT_ALLOWED: Operation tried to install while another installation was in progress or the system was pending a mandatory restart.'
    '0x80240017' = 'WU_E_NOT_APPLICABLE: Operation was not performed because there are no applicable updates.'
    '0x80240022' = 'WU_E_ALL_UPDATES_FAILED: Operation failed for all the updates.'
    '0x8024002E' = 'WU_E_WU_DISABLED: Access to an unmanaged server is not allowed.'
    '0x80240438' = 'WU_E_PT_ENDPOINT_UNREACHABLE: There is no route or network connectivity to the endpoint.'
    '0x80244017' = 'WU_E_PT_HTTP_STATUS_DENIED: Same as HTTP status 401 - the requested resource requires user authentication.'
    '0x80244018' = 'WU_E_PT_HTTP_STATUS_FORBIDDEN: Same as HTTP status 403 - server understood the request, but declined to fulfill it.'
    '0x80244019' = 'WU_E_PT_HTTP_STATUS_NOT_FOUND: Same as HTTP status 404 - the server cannot find the requested URI.'
    '0x8024401C' = 'WU_E_PT_HTTP_STATUS_REQUEST_TIMEOUT: Same as HTTP status 408 - the server timed out waiting for the request.'
    '0x80244022' = 'WU_E_PT_HTTP_STATUS_SERVICE_UNAVAIL: Same as HTTP status 503 - the service is temporarily overloaded.'
    '0x8024402C' = 'WU_E_PT_WINHTTP_NAME_NOT_RESOLVED: The proxy server or target server name cannot be resolved.'
    '0x80246007' = 'WU_E_DM_NOTDOWNLOADED: The update has not been downloaded.'
    '0x80D02002' = 'DO_E_DOWNLOAD_NO_PROGRESS: Download of a file saw no progress within the defined period.'
    '0x87D00324' = 'The application was not detected after installation completed.'
}

function Get-MessageSources {
    <# Every English message-table file on the machine, most relevant first. #>
    $sys      = Join-Path $env:SystemRoot 'System32'
    $priority = @('kernelbase.dll.mui', 'kernel32.dll.mui', 'ntdll.dll.mui', 'wuaueng.dll.mui', 'qmgr.dll.mui',
                  'winhttp.dll.mui', 'wininet.dll.mui', 'dosvc.dll.mui', 'msi.dll.mui')
    $list = New-Object System.Collections.Generic.List[string]

    $enUS = Join-Path $sys 'en-US'
    if (Test-Path -LiteralPath $enUS) {
        Get-ChildItem -LiteralPath $enUS -Filter '*.mui' -File -ErrorAction SilentlyContinue |
            Sort-Object @{ Expression = { $i = [array]::IndexOf($priority, $_.Name.ToLower()); if ($i -lt 0) { 999 } else { $i } } }, Name |
            ForEach-Object { $list.Add($_.FullName) }
    }

    # ConfigMgr / SCCM client
    $ccm = Join-Path $env:SystemRoot 'CCM'
    if (Test-Path -LiteralPath $ccm) {
        Get-ChildItem -LiteralPath (Join-Path $ccm 'en-US') -Filter '*.mui' -File -ErrorAction SilentlyContinue |
            ForEach-Object { $list.Add($_.FullName) }
        Get-ChildItem -LiteralPath $ccm -Filter '*.dll' -File -ErrorAction SilentlyContinue |
            ForEach-Object { $list.Add($_.FullName) }
    }
    $list
}

function Initialize-SccmResources {
    <# Loads SrsResources.dll (ConfigMgr console or client), which knows every 0x87D0xxxx message. #>
    $candidates = @()
    if ($env:SMS_ADMIN_UI_PATH) { $candidates += Join-Path (Split-Path $env:SMS_ADMIN_UI_PATH -Parent) 'SrsResources.dll' }
    $candidates += "${env:ProgramFiles(x86)}\Microsoft Endpoint Manager\AdminConsole\bin\SrsResources.dll"
    $candidates += "${env:ProgramFiles(x86)}\Microsoft Configuration Manager\AdminConsole\bin\SrsResources.dll"
    $candidates += "$env:SystemRoot\CCM\SrsResources.dll"

    foreach ($p in $candidates) {
        if ($p -and (Test-Path -LiteralPath $p)) {
            try {
                [void][System.Reflection.Assembly]::LoadFrom($p)
                if ('SrsResources.Localization' -as [type]) {
                    $script:SrsReady = $true
                    $script:SrsPath  = $p
                    return
                }
            } catch { }
        }
    }
}

function Initialize-ErrorIndex {
    <# Builds the in-memory index from every message table (shows progress in the status bar). #>
    $files = @(Get-MessageSources)
    $progress.Visible = $true
    $progress.Maximum = [Math]::Max(1, $files.Count)
    $progress.Value   = 0

    for ($i = 0; $i -lt $files.Count; $i++) {
        $f    = $files[$i]
        $name = [System.IO.Path]::GetFileName($f) -replace '\.mui$', ''
        if ($f -like "*\CCM\*") { $name = "ConfigMgr: $name" }
        try { [void][ErrorCodeConverterV3.ErrorIndex]::AddModule($f, $name) } catch { }
        if ($i % 25 -eq 0) {
            $progress.Value = $i
            $lblStatus.Text = "Indexing error messages... $i of $($files.Count) files"
            [System.Windows.Forms.Application]::DoEvents()
        }
    }

    foreach ($k in $script:KnownErrors.Keys) {
        [ErrorCodeConverterV3.ErrorIndex]::Add([Convert]::ToUInt32($k.Substring(2), 16), $script:KnownErrors[$k], 'Built-in table')
    }

    $progress.Visible   = $false
    $script:IndexReady  = $true
    $script:DescCache.Clear()

    $srs = if ($script:SrsReady) { 'ConfigMgr lookup: available' } else { 'ConfigMgr lookup: not found (install the console or client for all 0x87D0xxxx texts)' }
    $lblStatus.Text = "Ready.  Error index: {0:N0} English messages from {1} files.  {2}" -f [ErrorCodeConverterV3.ErrorIndex]::Count, [ErrorCodeConverterV3.ErrorIndex]::ModulesWithMessages, $srs
    if ([ErrorCodeConverterV3.ErrorIndex]::ModulesWithMessages -lt 50) {
        $lblStatus.Text += '  Tip: install the English (United States) language pack for full coverage.'
    }
}

function Get-ErrorDescription {
    param([int]$Signed, [int]$Facility, [int]$Code)

    if ($script:DescCache.ContainsKey($Signed)) { return $script:DescCache[$Signed] }

    # Plain Win32 error (e.g. 5) uses the value itself; HRESULT 0x8007xxxx uses the Win32 code.
    $isWin32 = ($Signed -ge 0) -or ($Facility -eq 7)
    $id      = if ($Signed -ge 0) { $Signed } elseif ($Facility -eq 7) { $Code } else { $Signed }
    $text    = $null
    $src     = ''

    # 1) Windows system message table (English)
    try { $text = [ErrorCodeConverterV3.EnglishErrorMessage]::FromSystem($id) } catch { }
    if ($text) { $src = 'Windows' }

    # 2) ConfigMgr / SCCM (SrsResources.dll)
    if (-not $text -and $script:SrsReady) {
        try {
            $t = [SrsResources.Localization]::GetErrorMessage($Signed, 'en-US')
            if ($t -and $t -notmatch '^\s*Unknown error') { $text = $t; $src = 'ConfigMgr' }
        } catch { }
    }

    # 3) Full message-table index (HRESULT / NTSTATUS only, to avoid matching
    #    event-log messages that reuse small numbers)
    if (-not $text -and -not $isWin32 -and $script:IndexReady) {
        $e = [ErrorCodeConverterV3.ErrorIndex]::Lookup($Signed)
        if ($e) { $text = $e.Text; $src = $e.Source }
    }

    # 4) Direct component lookup (WinINet/WinHTTP for Win32 codes, all components otherwise)
    if (-not $text) {
        $mods = if ($isWin32) { $script:MessageModules | Where-Object { $_ -match 'win(http|inet)\.dll$' } } else { $script:MessageModules }
        foreach ($m in $mods) {
            foreach ($i in (@($id, $Signed) | Select-Object -Unique)) {
                $t = $null
                try { $t = [ErrorCodeConverterV3.EnglishErrorMessage]::FromModule($m, $i) } catch { }
                if ($t) { $text = $t; $src = [System.IO.Path]::GetFileName($m); break }
            }
            if ($text) { break }
        }
    }

    # 5) Built-in English table
    if (-not $text) {
        $text = $script:KnownErrors['0x{0:X8}' -f $Signed]
        if (-not $text -and $Facility -eq 7) { $text = $script:KnownErrors['0x{0:X8}' -f $Code] }
        if ($text) { $src = 'Built-in table' }
    }

    # 6) BITS errors 0x8019xxxx carry the HTTP status code
    if (-not $text -and $Facility -eq 25 -and $Code -ge 100 -and $Code -le 599) {
        $text = "BG_E_HTTP_ERROR_$($Code): The server returned HTTP status $Code."
        $src  = 'BITS (HTTP status)'
    }

    $result = [pscustomobject]@{
        Text   = if ($text) { ($text -replace '\s+', ' ').Trim() } else { '' }
        Source = $src
    }
    $script:DescCache[$Signed] = $result
    return $result
}

# ----------------------------------------------------------------------------------------
#  Conversion logic
# ----------------------------------------------------------------------------------------

function Convert-ErrorCode {
    <#
        Takes a text value (decimal or hexadecimal) and returns an object with every representation.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [switch]$WithDescription
    )

    $t = $Value.Trim()
    $r = [ordered]@{
        Input       = $t
        Hex         = ''
        Int32       = ''
        UInt32      = ''
        Severity    = ''
        Facility    = ''
        Code        = ''
        Description = ''
        Source      = ''
        Status      = 'OK'
    }

    try {
        if ([string]::IsNullOrWhiteSpace($t)) { throw 'Empty value' }

        $hexDigits = $null
        if ($t -match '^(?i)(?:0x|&h)([0-9a-f]{1,16})$')                    { $hexDigits = $Matches[1] }
        elseif ($t -match '^(?i)[0-9a-f]{1,16}$' -and $t -match '(?i)[a-f]') { $hexDigits = $t }

        [uint32]$u = 0
        if ($hexDigits) {
            if ($hexDigits.Length -gt 8) {
                $high = $hexDigits.Substring(0, $hexDigits.Length - 8)
                $hexDigits = $hexDigits.Substring($hexDigits.Length - 8)
                if ($high -notmatch '^(?i)(0+|f+)$') { $r.Status = 'Truncated to 32 bits' }
            }
            $u = [Convert]::ToUInt32($hexDigits, 16)
        }
        else {
            [int64]$v = 0
            $ok = [int64]::TryParse($t, [System.Globalization.NumberStyles]::AllowLeadingSign,
                                    [System.Globalization.CultureInfo]::InvariantCulture, [ref]$v)
            if (-not $ok) { throw 'Invalid value' }
            if ($v -lt -2147483648L -or $v -gt 4294967295L) { $r.Status = 'Truncated to 32 bits' }
            $u = [uint32]($v -band 4294967295L)   # lower 32 bits (two's complement)
        }

        $signed   = [BitConverter]::ToInt32([BitConverter]::GetBytes($u), 0)
        $sev      = [int]($u -shr 31)
        $facility = [int](($u -shr 16) -band 0x7FF)
        $code     = [int]($u -band 0xFFFF)

        $r.Hex      = '0x{0:X8}' -f $u
        $r.Int32    = $signed
        $r.UInt32   = $u
        $r.Severity = if ($sev -eq 1) { '1 (Failure)' } else { '0 (Success)' }
        $facName    = $script:Facilities[$facility]
        $r.Facility = if ($facName) { '{0} ({1})' -f $facility, $facName } else { "$facility" }
        $r.Code     = '{0} (0x{0:X4})' -f $code

        if ($WithDescription) {
            $d = Get-ErrorDescription -Signed $signed -Facility $facility -Code $code
            $r.Description = $d.Text
            $r.Source      = $d.Source
        }
    }
    catch {
        $r.Status = "ERROR: $($_.Exception.Message)"
    }

    [pscustomobject]$r
}

function Get-CodesFromText {
    <# Extracts every code from free text (lists, CSV, logs...). #>
    param([string]$Text)
    $pattern = '(?i)(?:0x|&h)[0-9a-f]{1,16}\b|\b(?=[0-9a-f]{8,16}\b)[0-9]*[a-f][0-9a-f]*\b|-?\b\d+\b'
    [regex]::Matches($Text, $pattern) | ForEach-Object { $_.Value }
}

# ----------------------------------------------------------------------------------------
#  GUI helpers
# ----------------------------------------------------------------------------------------

$fontUI    = New-Object System.Drawing.Font('Segoe UI', 9)
$fontBold  = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$fontTitle = New-Object System.Drawing.Font('Segoe UI', 15, [System.Drawing.FontStyle]::Bold)
$fontMono  = New-Object System.Drawing.Font('Consolas', 10)
$fontMonoB = New-Object System.Drawing.Font('Consolas', 10, [System.Drawing.FontStyle]::Bold)
$fontBig   = New-Object System.Drawing.Font('Consolas', 18, [System.Drawing.FontStyle]::Bold)

function New-Btn {
    param([string]$Text, [int]$Width = 90, [switch]$Primary)
    $b = New-Object System.Windows.Forms.Button
    $b.Text      = $Text
    $b.Size      = New-Object System.Drawing.Size($Width, 28)
    $b.FlatStyle = 'Flat'
    $b.Cursor    = 'Hand'
    $b.Font      = $fontBold
    $b.FlatAppearance.BorderSize = 1
    if ($Primary) {
        $b.BackColor = $Theme.Purple
        $b.ForeColor = $Theme.White
        $b.FlatAppearance.BorderColor        = $Theme.Purple
        $b.FlatAppearance.MouseOverBackColor = $Theme.PurpleDark
        $b.FlatAppearance.MouseDownBackColor = $Theme.PurpleDeep
    } else {
        $b.BackColor = $Theme.White
        $b.ForeColor = $Theme.PurpleDark
        $b.FlatAppearance.BorderColor        = $Theme.Purple
        $b.FlatAppearance.MouseOverBackColor = $Theme.PurplePale
        $b.FlatAppearance.MouseDownBackColor = $Theme.PurpleLight
    }
    $b
}

function New-Group([string]$Text) {
    $g = New-Object System.Windows.Forms.GroupBox
    $g.Text      = $Text
    $g.Dock      = 'Fill'
    $g.Padding   = New-Object System.Windows.Forms.Padding(8)
    $g.ForeColor = $Theme.PurpleDeep
    $g.Font      = $fontBold
    $g.BackColor = $Theme.White
    $g
}

# ----------------------------------------------------------------------------------------
#  Main form
# ----------------------------------------------------------------------------------------

$form = New-Object System.Windows.Forms.Form
$form.Text          = "Error Code Converter  $($Sym.Dash)  Decimal $($Sym.LR) Hexadecimal"
$form.Size          = New-Object System.Drawing.Size(1320, 820)
$form.MinimumSize   = New-Object System.Drawing.Size(900, 600)
$form.StartPosition = 'CenterScreen'
$form.Font          = $fontUI
$form.BackColor     = $Theme.GrayBg
$form.ForeColor     = $Theme.Black
$form.KeyPreview    = $true

$tip = New-Object System.Windows.Forms.ToolTip

# ---------- Header ----------
$header = New-Object System.Windows.Forms.Panel
$header.Dock      = 'Top'
$header.Height    = 56
$header.BackColor = $Theme.Black

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text      = 'Error Code Converter'
$lblTitle.Font      = $fontTitle
$lblTitle.ForeColor = $Theme.White
$lblTitle.AutoSize  = $true
$lblTitle.Location  = New-Object System.Drawing.Point(16, 12)

$lblSubtitle = New-Object System.Windows.Forms.Label
$lblSubtitle.Text      = "Decimal $($Sym.LR) Hexadecimal  $($Sym.Dot)  HRESULT decoder  $($Sym.Dot)  Bulk conversion"
$lblSubtitle.ForeColor = $Theme.PurpleLight
$lblSubtitle.AutoSize  = $true
$lblSubtitle.Location  = New-Object System.Drawing.Point(264, 21)

$header.Controls.AddRange(@($lblTitle, $lblSubtitle))

$accentBar = New-Object System.Windows.Forms.Panel
$accentBar.Dock      = 'Top'
$accentBar.Height    = 4
$accentBar.BackColor = $Theme.Purple

# ---------- Status bar ----------
$status    = New-Object System.Windows.Forms.StatusStrip
$status.BackColor  = $Theme.Black
$status.SizingGrip = $false
$lblStatus = New-Object System.Windows.Forms.ToolStripStatusLabel
$lblStatus.Spring    = $true
$lblStatus.TextAlign = 'MiddleLeft'
$lblStatus.ForeColor = $Theme.White
$lblStatus.Text      = 'Starting...'
$progress  = New-Object System.Windows.Forms.ToolStripProgressBar
$progress.Size    = New-Object System.Drawing.Size(250, 16)
$progress.Visible = $false
[void]$status.Items.Add($lblStatus)
[void]$status.Items.Add($progress)

# ---------- Quick conversion ----------
$quickHost = New-Object System.Windows.Forms.Panel
$quickHost.Dock    = 'Top'
$quickHost.Height  = 132
$quickHost.Padding = New-Object System.Windows.Forms.Padding(8, 8, 8, 0)

$grpQuick = New-Group "Quick conversion (type a code $($Sym.Dash) converts as you type)"
$quickHost.Controls.Add($grpQuick)

$txtQuick = New-Object System.Windows.Forms.TextBox
$txtQuick.Font        = $fontBig
$txtQuick.ForeColor   = $Theme.Black
$txtQuick.BorderStyle = 'FixedSingle'
$txtQuick.Location    = New-Object System.Drawing.Point(15, 30)
$txtQuick.Width       = 330
$txtQuick.Text        = '-2133837819'

$lblArrow = New-Object System.Windows.Forms.Label
$lblArrow.Text      = $Sym.Arrow
$lblArrow.Font      = $fontBig
$lblArrow.ForeColor = $Theme.Purple
$lblArrow.AutoSize  = $true
$lblArrow.Location  = New-Object System.Drawing.Point(355, 32)

$lblQHex = New-Object System.Windows.Forms.Label
$lblQHex.Font      = $fontBig
$lblQHex.ForeColor = $Theme.Purple
$lblQHex.AutoSize  = $true
$lblQHex.Location  = New-Object System.Drawing.Point(400, 32)
$lblQHex.Cursor    = 'Hand'
$tip.SetToolTip($lblQHex, 'Click to copy')

$btnQCopy = New-Btn 'Copy Hex' 95 -Primary
$btnQCopy.Height   = 32
$btnQCopy.Location = New-Object System.Drawing.Point(600, 32)

$lblQInfo = New-Object System.Windows.Forms.Label
$lblQInfo.AutoSize  = $false
$lblQInfo.Font      = $fontUI
$lblQInfo.Location  = New-Object System.Drawing.Point(15, 75)
$lblQInfo.Size      = New-Object System.Drawing.Size(1260, 40)
$lblQInfo.Anchor    = 'Top, Left, Right'
$lblQInfo.ForeColor = $Theme.GrayText

$grpQuick.Controls.AddRange(@($txtQuick, $lblArrow, $lblQHex, $btnQCopy, $lblQInfo))

function Update-Quick {
    $res = Convert-ErrorCode -Value $txtQuick.Text -WithDescription
    if ($res.Status -like 'ERROR*') {
        $lblQHex.Text      = $Sym.Dash
        $lblQHex.ForeColor = $Theme.ErrorText
        $lblQInfo.Text     = $res.Status
    } else {
        $lblQHex.Text      = $res.Hex
        $lblQHex.ForeColor = $Theme.Purple
        $info = "Int32: $($res.Int32)   |   UInt32: $($res.UInt32)   |   Severity: $($res.Severity)   |   Facility: $($res.Facility)   |   Code: $($res.Code)"
        if ($res.Status -ne 'OK') { $info += "   |   $($res.Status)" }
        if ($res.Description)     { $info += "`r`n$($res.Description)   [$($res.Source)]" }
        else                      { $info += "`r`nNo description found on this machine." }
        $lblQInfo.Text = $info
    }
    $btnQCopy.Left = $lblQHex.Right + 15
}

$txtQuick.Add_TextChanged({ Update-Quick })
$copyQuick = {
    if ($lblQHex.Text -like '0x*') {
        [System.Windows.Forms.Clipboard]::SetText($lblQHex.Text)
        $lblStatus.Text = "Copied: $($lblQHex.Text)"
    }
}
$btnQCopy.Add_Click($copyQuick)
$lblQHex.Add_Click($copyQuick)

# ---------- Main split ----------
$split = New-Object System.Windows.Forms.SplitContainer
$split.Dock          = 'Fill'
$split.SplitterWidth = 6
$split.BackColor     = $Theme.GrayBg
$split.Padding       = New-Object System.Windows.Forms.Padding(8)

# ===== Left panel: bulk input =====
$grpIn = New-Group 'Bulk input (paste a list / log, import or drag & drop files)'

$flowIn = New-Object System.Windows.Forms.FlowLayoutPanel
$flowIn.Dock         = 'Top'
$flowIn.Height       = 66
$flowIn.WrapContents = $true

$btnImport = New-Btn 'Import...' 85
$btnPaste  = New-Btn 'Paste' 65
$btnClear  = New-Btn 'Clear' 65
$btnSample = New-Btn 'Sample' 70

$chkDedup = New-Object System.Windows.Forms.CheckBox
$chkDedup.Text = 'Remove duplicates'; $chkDedup.AutoSize = $true; $chkDedup.Checked = $true
$chkDedup.Font = $fontUI; $chkDedup.ForeColor = $Theme.Black
$chkDedup.Margin = New-Object System.Windows.Forms.Padding(6, 7, 3, 3)

$chkDesc = New-Object System.Windows.Forms.CheckBox
$chkDesc.Text = 'Look up description'; $chkDesc.AutoSize = $true; $chkDesc.Checked = $true
$chkDesc.Font = $fontUI; $chkDesc.ForeColor = $Theme.Black
$chkDesc.Margin = New-Object System.Windows.Forms.Padding(6, 7, 3, 3)
$tip.SetToolTip($chkDesc, 'Looks up the English error message (slightly slower on huge lists)')

$flowIn.Controls.AddRange(@($btnImport, $btnPaste, $btnClear, $btnSample, $chkDedup, $chkDesc))

$txtIn = New-Object System.Windows.Forms.TextBox
$txtIn.Multiline   = $true
$txtIn.ScrollBars  = 'Both'
$txtIn.WordWrap    = $false
$txtIn.Font        = $fontMono
$txtIn.ForeColor   = $Theme.Black
$txtIn.BorderStyle = 'FixedSingle'
$txtIn.Dock        = 'Fill'
$txtIn.MaxLength   = 0
$txtIn.AllowDrop   = $true

$btnConvert = New-Btn 'CONVERT ALL   (Ctrl+Enter)' 100 -Primary
$btnConvert.Dock   = 'Bottom'
$btnConvert.Height = 42
$btnConvert.Font   = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)

$grpIn.Controls.Add($btnConvert)
$grpIn.Controls.Add($flowIn)
$grpIn.Controls.Add($txtIn)
$txtIn.BringToFront()
$split.Panel1.Controls.Add($grpIn)

# ===== Right panel: results =====
$grpOut = New-Group 'Results'

$flowOut = New-Object System.Windows.Forms.FlowLayoutPanel
$flowOut.Dock   = 'Top'
$flowOut.Height = 36

$lblFilter = New-Object System.Windows.Forms.Label
$lblFilter.Text = 'Filter:'; $lblFilter.AutoSize = $true
$lblFilter.Font = $fontUI; $lblFilter.ForeColor = $Theme.Black
$lblFilter.Margin = New-Object System.Windows.Forms.Padding(3, 9, 0, 0)

$txtFilter = New-Object System.Windows.Forms.TextBox
$txtFilter.Width       = 180
$txtFilter.Font        = $fontUI
$txtFilter.BorderStyle = 'FixedSingle'
$txtFilter.Margin      = New-Object System.Windows.Forms.Padding(3, 5, 10, 0)
$tip.SetToolTip($txtFilter, 'Filters by input, hex, facility, description, source or status')

$btnExport   = New-Btn 'Export CSV' 95
$btnCopyAll  = New-Btn 'Copy table' 95
$btnCopyHex  = New-Btn 'Copy Hex only' 110
$btnExportDb = New-Btn 'Export error database' 160
$tip.SetToolTip($btnExportDb, 'Exports every error message indexed on this machine to CSV')
$flowOut.Controls.AddRange(@($lblFilter, $txtFilter, $btnExport, $btnCopyAll, $btnCopyHex, $btnExportDb))

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock                  = 'Fill'
$grid.ReadOnly              = $true
$grid.AllowUserToAddRows    = $false
$grid.AllowUserToDeleteRows = $false
$grid.RowHeadersVisible     = $false
$grid.SelectionMode         = 'FullRowSelect'
$grid.AutoSizeColumnsMode   = 'None'
$grid.BorderStyle           = 'None'
$grid.BackgroundColor       = $Theme.White
$grid.GridColor             = $Theme.GrayLine
$grid.ClipboardCopyMode     = 'EnableAlwaysIncludeHeaderText'
$grid.EnableHeadersVisualStyles   = $false
$grid.ColumnHeadersHeightSizeMode = 'DisableResizing'
$grid.ColumnHeadersHeight         = 32
$grid.ColumnHeadersBorderStyle    = 'Single'
$grid.ColumnHeadersDefaultCellStyle.BackColor          = $Theme.PurpleDeep
$grid.ColumnHeadersDefaultCellStyle.ForeColor          = $Theme.White
$grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $Theme.PurpleDeep
$grid.ColumnHeadersDefaultCellStyle.Font               = $fontBold
$grid.DefaultCellStyle.Font               = $fontMono
$grid.DefaultCellStyle.ForeColor          = $Theme.Black
$grid.DefaultCellStyle.SelectionBackColor = $Theme.PurpleDark
$grid.DefaultCellStyle.SelectionForeColor = $Theme.White
$grid.AlternatingRowsDefaultCellStyle.BackColor = $Theme.PurplePale
# Double buffering for large lists
$grid.GetType().GetProperty('DoubleBuffered', [System.Reflection.BindingFlags]'NonPublic,Instance').SetValue($grid, $true, $null)

$grpOut.Controls.Add($flowOut)
$grpOut.Controls.Add($grid)
$grid.BringToFront()
$split.Panel2.Controls.Add($grpOut)

# ---------- Data table ----------
$script:Columns = @('#', 'Input', 'Hex', 'Int32', 'UInt32', 'Severity', 'Facility', 'Code', 'Description', 'Source', 'Status')
$script:Table = New-Object System.Data.DataTable 'Results'
foreach ($c in $script:Columns) {
    $type = if ($c -eq '#') { [int] } else { [string] }
    [void]$script:Table.Columns.Add($c, $type)
}
$grid.DataSource = $script:Table.DefaultView

$widths = @{ '#'=55; Input=150; Hex=110; Int32=115; UInt32=105; Severity=95; Facility=170; Code=115; Source=130; Status=150 }
function Set-GridColumns {
    # Columns only exist once the grid is attached to the form, so this runs on Shown and after each conversion.
    if ($grid.Columns.Count -eq 0) { return }
    foreach ($col in $grid.Columns) { if ($widths.ContainsKey($col.Name)) { $col.Width = $widths[$col.Name] } }
    $grid.Columns['Description'].AutoSizeMode = 'Fill'
    $grid.Columns['Description'].MinimumWidth = 200
    $grid.Columns['Hex'].DefaultCellStyle.ForeColor = $Theme.Purple
    $grid.Columns['Hex'].DefaultCellStyle.Font      = $fontMonoB
}

$grid.Add_CellFormatting({
    param($s, $e)
    if ($e.RowIndex -lt 0) { return }
    $st = [string]$grid.Rows[$e.RowIndex].Cells['Status'].Value
    if ($st -like 'ERROR*')     { $e.CellStyle.BackColor = $Theme.ErrorBg; $e.CellStyle.ForeColor = $Theme.ErrorText }
    elseif ($st -like 'Trunc*') { $e.CellStyle.BackColor = $Theme.WarnBg }
})

# Double-click copies the row's hex
$grid.Add_CellDoubleClick({
    param($s, $e)
    if ($e.RowIndex -ge 0) {
        $h = [string]$grid.Rows[$e.RowIndex].Cells['Hex'].Value
        if ($h) { [System.Windows.Forms.Clipboard]::SetText($h); $lblStatus.Text = "Copied: $h" }
    }
})

# ---------- Actions ----------
function Invoke-BulkConvert {
    $codes = @(Get-CodesFromText -Text $txtIn.Text)
    if ($codes.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('No codes found in the input.', 'Warning', 'OK', 'Information') | Out-Null
        return
    }
    if ($chkDedup.Checked) {
        $seen  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $codes = @($codes | Where-Object { $seen.Add($_) })
    }

    $form.Cursor        = 'WaitCursor'
    $btnConvert.Enabled = $false
    $progress.Visible   = $true
    $progress.Maximum   = $codes.Count
    $progress.Value     = 0
    $sw = [Diagnostics.Stopwatch]::StartNew()

    $grid.DataSource = $null
    $script:Table.Clear()
    $script:Table.BeginLoadData()
    $withDesc = $chkDesc.Checked
    $errors   = 0
    $noDesc   = 0

    for ($i = 0; $i -lt $codes.Count; $i++) {
        $r = Convert-ErrorCode -Value $codes[$i] -WithDescription:$withDesc
        if ($r.Status -like 'ERROR*') { $errors++ }
        elseif ($withDesc -and -not $r.Description) { $noDesc++ }
        [void]$script:Table.Rows.Add(($i + 1), $r.Input, $r.Hex, [string]$r.Int32, [string]$r.UInt32,
                                     $r.Severity, $r.Facility, $r.Code, [string]$r.Description, [string]$r.Source, $r.Status)
        if ($i % 250 -eq 0) {
            $progress.Value = $i
            $lblStatus.Text = "Converting... $i of $($codes.Count)"
            [System.Windows.Forms.Application]::DoEvents()
        }
    }

    $script:Table.EndLoadData()
    $grid.DataSource = $script:Table.DefaultView
    Set-GridColumns

    $sw.Stop()
    $progress.Visible   = $false
    $btnConvert.Enabled = $true
    $form.Cursor        = 'Default'
    $lblStatus.Text = "{0} code(s) converted in {1:N2}s  $($Sym.Dash)  {2} error(s)  $($Sym.Dash)  {3} without description." -f $codes.Count, $sw.Elapsed.TotalSeconds, $errors, $noDesc
    Apply-Filter
}

function Apply-Filter {
    $f = $txtFilter.Text.Trim().Replace("'", "''").Replace('[', '[[]').Replace('*', '[*]').Replace('%', '[%]')
    if ([string]::IsNullOrEmpty($f)) {
        $script:Table.DefaultView.RowFilter = ''
    } else {
        $cols = 'Input', 'Hex', 'Int32', 'Facility', 'Code', 'Description', 'Source', 'Status'
        $script:Table.DefaultView.RowFilter = ($cols | ForEach-Object { "[$_] LIKE '%$f%'" }) -join ' OR '
    }
    $grpOut.Text = "Results  ({0} of {1})" -f $script:Table.DefaultView.Count, $script:Table.Rows.Count
}

function Get-VisibleRows {
    foreach ($rv in $script:Table.DefaultView) { $rv }
}

function Import-Files([string[]]$Paths) {
    $sb = New-Object System.Text.StringBuilder
    if ($txtIn.TextLength -gt 0) { [void]$sb.AppendLine($txtIn.Text) }
    foreach ($p in $Paths) {
        if (Test-Path -LiteralPath $p -PathType Leaf) {
            [void]$sb.AppendLine([System.IO.File]::ReadAllText($p))
        }
    }
    $txtIn.Text = $sb.ToString()
    $lblStatus.Text = "$($Paths.Count) file(s) imported. Click Convert."
}

$btnConvert.Add_Click({ Invoke-BulkConvert })
$txtFilter.Add_TextChanged({ Apply-Filter })

$btnImport.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter      = 'Text/CSV/Log (*.txt;*.csv;*.log)|*.txt;*.csv;*.log|All files (*.*)|*.*'
    $dlg.Multiselect = $true
    if ($dlg.ShowDialog() -eq 'OK') { Import-Files $dlg.FileNames }
})

$btnPaste.Add_Click({
    if ([System.Windows.Forms.Clipboard]::ContainsText()) {
        $txtIn.Text = [System.Windows.Forms.Clipboard]::GetText()
    }
})

$btnClear.Add_Click({
    $txtIn.Clear()
    $script:Table.Clear()
    $txtFilter.Clear()
    Apply-Filter
    $lblStatus.Text = 'Ready.'
})

$btnSample.Add_Click({
    $txtIn.Text = @"
-2145844844
-2133837819
-2147024891
-2147024894
-2016410844
-2145124329
0x80070005
80D03805
2149122452
5
Log: Install failed with error -2147012889
FFFFFFFF80190194
"@
})

$txtIn.Add_DragEnter({
    param($s, $e)
    if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) { $e.Effect = 'Copy' }
})
$txtIn.Add_DragDrop({
    param($s, $e)
    Import-Files ([string[]]$e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop))
})

$btnExport.Add_Click({
    if ($script:Table.DefaultView.Count -eq 0) { $lblStatus.Text = 'Nothing to export.'; return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter   = 'CSV (*.csv)|*.csv'
    $dlg.FileName = 'error_codes_{0:yyyyMMdd_HHmmss}.csv' -f (Get-Date)
    if ($dlg.ShowDialog() -eq 'OK') {
        $sep = (Get-Culture).TextInfo.ListSeparator   # matches the regional Excel separator
        Get-VisibleRows | Select-Object -Property $script:Columns |
            Export-Csv -LiteralPath $dlg.FileName -NoTypeInformation -Encoding UTF8 -Delimiter $sep
        $lblStatus.Text = "Exported: $($dlg.FileName)"
    }
})

$btnExportDb.Add_Click({
    if (-not $script:IndexReady) { $lblStatus.Text = 'The error index is still being built.'; return }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter   = 'CSV (*.csv)|*.csv'
    $dlg.FileName = 'error_database_{0}_{1:yyyyMMdd}.csv' -f $env:COMPUTERNAME, (Get-Date)
    if ($dlg.ShowDialog() -eq 'OK') {
        $form.Cursor = 'WaitCursor'
        $n = [ErrorCodeConverterV3.ErrorIndex]::ExportCsv($dlg.FileName, (Get-Culture).TextInfo.ListSeparator)
        $form.Cursor = 'Default'
        $lblStatus.Text = "{0:N0} error messages exported to {1}" -f $n, $dlg.FileName
    }
})

$btnCopyAll.Add_Click({
    if ($script:Table.DefaultView.Count -eq 0) { return }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine(($script:Columns -join "`t"))
    foreach ($rv in Get-VisibleRows) {
        [void]$sb.AppendLine((($script:Columns | ForEach-Object { [string]$rv[$_] }) -join "`t"))
    }
    [System.Windows.Forms.Clipboard]::SetText($sb.ToString())
    $lblStatus.Text = "$($script:Table.DefaultView.Count) row(s) copied (paste into Excel)."
})

$btnCopyHex.Add_Click({
    $hex = @(Get-VisibleRows | ForEach-Object { [string]$_['Hex'] } | Where-Object { $_ })
    if ($hex.Count -gt 0) {
        [System.Windows.Forms.Clipboard]::SetText(($hex -join "`r`n"))
        $lblStatus.Text = "$($hex.Count) hex value(s) copied."
    }
})

$form.Add_KeyDown({
    param($s, $e)
    if ($e.Control -and $e.KeyCode -eq 'Return') { Invoke-BulkConvert; $e.SuppressKeyPress = $true }
})

# ---------- Layout ----------
# Docking is applied from the last control to the first, so edges are added before the Fill control.
$form.Controls.Add($status)
$form.Controls.Add($quickHost)
$form.Controls.Add($accentBar)
$form.Controls.Add($header)
$form.Controls.Add($split)
$split.BringToFront()

$form.Add_Shown({
    $split.SplitterDistance = [int]($split.Width * 0.28)
    Set-GridColumns
    Apply-Filter
    $form.Cursor = 'WaitCursor'
    Initialize-SccmResources
    Initialize-ErrorIndex
    $form.Cursor = 'Default'
    Update-Quick
    $txtQuick.Focus()
    $txtQuick.SelectAll()
})

[void]$form.ShowDialog()
$form.Dispose()
