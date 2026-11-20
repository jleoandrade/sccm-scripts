<#
.SYNOPSIS
    GUI tool to list installed software, uninstall or repair it, and scan for leftovers.

.DESCRIPTION
    Works on the local computer or on a remote one (WinRM). Every action asks for confirmation first.
      1. Load      - lists installed software (read-only).
      2. Guard     - rule 5 blockers: pending reboot, install in progress (msiexec, TiWorker, ccmsetup),
                     low disk (repair only). Maintenance window outside = warning in the confirmation, never a block.
      3. Uninstall / Repair - MSI with /norestart; the tool NEVER forces a reboot.
      4. Leftover scan (read-only) after an uninstall: folders, shortcuts, registry, services, scheduled tasks,
         firewall rules, startup entries, PATH. Nothing is pre-selected: you choose what to delete.
      5. Delete    - direct deletion (no backup, as requested), re-validated on the target against a protected list.
    Not covered: Microsoft Store (Appx) apps, COM/CLSID, drivers, offline user hives.
    Remote mode only runs silent uninstalls (MSI or QuietUninstallString): there is no screen to click on.
    Log on the target: C:\ProgramData\SoftwareManager\SoftwareManager.log

.EXAMPLE
    .\Show-SoftwareManager.ps1
    .\Show-SoftwareManager.ps1 -ComputerName PC01
#>

param(
    [string]$ComputerName = $env:COMPUTERNAME,

    # Repair is blocked below this free space on the system drive (same default as Invoke-SccmHealthAudit.ps1)
    [int]$MinFreeGB = 10,

    # Maintenance window in the TARGET's local time (19 -> 7 = 19:00 to 06:59). Outside = warning only.
    [ValidateRange(0, 24)][int]$WindowStartHour = 19,
    [ValidateRange(0, 24)][int]$WindowEndHour = 7
)

# WinForms needs an STA thread
if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-ComputerName', $ComputerName, '-MinFreeGB', $MinFreeGB, '-WindowStartHour', $WindowStartHour, '-WindowEndHour', $WindowEndHour
    return
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Administrator rights are required to uninstall on this computer
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $answer = [System.Windows.Forms.MessageBox]::Show('Administrator rights are required. Restart this tool as administrator?', 'Software Manager', 'YesNo', 'Question')
    if ($answer -eq 'Yes') {
        Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList '-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-ComputerName', $ComputerName, '-MinFreeGB', $MinFreeGB, '-WindowStartHour', $WindowStartHour, '-WindowEndHour', $WindowEndHour
    }
    return
}

# Accenture palette: Purple #A100FF, Black, White, Gray #66646E, Deep purple #7500C0, Light tint #D2A5FF, Concrete #F2F2F2
$Purple     = [System.Drawing.ColorTranslator]::FromHtml('#A100FF')
$DeepPurple = [System.Drawing.ColorTranslator]::FromHtml('#7500C0')
$LightPurp  = [System.Drawing.ColorTranslator]::FromHtml('#D2A5FF')
$Tint       = [System.Drawing.ColorTranslator]::FromHtml('#F5EBFF')
$Gray       = [System.Drawing.ColorTranslator]::FromHtml('#66646E')
$Concrete   = [System.Drawing.ColorTranslator]::FromHtml('#F2F2F2')
$Black      = [System.Drawing.Color]::Black
$White      = [System.Drawing.Color]::White

# ---------------------------------------------------------------------------------------------
# Code that runs ON THE TARGET (local job or remote job). Every body below is prefixed with this block.
# ---------------------------------------------------------------------------------------------
$Common = @'
$ErrorActionPreference = 'Continue'
$LogDir = 'C:\ProgramData\SoftwareManager'

function Out-Log([string]$Text) { [pscustomobject]@{ Kind = 'Log'; Text = $Text } }
function Out-Result($Data)      { [pscustomobject]@{ Kind = 'Result'; Data = $Data } }
function Write-AuditLog([string]$Text) {
    try {
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        Add-Content -Path "$LogDir\SoftwareManager.log" -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Text"
    } catch { }
}

# Folder names that are never touched, and names too generic to be matched
$script:ProtectedLeaf = 'microsoft','windows','common files','windows nt','windowsapps','windows defender','windows mail',
    'windows media player','windows photo viewer','windows portable devices','windows security','windows sidebar',
    'internet explorer','microsoft.net','dotnet','modifiablewindowsapps','package cache','packages','temp','system32',
    'syswow64','start menu','programs','startup','desktop','documents','downloads','application data','softwaredistribution',
    'windowspowershell','powershell','reference assemblies','msbuild','installer','servicing','assembly','winsxs','boot',
    'recovery','perflogs','users','default','public','all users','program files','program files (x86)','programdata',
    'appdata','local','roaming','locallow','accessories','administrative tools','windows accessories','windows system',
    'windows powershell','system tools','maintenance','windows administrative tools','windows ease of access'
$script:ProtectedAncestor = 'common files','windows nt','windows defender','windowsapps','microsoft','windows','system32','winsxs'
$script:ProtectedRegTop = 'microsoft','classes','policies','wow6432node','clients','registeredapplications','odbc','windows','partner'
$script:GenericNames = 'update','setup','driver','drivers','tools','tool','client','agent','service','services','runtime',
    'windows','microsoft','intel','software','system','common','shared','data','program','programs','install','installer',
    'application','applications','framework','library','helper','manager','launcher','updater','web','cloud','security',
    'office','java','desktop','player','sync','support','utility','utilities','suite'

function Get-GuardState($Arg) {
    $sources = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $sources += 'Windows servicing (CBS)' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $sources += 'Windows Update' }
    try {
        $s = Invoke-CimMethod -Namespace root\ccm\ClientSDK -ClassName CCM_ClientUtilities -MethodName DetermineIfRebootPending -ErrorAction Stop
        if ($s.RebootPending -or $s.IsHardRebootPending) { $sources += 'SCCM client' }
    } catch { }
    $busy = @(Get-Process -Name msiexec, TiWorker, ccmsetup -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -Unique)
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
    $hour = (Get-Date).Hour
    $start = [int]$Arg.WindowStartHour; $end = [int]$Arg.WindowEndHour
    if ($start -le $end) { $inWindow = $hour -ge $start -and $hour -lt $end } else { $inWindow = $hour -ge $start -or $hour -lt $end }
    [pscustomobject]@{
        RebootPending = [bool]$sources.Count
        RebootSources = $sources -join ', '
        Busy          = $busy -join ', '
        FreeGB        = [math]::Round($disk.FreeSpace / 1GB, 1)
        InWindow      = $inWindow
        Hour          = $hour
        Computer      = $env:COMPUTERNAME
    }
}

function Test-UnderPath([string]$Path, [string]$Root) {
    if (-not $Path -or -not $Root) { return $false }
    $p = $Path.TrimEnd('\'); $r = $Root.TrimEnd('\')
    return (($p -eq $r) -or $p.StartsWith("$r\", [StringComparison]::OrdinalIgnoreCase))
}

# $true = never touch this path
function Test-ProtectedPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    try { $full = [IO.Path]::GetFullPath($Path).TrimEnd('\') } catch { return $true }
    if ($full -notmatch '^[A-Za-z]:\\[^\\]+\\') { return $true }            # drive root or direct child of it
    if (Test-UnderPath $full $env:windir) { return $true }
    $leaf = (Split-Path $full -Leaf).ToLower()
    if ($script:ProtectedLeaf -contains $leaf) { return $true }
    # Start Menu shortcut folders / shortcuts are allowed (only the product's own, matched by name elsewhere)
    if ($full -match '\\Microsoft\\Windows\\Start Menu\\Programs\\[^\\]+(\\[^\\]*)?$' -or $full -match '\\Desktop\\[^\\]+\.lnk$') { return $false }
    if ($full -match '^[A-Za-z]:\\Users\\[^\\]+(\\AppData(\\(Local|Roaming|LocalLow))?)?$') { return $true }
    $parts = $full.Substring(3) -split '\\'
    for ($i = 0; $i -lt $parts.Count - 1; $i++) { if ($script:ProtectedAncestor -contains $parts[$i].ToLower()) { return $true } }
    return $false
}

# Registry delete allow-list per kind: anything else is refused
function Test-AllowedRegKey([string]$Kind, [string]$Path) {
    $hives = 'HKLM:\\SOFTWARE\\(WOW6432Node\\)?|Registry::HKEY_USERS\\S-1-5-21-[\d-]+\\Software\\'
    switch ($Kind) {
        'RegKey' {
            if ($Path -notmatch "^($hives)") { return $false }
            $rel = $Path -replace "^($hives)", ''
            $parts = $rel -split '\\'
            if ($parts.Count -lt 1 -or $parts.Count -gt 2) { return $false }
            return ($script:ProtectedRegTop -notcontains $parts[0].ToLower())
        }
        'AppPath'        { return ($Path -match '^HKLM:\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\App Paths\\[^\\]+$') }
        'UninstallEntry' { return ($Path -match "^($hives)Microsoft\\Windows\\CurrentVersion\\Uninstall\\[^\\]+$") }
        'RunValue'       { return ($Path -match "^($hives)Microsoft\\Windows\\CurrentVersion\\Run$") }
    }
    return $false
}

function ConvertTo-NormName([string]$s) { return (($s.ToLower() -replace '[\s_]+', ' ').Trim()) }
function Test-NameIn([string]$Candidate, $Variants) {
    $c = ConvertTo-NormName $Candidate
    foreach ($v in @($Variants)) { if ($c -eq (ConvertTo-NormName $v)) { return $true } }
    return $false
}

function Get-PublisherVariant([string]$Publisher) {
    if ([string]::IsNullOrWhiteSpace($Publisher)) { return $null }
    $p = $Publisher.Trim()
    for ($i = 0; $i -lt 2; $i++) { $p = $p -replace '(?i)[,\.]?\s+(inc|incorporated|llc|ltd|limited|corp|corporation|gmbh|co|company|ag|bv|plc|pty|sa)\.?$', '' }
    $p = $p.Trim(' ', ',', '.')
    if ($p.Length -lt 3) { return $null }
    if (($script:GenericNames -contains $p.ToLower()) -or ($script:ProtectedLeaf -contains $p.ToLower())) { return $null }
    return $p
}

# Name variants used for matching: full name, without (x64), without version, without the publisher prefix
function Get-NameVariants([string]$Name, [string]$Publisher) {
    $out = New-Object 'System.Collections.Generic.List[string]'
    if ([string]::IsNullOrWhiteSpace($Name)) { return @() }
    $n = $Name.Trim()
    $a = ($n -replace '\s*[\(\[][^\)\]]*[\)\]]', '').Trim()
    $b = ($a -replace '(?i)\s+(x64|x86|amd64|64-bit|32-bit)\b', '').Trim()
    $c = ($b -replace '(?i)[\s,-]+(version\s+|ver\.?\s*|v)?\d+([._]\d+)*[a-z]?$', '').Trim()
    $d = $c
    $pub = Get-PublisherVariant $Publisher
    if ($pub -and $c.ToLower().StartsWith($pub.ToLower() + ' ')) { $d = $c.Substring($pub.Length).Trim() }
    foreach ($v in $n, $a, $b, $c, $d) {
        if ($v.Length -ge 4 -and ($script:GenericNames -notcontains $v.ToLower()) -and -not $out.Contains($v)) { $out.Add($v) }
    }
    return @($out)
}

function Split-Command([string]$Cmd) {
    if ([string]::IsNullOrWhiteSpace($Cmd)) { return $null }
    $c = $Cmd.Trim()
    if ($c -match '^"([^"]+)"\s*(.*)$') { return @{ Exe = $Matches[1]; Args = [string]$Matches[2] } }
    if ($c -match '^(.+?\.exe)(?:\s+(.*))?$') { return @{ Exe = $Matches[1]; Args = [string]$Matches[2] } }
    return $null
}

function Get-LoadedUserSids {
    Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object { $_.PSChildName }
}
function Get-UninstallBases {
    $b = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    foreach ($sid in Get-LoadedUserSids) { $b += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
    return $b
}

# Installed programs, as shown in Programs and Features (updates and system components are skipped)
function Get-Inventory {
    foreach ($base in Get-UninstallBases) {
        foreach ($k in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
            $keyPath = "$base\$($k.PSChildName)"
            $p = Get-ItemProperty -LiteralPath $keyPath -ErrorAction SilentlyContinue
            if (-not $p -or [string]::IsNullOrWhiteSpace($p.DisplayName)) { continue }
            if ($p.SystemComponent -eq 1 -or $p.ParentKeyName) { continue }
            if ($p.ReleaseType -in 'Update', 'Hotfix', 'Security Update', 'Update Rollup', 'ServicePack') { continue }
            if ($p.DisplayName -match '\(KB\d+\)|^(Security )?Update for ') { continue }
            $code = $null
            if ($k.PSChildName -match '^\{[0-9A-Fa-f-]{36}\}$') { $code = $k.PSChildName }
            elseif ("$($p.UninstallString)" -match '(\{[0-9A-Fa-f-]{36}\})') { $code = $Matches[1] }
            $isMsi = ($p.WindowsInstaller -eq 1) -or (("$($p.UninstallString)" -match 'msiexec') -and $code)
            if ("$($p.InstallDate)" -match '^(\d{4})(\d{2})(\d{2})$') { $date = "$($Matches[1])-$($Matches[2])-$($Matches[3])" } else { $date = "$($p.InstallDate)" }
            if ($base -like 'Registry::HKEY_USERS*') { $scope = 'User' } else { $scope = 'Machine' }
            [pscustomobject]@{
                KeyPath = $keyPath; KeyName = $k.PSChildName; Name = [string]$p.DisplayName; Version = [string]$p.DisplayVersion
                Publisher = [string]$p.Publisher; InstallDate = $date; SizeMB = [math]::Round(([double]$p.EstimatedSize) / 1024, 1)
                InstallLocation = [string]$p.InstallLocation; UninstallString = [string]$p.UninstallString
                QuietUninstallString = [string]$p.QuietUninstallString; ModifyPath = [string]$p.ModifyPath
                IsMsi = [bool]$isMsi; ProductCode = $code; NoRepair = ($p.NoRepair -eq 1); Scope = $scope
                Arch = $(if ($base -like '*WOW6432Node*') { 'x86' } else { 'x64/any' })
            }
        }
    }
}
'@

function New-Body([string]$Body) { [scriptblock]::Create("param(`$Arg)`n" + $Common + "`n" + $Body) }

$GuardBody = New-Body @'
$g = Get-GuardState $Arg
# Between queue items: wait for a lingering msiexec/TiWorker to finish (never when a reboot is pending)
$waited = 0
while ($g.Busy -and -not $g.RebootPending -and $waited -lt [int]$Arg.WaitBusySeconds) { Start-Sleep -Seconds 10; $waited += 10; $g = Get-GuardState $Arg }
Out-Result $g
'@

$InventoryBody = New-Body @'
Out-Log 'Reading installed software...'
$inv = @(Get-Inventory | Sort-Object Name)
Out-Result @{ Items = $inv; Guard = (Get-GuardState $Arg) }
'@

# Uninstall or repair ONE program. MSI always with /norestart. Never forces a reboot.
$ActionBody = New-Body @'
$e = $Arg.Entry
$action = $Arg.Action
$exe = $null; $procArgs = ''; $mode = $null

if ($e.IsMsi -and $e.ProductCode) {
    $exe = "$env:windir\System32\msiexec.exe"
    if ($action -eq 'Uninstall') { $flag = '/x' } else { $flag = '/fa' }
    if ($Arg.Interactive) { $ui = '/qb-' } else { $ui = '/qn' }
    $procArgs = "$flag $($e.ProductCode) $ui /norestart"
    $mode = 'MSI'
}
elseif ($action -eq 'Uninstall') {
    $cmd = $e.QuietUninstallString
    $mode = 'EXE (quiet)'
    if (-not $cmd) { $cmd = $e.UninstallString; $mode = 'EXE (uninstaller screen)' }
    $sp = Split-Command $cmd
    if (-not $sp) { Out-Result @{ Ok = $false; Message = "Cannot parse the uninstall command: $cmd" }; return }
    if (-not $Arg.Interactive -and $mode -ne 'EXE (quiet)') {
        Out-Result @{ Ok = $false; Message = 'Remote mode needs a silent uninstall (MSI or QuietUninstallString). This program only has an interactive uninstaller; run the tool on the computer itself.' }
        return
    }
    $exe = $sp.Exe; $procArgs = $sp.Args
}
else {
    # Repair of a non-MSI program: only through its own modify/repair screen, on the computer itself
    $sp = Split-Command $e.ModifyPath
    if ($e.NoRepair -or -not $sp) { Out-Result @{ Ok = $false; Message = 'This program does not offer a repair option.' }; return }
    if (-not $Arg.Interactive) { Out-Result @{ Ok = $false; Message = 'Repair of a non-MSI program needs its screen: run the tool on the computer itself.' }; return }
    $exe = $sp.Exe; $procArgs = $sp.Args; $mode = 'EXE (repair screen)'
}

if (-not (Test-Path -LiteralPath $exe)) { Out-Result @{ Ok = $false; Message = "Program not found: $exe" }; return }

Out-Log "[$mode] $exe $procArgs"
Write-AuditLog "[$action] START $($e.Name) $($e.Version) | $exe $procArgs"
try {
    if ($procArgs) { $proc = Start-Process -FilePath $exe -ArgumentList $procArgs -Wait -PassThru -ErrorAction Stop }
    else { $proc = Start-Process -FilePath $exe -Wait -PassThru -ErrorAction Stop }
}
catch {
    Write-AuditLog "[$action] FAILED to start: $($_.Exception.Message)"
    Out-Result @{ Ok = $false; Message = "Could not start: $($_.Exception.Message)" }
    return
}
$code = $proc.ExitCode
$text = switch ($code) {
    0 { 'Success' } 3010 { 'Success, restart required (NOT done by this tool)' } 1641 { 'Success, restart required' }
    1602 { 'Cancelled' } 1603 { 'Fatal error during installation' } 1605 { 'Product is not installed' }
    1618 { 'Another installation is in progress' } default { "Exit code $code" }
}
$success = $code -in 0, 3010, 1641

# Some uninstallers hand over to another process and return early: wait until the entry disappears
$gone = $false
if ($action -eq 'Uninstall') {
    $maxTries = 1
    if ($success -or $mode -ne 'MSI') { $maxTries = 36 }
    for ($i = 0; $i -lt $maxTries; $i++) {
        if (-not (Test-Path -LiteralPath $e.KeyPath)) { $gone = $true; break }
        Start-Sleep -Seconds 5
    }
}
Write-AuditLog "[$action] END $($e.Name) | $text | entry removed: $gone"
Out-Result @{
    Ok = $success; ExitCode = $code; Message = $text; Mode = $mode; EntryGone = $gone
    RebootRequired = ($code -in 3010, 1641); Guard = (Get-GuardState $Arg)
}
'@

# Leftover scan: READ-ONLY. Matches by product name (never by publisher alone) and by install location.
$ScanBody = New-Body @'
$e = $Arg.Entry
$name = [string]$e.Name; $publisher = [string]$e.Publisher
$variants = @(Get-NameVariants $name $publisher)
$pubVariant = Get-PublisherVariant $publisher
$pubList = @(); if ($pubVariant) { $pubList = @($pubVariant) }
$items = New-Object System.Collections.ArrayList
$notes = New-Object System.Collections.ArrayList
$folderPaths = New-Object System.Collections.ArrayList

Out-Log "Scanning leftovers of '$name' (match names: $($variants -join ' | '))..."

# Other installed programs: used to avoid touching anything that still belongs to another program
$others = @(Get-Inventory | Where-Object { $_.KeyPath -ne [string]$e.KeyPath })
$otherLocs = New-Object System.Collections.ArrayList
$nameScan = $true
foreach ($o in $others) {
    if ($o.InstallLocation) { [void]$otherLocs.Add($o.InstallLocation.Trim('"').TrimEnd('\')) }
    $osp = Split-Command $o.UninstallString
    if ($osp -and $osp.Exe -notmatch 'msiexec') { [void]$otherLocs.Add((Split-Path $osp.Exe -Parent)) }
    foreach ($ov in @(Get-NameVariants $o.Name $o.Publisher)) {
        if (Test-NameIn $ov $variants) {
            if ($nameScan) { [void]$notes.Add("Another installed program shares this name ('$($o.Name)'): name-based scan skipped, only the install location is checked.") }
            $nameScan = $false
        }
    }
}
if (-not $variants.Count) { $nameScan = $false; [void]$notes.Add('Name too short or generic for a safe name-based scan.') }

function Test-Shared([string]$Path) {
    foreach ($l in $otherLocs) { if ($l -and ((Test-UnderPath $l $Path) -or (Test-UnderPath $Path $l))) { return $true } }
    return $false
}
function Add-Leftover([string]$Kind, [string]$Category, [string]$Display, [string]$Path, [string]$Extra, [string]$Detail) {
    foreach ($i in $items) { if ($i.Kind -eq $Kind -and $i.Path -eq $Path -and $i.Extra -eq $Extra) { return } }
    [void]$items.Add([pscustomobject]@{ Kind = $Kind; Category = $Category; Display = $Display; Path = $Path; Extra = $Extra; Detail = $Detail })
}
function Get-FolderDetail([string]$Path) {
    $m = Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum
    return ('{0} files, {1} MB' -f $m.Count, [math]::Round(($m.Sum / 1MB), 1))
}
function Add-FolderCandidate([string]$Path, [string]$Category) {
    if (Test-ProtectedPath $Path) { [void]$notes.Add("Skipped (protected path): $Path"); return }
    if (Test-Shared $Path) { [void]$notes.Add("Skipped (used by another installed program): $Path"); return }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return }
    [void]$folderPaths.Add($Path)
    Add-Leftover 'Folder' $Category $Path $Path '' (Get-FolderDetail $Path)
}
function Add-FileCandidate([string]$Path, [string]$Category) {
    if (Test-ProtectedPath $Path) { return }
    Add-Leftover 'File' $Category $Path $Path '' 'Shortcut'
}

# --- 1. Install folder (from InstallLocation and from the uninstaller location) ---
$goodLocs = New-Object System.Collections.ArrayList
$locs = @()
if ($e.InstallLocation) { $locs += ([string]$e.InstallLocation).Trim('"').TrimEnd('\') }
$usp = Split-Command ([string]$e.UninstallString)
if ($usp -and $usp.Exe -notmatch 'msiexec') { $locs += (Split-Path $usp.Exe -Parent) }
foreach ($l in ($locs | Where-Object { $_ } | Select-Object -Unique)) {
    if (Test-ProtectedPath $l) { [void]$notes.Add("Skipped (protected path): $l"); continue }
    if (Test-Shared $l) { [void]$notes.Add("Skipped (used by another installed program): $l"); continue }
    [void]$goodLocs.Add($l)
    if (Test-Path -LiteralPath $l -PathType Container) { Add-FolderCandidate $l 'Install folder' }
}

# --- 2. Folders by name: Program Files, ProgramData, AppData ---
if ($nameScan) {
    Out-Log 'Scanning folders...'
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)
    foreach ($u in @(Get-ChildItem "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue)) {
        $roots += "$($u.FullName)\AppData\Local", "$($u.FullName)\AppData\Roaming", "$($u.FullName)\AppData\LocalLow", "$($u.FullName)\AppData\Local\Programs"
    }
    foreach ($root in ($roots | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique)) {
        if ($root -like '*\Users\*') { $label = 'User data (AppData)' } elseif ($root -eq $env:ProgramData) { $label = 'Program data' } else { $label = 'Program folder' }
        foreach ($dir in @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue)) {
            if ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
            if (Test-NameIn $dir.Name $variants) { Add-FolderCandidate $dir.FullName $label; continue }
            if ($pubList.Count -and (Test-NameIn $dir.Name $pubList)) {
                $subs = @(Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue)
                $match = @($subs | Where-Object { $_.PSIsContainer -and (Test-NameIn $_.Name $variants) })
                if ($match.Count -gt 0) {
                    if ($match.Count -eq $subs.Count -and -not (Test-Shared $dir.FullName) -and -not (Test-ProtectedPath $dir.FullName)) {
                        Add-FolderCandidate $dir.FullName "$label - publisher folder with only this product"
                    }
                    else { foreach ($m in $match) { Add-FolderCandidate $m.FullName $label } }
                }
                elseif ($subs.Count -eq 0) { Add-FolderCandidate $dir.FullName "$label - empty publisher folder" }
            }
        }
    }

    # --- 3. Shortcuts: Start Menu and Desktop ---
    Out-Log 'Scanning shortcuts...'
    $startRoots = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs", "$env:PUBLIC\Desktop")
    foreach ($u in @(Get-ChildItem "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue)) {
        $startRoots += "$($u.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs", "$($u.FullName)\Desktop"
    }
    foreach ($sr in ($startRoots | Where-Object { $_ -and (Test-Path -LiteralPath $_) })) {
        foreach ($f in @(Get-ChildItem -LiteralPath $sr -Force -ErrorAction SilentlyContinue)) {
            if (-not $f.PSIsContainer) {
                if ($f.Extension -eq '.lnk' -and (Test-NameIn $f.BaseName $variants)) { Add-FileCandidate $f.FullName 'Shortcut' }
            }
            elseif (-not ($f.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                if (Test-NameIn $f.Name $variants) { Add-FolderCandidate $f.FullName 'Start Menu folder' }
                elseif ($pubList.Count -and (Test-NameIn $f.Name $pubList)) {
                    $subs = @(Get-ChildItem -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue)
                    if ($subs.Count -eq 0) { Add-FolderCandidate $f.FullName 'Start Menu - empty publisher folder' }
                    foreach ($s in $subs) { if (-not $s.PSIsContainer -and $s.Extension -eq '.lnk' -and (Test-NameIn $s.BaseName $variants)) { Add-FileCandidate $s.FullName 'Shortcut' } }
                }
            }
        }
    }

    # --- 4. Registry keys by name (HKLM, HKLM Wow6432Node, loaded user hives) ---
    Out-Log 'Scanning registry...'
    $regBases = @('HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\WOW6432Node')
    foreach ($sid in Get-LoadedUserSids) { $regBases += "Registry::HKEY_USERS\$sid\Software" }
    foreach ($base in $regBases) {
        foreach ($k in @(Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue)) {
            $top = $k.PSChildName
            if ($script:ProtectedRegTop -contains $top.ToLower()) { continue }
            $topPath = "$base\$top"
            if (Test-NameIn $top $variants) {
                if (Test-AllowedRegKey 'RegKey' $topPath) { Add-Leftover 'RegKey' 'Registry key' $topPath $topPath '' "$($k.SubKeyCount) subkeys, $($k.ValueCount) values" }
                continue
            }
            if ($pubList.Count -and (Test-NameIn $top $pubList)) {
                $subs = @(Get-ChildItem -LiteralPath $topPath -ErrorAction SilentlyContinue)
                $match = @($subs | Where-Object { Test-NameIn $_.PSChildName $variants })
                if ($match.Count -gt 0) {
                    if ($match.Count -eq $subs.Count -and $k.ValueCount -eq 0) {
                        if (Test-AllowedRegKey 'RegKey' $topPath) { Add-Leftover 'RegKey' 'Registry key - publisher key with only this product' $topPath $topPath '' "$($subs.Count) subkeys" }
                    }
                    else {
                        foreach ($m in $match) {
                            $mp = "$topPath\$($m.PSChildName)"
                            if (Test-AllowedRegKey 'RegKey' $mp) { Add-Leftover 'RegKey' 'Registry key' $mp $mp '' "$($m.SubKeyCount) subkeys, $($m.ValueCount) values" }
                        }
                    }
                }
                elseif ($subs.Count -eq 0 -and $k.ValueCount -eq 0) {
                    if (Test-AllowedRegKey 'RegKey' $topPath) { Add-Leftover 'RegKey' 'Registry key - empty publisher key' $topPath $topPath '' 'empty' }
                }
            }
        }
    }
}

$allLocs = @($goodLocs) + @($folderPaths)

# --- 5. App Paths and startup (Run) entries that point into the removed locations ---
Out-Log 'Scanning App Paths and startup entries...'
foreach ($ap in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths') {
    foreach ($k in @(Get-ChildItem -LiteralPath $ap -ErrorAction SilentlyContinue)) {
        $kp = "$ap\$($k.PSChildName)"
        $def = [string](Get-ItemProperty -LiteralPath $kp -ErrorAction SilentlyContinue).'(default)'
        $target = [Environment]::ExpandEnvironmentVariables($def).Trim('"')
        foreach ($l in $allLocs) {
            if (Test-UnderPath $target $l) { Add-Leftover 'AppPath' 'App Paths entry' $kp $kp '' $target; break }
        }
    }
}
$runKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
foreach ($sid in Get-LoadedUserSids) { $runKeys += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Run" }
foreach ($rk in $runKeys) {
    $props = Get-ItemProperty -LiteralPath $rk -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    foreach ($pr in @($props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
        $val = [Environment]::ExpandEnvironmentVariables([string]$pr.Value)
        $csp = Split-Command $val
        if ($csp) { $exeP = $csp.Exe } else { $exeP = $val.Trim('"') }
        $hit = $false
        foreach ($l in $allLocs) { if (Test-UnderPath $exeP $l) { $hit = $true } }
        if ($nameScan -and (Test-NameIn $pr.Name $variants)) { $hit = $true }
        if ($hit -and (Test-AllowedRegKey 'RunValue' $rk)) { Add-Leftover 'RunValue' 'Startup entry (Run)' "$($pr.Name)  [$rk]" $rk $pr.Name $val }
    }
}

# --- 6. Services ---
Out-Log 'Scanning services...'
foreach ($svc in @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)) {
    $ssp = Split-Command ([Environment]::ExpandEnvironmentVariables([string]$svc.PathName))
    if ($ssp) { $exeP = $ssp.Exe } else { $exeP = ([string]$svc.PathName).Trim('"') }
    if (-not $exeP -or (Test-UnderPath $exeP $env:windir)) { continue }
    $hit = $false
    foreach ($l in $allLocs) { if (Test-UnderPath $exeP $l) { $hit = $true } }
    if ($nameScan -and ((Test-NameIn $svc.DisplayName $variants) -or (Test-NameIn $svc.Name $variants))) { $hit = $true }
    if ($hit) { Add-Leftover 'Service' 'Windows service' "$($svc.DisplayName) [$($svc.Name)]" $svc.Name '' "$($svc.State) | $exeP" }
}

# --- 7. Scheduled tasks (Microsoft's own tasks are never listed) ---
Out-Log 'Scanning scheduled tasks...'
if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        if ($t.TaskPath -like '\Microsoft\*') { continue }
        $hit = $false
        foreach ($a in @($t.Actions)) {
            $ex = [Environment]::ExpandEnvironmentVariables([string]$a.Execute).Trim('"')
            foreach ($l in $allLocs) { if (Test-UnderPath $ex $l) { $hit = $true } }
        }
        if ($nameScan) {
            foreach ($v in $variants) {
                if ($v.Length -ge 5 -and ($t.TaskName.StartsWith($v, [StringComparison]::OrdinalIgnoreCase) -or $t.TaskPath -like "*\$v\*")) { $hit = $true }
            }
        }
        if ($hit) { Add-Leftover 'Task' 'Scheduled task' "$($t.TaskPath)$($t.TaskName)" $t.TaskName $t.TaskPath "State: $($t.State)" }
    }
}

# --- 8. Firewall rules ---
Out-Log 'Scanning firewall rules...'
if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
    $ruleNames = New-Object System.Collections.ArrayList
    foreach ($f in @(Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue)) {
        $prog = [Environment]::ExpandEnvironmentVariables([string]$f.Program)
        foreach ($l in $allLocs) { if ($prog -and (Test-UnderPath $prog $l)) { [void]$ruleNames.Add([string]$f.InstanceID) } }
    }
    foreach ($r in @(Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
        $hit = $ruleNames.Contains([string]$r.Name)
        if ($nameScan -and -not $hit -and $r.DisplayName -notlike '@*') {
            foreach ($v in $variants) { if ($v.Length -ge 5 -and $r.DisplayName.StartsWith($v, [StringComparison]::OrdinalIgnoreCase)) { $hit = $true } }
        }
        if ($hit) { Add-Leftover 'Firewall' 'Firewall rule' "$($r.DisplayName) [$($r.Direction)]" $r.Name '' "Enabled: $($r.Enabled)" }
    }
}

# --- 9. Machine PATH entries pointing into the removed locations ---
$envKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$rawPath = [string](Get-Item -LiteralPath $envKeyPath).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
foreach ($pe in ($rawPath -split ';')) {
    if (-not $pe.Trim()) { continue }
    $ex = [Environment]::ExpandEnvironmentVariables($pe).Trim('"')
    foreach ($l in $allLocs) { if (Test-UnderPath $ex $l) { Add-Leftover 'PathEntry' 'PATH entry (Machine)' $pe $pe '' 'System PATH'; break } }
}

# Drop folders nested inside another listed folder (deleting the parent covers them)
$final = @($items | Where-Object {
    $it = $_
    -not ($it.Kind -eq 'Folder' -and ($items | Where-Object { $_.Kind -eq 'Folder' -and $_.Path -ne $it.Path -and (Test-UnderPath $it.Path $_.Path) }))
})
Write-AuditLog "[Scan] $name | $($final.Count) leftover(s) found"
Out-Result @{ Items = $final; Notes = @($notes); Name = $name }
'@

# Direct deletion of the leftovers the user ticked. Everything is re-validated here, on the target.
$DeleteBody = New-Body @'
$g = Get-GuardState $Arg
if ($g.RebootPending -or $g.Busy) {
    $why = @()
    if ($g.RebootPending) { $why += "reboot pending ($($g.RebootSources))" }
    if ($g.Busy) { $why += "install in progress ($($g.Busy))" }
    Out-Result @{ Blocked = ($why -join '; '); Results = @() }
    return
}
$results = New-Object System.Collections.ArrayList
function Add-Res($it, [bool]$ok, [string]$msg) {
    Write-AuditLog "[Delete] $($it.Kind) | $($it.Path) $($it.Extra) | ok=$ok | $msg"
    [void]$results.Add([pscustomobject]@{ Kind = $it.Kind; Display = $it.Display; Ok = $ok; Message = $msg })
}
foreach ($it in @($Arg.Items)) {
    try {
        switch ($it.Kind) {
            'Folder' {
                if (Test-ProtectedPath $it.Path) { Add-Res $it $false 'Refused: protected path'; break }
                if (-not (Test-Path -LiteralPath $it.Path)) { Add-Res $it $true 'Already gone'; break }
                $dirItem = Get-Item -LiteralPath $it.Path -Force
                if ($dirItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { Add-Res $it $false 'Refused: link/junction'; break }
                # rd /s does not follow junctions inside the folder (Remove-Item -Recurse can, in Windows PowerShell 5.1)
                & cmd.exe /c rd /s /q "$($it.Path)" 2>&1 | Out-Null
                if (Test-Path -LiteralPath $it.Path) { Add-Res $it $false 'Partially removed: files in use or access denied' } else { Add-Res $it $true 'Deleted' }
            }
            'File' {
                if ((Test-ProtectedPath $it.Path) -or [IO.Path]::GetExtension($it.Path) -ne '.lnk') { Add-Res $it $false 'Refused: only shortcuts (.lnk) outside protected paths'; break }
                Remove-Item -LiteralPath $it.Path -Force -ErrorAction Stop
                Add-Res $it $true 'Deleted'
            }
            { $_ -in 'RegKey', 'AppPath' } {
                if (-not (Test-AllowedRegKey $it.Kind $it.Path)) { Add-Res $it $false 'Refused: registry path not allowed'; break }
                if (Test-Path -LiteralPath $it.Path) { Remove-Item -LiteralPath $it.Path -Recurse -Force -ErrorAction Stop }
                Add-Res $it $true 'Deleted'
            }
            'RunValue' {
                if (-not (Test-AllowedRegKey 'RunValue' $it.Path)) { Add-Res $it $false 'Refused: registry path not allowed'; break }
                Remove-ItemProperty -LiteralPath $it.Path -Name $it.Extra -Force -ErrorAction Stop
                Add-Res $it $true 'Deleted'
            }
            'Service' {
                $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($it.Path -replace "'", "''")'" -ErrorAction SilentlyContinue
                if (-not $svc) { Add-Res $it $true 'Already gone'; break }
                if ([string]$svc.PathName -match [regex]::Escape($env:windir)) { Add-Res $it $false 'Refused: Windows service'; break }
                if ($svc.State -eq 'Running') { Stop-Service -Name $it.Path -Force -ErrorAction SilentlyContinue }
                $out = & sc.exe delete $it.Path 2>&1
                if ($LASTEXITCODE -eq 0) { Add-Res $it $true 'Deleted' } else { Add-Res $it $false "sc.exe: $out" }
            }
            'Task' {
                if ($it.Extra -like '\Microsoft\*') { Add-Res $it $false 'Refused: Microsoft task'; break }
                Unregister-ScheduledTask -TaskName $it.Path -TaskPath $it.Extra -Confirm:$false -ErrorAction Stop
                Add-Res $it $true 'Deleted'
            }
            'Firewall' {
                Remove-NetFirewallRule -Name $it.Path -ErrorAction Stop
                Add-Res $it $true 'Deleted'
            }
            'PathEntry' {
                $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment', $true)
                try {
                    $raw = [string]$key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
                    $keep = @($raw -split ';' | Where-Object { $_ -and $_ -ne $it.Path })
                    # Written back as REG_EXPAND_SZ so %SystemRoot% and friends keep working
                    $key.SetValue('Path', ($keep -join ';'), [Microsoft.Win32.RegistryValueKind]::ExpandString)
                }
                finally { $key.Close() }
                Add-Res $it $true 'Removed from PATH (applies to new sessions)'
            }
            default { Add-Res $it $false 'Unknown item type' }
        }
    }
    catch { Add-Res $it $false $_.Exception.Message }
}
Out-Result @{ Blocked = ''; Results = @($results); Guard = (Get-GuardState $Arg) }
'@

# =============================================================================================
# GUI
# =============================================================================================
$script:Busy = $false
$script:Job = $null
$script:ResultData = $null
$script:OnDone = $null
$script:Entries = @{}            # grid row Id -> inventory entry
$script:Guard = $null
$script:LogPath = $null

function Test-IsLocal([string]$Name) {
    $n = $Name.Trim()
    return ($n -eq '' -or $n -in '.', 'localhost', '127.0.0.1', $env:COMPUTERNAME)
}
function Show-Box([string]$Text, [string]$Title = 'Software Manager', [string]$Buttons = 'OK', [string]$Icon = 'Information') {
    return [System.Windows.Forms.MessageBox]::Show($form, $Text, $Title, $Buttons, $Icon)
}
function Add-LogLine([string]$Text) {
    $txtLog.AppendText("[$(Get-Date -Format 'HH:mm:ss')] $Text`r`n")
}
function New-FlatButton([string]$Text, $Back, [int]$Width = 150) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text; $b.Width = $Width; $b.Height = 34
    $b.FlatStyle = 'Flat'; $b.FlatAppearance.BorderSize = 0
    $b.BackColor = $Back; $b.ForeColor = $White
    $b.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9.5)
    $b.Cursor = [System.Windows.Forms.Cursors]::Hand
    $b.Tag = $Back
    $b.Add_MouseEnter({ if ($this.Enabled) { $this.BackColor = $Black } })
    $b.Add_MouseLeave({ if ($this.Enabled) { $this.BackColor = $this.Tag } })
    return $b
}
function Set-ButtonEnabled($Button, [bool]$Enabled) {
    $Button.Enabled = $Enabled
    if ($Enabled) { $Button.BackColor = $Button.Tag; $Button.ForeColor = $White } else { $Button.BackColor = $LightPurp; $Button.ForeColor = $Gray }
}

# --- Form and layout ---
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Software Manager'
$form.Size = New-Object System.Drawing.Size(1180, 780)
$form.MinimumSize = New-Object System.Drawing.Size(960, 600)
$form.StartPosition = 'CenterScreen'
$form.BackColor = $White
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

# Grid (fills the remaining space)
$table = New-Object System.Data.DataTable
foreach ($c in 'Id') { [void]$table.Columns.Add($c, [int]) }
foreach ($c in 'Name', 'Version', 'Publisher', 'Installed', 'Type', 'Scope') { [void]$table.Columns.Add($c, [string]) }
[void]$table.Columns.Add('SizeMB', [double])
$view = New-Object System.Data.DataView($table)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = 'Fill'
$grid.DataSource = $view
$grid.ReadOnly = $true
$grid.AllowUserToAddRows = $false; $grid.AllowUserToDeleteRows = $false; $grid.AllowUserToResizeRows = $false
$grid.SelectionMode = 'FullRowSelect'; $grid.MultiSelect = $true
$grid.RowHeadersVisible = $false
$grid.BackgroundColor = $White; $grid.BorderStyle = 'None'
$grid.GridColor = $Concrete; $grid.CellBorderStyle = 'SingleHorizontal'
$grid.EnableHeadersVisualStyles = $false
$grid.ColumnHeadersDefaultCellStyle.BackColor = $Black
$grid.ColumnHeadersDefaultCellStyle.ForeColor = $White
$grid.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9.5)
$grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $Black
$grid.ColumnHeadersHeight = 34
$grid.ColumnHeadersHeightSizeMode = 'DisableResizing'
$grid.DefaultCellStyle.SelectionBackColor = $Purple
$grid.DefaultCellStyle.SelectionForeColor = $White
$grid.DefaultCellStyle.ForeColor = $Black
$grid.AlternatingRowsDefaultCellStyle.BackColor = $Tint
$grid.RowTemplate.Height = 26
$grid.AutoSizeColumnsMode = 'Fill'

# Bottom: progress + log
$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Dock = 'Bottom'; $progress.Height = 5; $progress.Style = 'Continuous'; $progress.MarqueeAnimationSpeed = 25

$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Dock = 'Bottom'; $txtLog.Height = 150; $txtLog.Multiline = $true; $txtLog.ReadOnly = $true
$txtLog.ScrollBars = 'Vertical'; $txtLog.BackColor = $Black; $txtLog.ForeColor = $LightPurp
$txtLog.Font = New-Object System.Drawing.Font('Consolas', 9); $txtLog.BorderStyle = 'None'

# Banner (reboot pending and other blockers are shown here)
$lblBanner = New-Object System.Windows.Forms.Label
$lblBanner.Dock = 'Top'; $lblBanner.Height = 30; $lblBanner.TextAlign = 'MiddleLeft'
$lblBanner.Padding = New-Object System.Windows.Forms.Padding(20, 0, 0, 0)
$lblBanner.BackColor = $Concrete; $lblBanner.ForeColor = $Gray
$lblBanner.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9.5)
$lblBanner.Text = 'Computer state not checked yet. Click "Load software".'

# Action bar
$pnlActions = New-Object System.Windows.Forms.Panel
$pnlActions.Dock = 'Top'; $pnlActions.Height = 56; $pnlActions.BackColor = $White
$btnUninstall = New-FlatButton 'Uninstall' $Purple 150
$btnRepair    = New-FlatButton 'Repair' $DeepPurple 150
$btnUninstall.Location = New-Object System.Drawing.Point(20, 11)
$btnRepair.Location    = New-Object System.Drawing.Point(184, 11)
$lblSelected = New-Object System.Windows.Forms.Label
$lblSelected.Location = New-Object System.Drawing.Point(356, 11); $lblSelected.Size = New-Object System.Drawing.Size(780, 34)
$lblSelected.TextAlign = 'MiddleLeft'; $lblSelected.ForeColor = $Gray
$lblSelected.Anchor = 'Top, Left, Right'
$lblSelected.Text = 'Select one or more programs (Ctrl/Shift + click).'
$pnlActions.Controls.AddRange(@($btnUninstall, $btnRepair, $lblSelected))

# Toolbar: computer + load + filter
$pnlTool = New-Object System.Windows.Forms.Panel
$pnlTool.Dock = 'Top'; $pnlTool.Height = 56; $pnlTool.BackColor = $Concrete
$lblComputer = New-Object System.Windows.Forms.Label
$lblComputer.Text = 'Computer'; $lblComputer.Location = New-Object System.Drawing.Point(20, 18); $lblComputer.AutoSize = $true
$lblComputer.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9.5)
$txtComputer = New-Object System.Windows.Forms.TextBox
$txtComputer.Location = New-Object System.Drawing.Point(92, 14); $txtComputer.Width = 200; $txtComputer.Text = $ComputerName
$txtComputer.BorderStyle = 'FixedSingle'
$btnLoad = New-FlatButton 'Load software' $Purple 150
$btnLoad.Location = New-Object System.Drawing.Point(304, 11)
$lblFilter = New-Object System.Windows.Forms.Label
$lblFilter.Text = 'Filter'; $lblFilter.Location = New-Object System.Drawing.Point(480, 18); $lblFilter.AutoSize = $true
$lblFilter.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9.5)
$txtFilter = New-Object System.Windows.Forms.TextBox
$txtFilter.Location = New-Object System.Drawing.Point(530, 14); $txtFilter.Width = 280; $txtFilter.BorderStyle = 'FixedSingle'
$lblCount = New-Object System.Windows.Forms.Label
$lblCount.Location = New-Object System.Drawing.Point(830, 18); $lblCount.AutoSize = $true; $lblCount.ForeColor = $Gray
$pnlTool.Controls.AddRange(@($lblComputer, $txtComputer, $btnLoad, $lblFilter, $txtFilter, $lblCount))

# Header (no logo: palette only) and purple accent line
$pnlAccent = New-Object System.Windows.Forms.Panel
$pnlAccent.Dock = 'Top'; $pnlAccent.Height = 4; $pnlAccent.BackColor = $Purple
$pnlHeader = New-Object System.Windows.Forms.Panel
$pnlHeader.Dock = 'Top'; $pnlHeader.Height = 66; $pnlHeader.BackColor = $Black
$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = 'Software Manager'; $lblTitle.ForeColor = $White; $lblTitle.AutoSize = $true
$lblTitle.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 18)
$lblTitle.Location = New-Object System.Drawing.Point(18, 6)
$lblSub = New-Object System.Windows.Forms.Label
$lblSub.Text = 'Uninstall  |  Repair  |  Leftover cleanup'; $lblSub.ForeColor = $LightPurp; $lblSub.AutoSize = $true
$lblSub.Font = New-Object System.Drawing.Font('Segoe UI', 9.5)
$lblSub.Location = New-Object System.Drawing.Point(22, 40)
$pnlHeader.Controls.AddRange(@($lblTitle, $lblSub))

# Z-order: Fill first, then Bottom, then Top (the last one added ends up at the very top)
$form.Controls.Add($grid)
$form.Controls.Add($progress)
$form.Controls.Add($txtLog)
$form.Controls.Add($lblBanner)
$form.Controls.Add($pnlActions)
$form.Controls.Add($pnlTool)
$form.Controls.Add($pnlAccent)
$form.Controls.Add($pnlHeader)

Set-ButtonEnabled $btnUninstall $false
Set-ButtonEnabled $btnRepair $false

# --- Background job plumbing: one operation at a time, polled by a timer so the window never freezes ---
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 500

function Set-UiBusy([bool]$IsBusy) {
    $txtComputer.Enabled = -not $IsBusy
    $txtFilter.Enabled = -not $IsBusy
    Set-ButtonEnabled $btnLoad (-not $IsBusy)
    if ($IsBusy) {
        Set-ButtonEnabled $btnUninstall $false; Set-ButtonEnabled $btnRepair $false
        $progress.Style = 'Marquee'; $form.Cursor = [System.Windows.Forms.Cursors]::AppStarting
    }
    else {
        $progress.Style = 'Continuous'; $progress.Value = 0; $form.Cursor = [System.Windows.Forms.Cursors]::Default
        Update-SelectionState
    }
}

function Start-Op([string]$Title, [scriptblock]$Body, $Arg, [scriptblock]$OnDone) {
    if ($script:Busy) { return }
    $target = $txtComputer.Text.Trim()
    $script:Busy = $true; $script:ResultData = $null; $script:OnDone = $OnDone
    Set-UiBusy $true
    Add-LogLine "$Title ($(if (Test-IsLocal $target) { 'local' } else { $target }))"
    try {
        if (Test-IsLocal $target) { $script:Job = Start-Job -ScriptBlock $Body -ArgumentList (, $Arg) }
        else { $script:Job = Invoke-Command -ComputerName $target -ScriptBlock $Body -ArgumentList (, $Arg) -AsJob }
        $timer.Start()
    }
    catch {
        $script:Busy = $false; Set-UiBusy $false
        Add-LogLine "ERROR: $($_.Exception.Message)"
        [void](Show-Box "Could not start the operation:`n$($_.Exception.Message)" 'Software Manager' 'OK' 'Error')
    }
}

$timer.Add_Tick({
    if (-not $script:Job) { return }
    $state = $script:Job.State                                   # read BEFORE receiving, so no output is lost
    $err = $null
    $out = @(Receive-Job -Job $script:Job -ErrorAction SilentlyContinue -ErrorVariable err)
    foreach ($o in $out) {
        if ($o.Kind -eq 'Log') { Add-LogLine ([string]$o.Text) }
        elseif ($o.Kind -eq 'Result') { $script:ResultData = $o.Data }
    }
    foreach ($er in @($err)) { Add-LogLine "ERROR: $($er.Exception.Message)" }
    if ($state -in 'Completed', 'Failed', 'Stopped') {
        $timer.Stop()
        $reason = $null
        if ($state -eq 'Failed' -and $script:Job.ChildJobs.Count) { $reason = [string]$script:Job.ChildJobs[0].JobStateInfo.Reason.Message }
        $job = $script:Job; $script:Job = $null
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
        $data = $script:ResultData; $script:ResultData = $null
        $script:Busy = $false
        Set-UiBusy $false
        if ($reason) { Add-LogLine "FAILED: $reason" }
        try { & $script:OnDone $data $reason }
        catch { Add-LogLine "ERROR in handler: $($_.Exception.Message)" }
    }
})

# --- Banner with the computer state (reboot pending is always shown) ---
function Update-Banner($Guard) {
    $script:Guard = $Guard
    if (-not $Guard) { return }
    $parts = @()
    $alert = $false
    if ($Guard.RebootPending) { $parts += "REBOOT PENDING ($($Guard.RebootSources)) - uninstall, repair and delete are blocked until the computer is restarted"; $alert = $true }
    if ($Guard.Busy) { $parts += "install in progress ($($Guard.Busy))"; $alert = $true }
    if (-not $Guard.InWindow) { $parts += "outside maintenance window ($WindowStartHour`:00-$WindowEndHour`:00): extra confirmation" }
    $parts += "free space $($Guard.FreeGB) GB"
    $lblBanner.Text = "$($Guard.Computer):  " + ($parts -join '   |   ')
    if ($alert) { $lblBanner.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#B00020'); $lblBanner.ForeColor = $White }
    else { $lblBanner.BackColor = $Concrete; $lblBanner.ForeColor = $Black }
}

function Get-ArgBase { return @{ WindowStartHour = $WindowStartHour; WindowEndHour = $WindowEndHour; MinFreeGB = $MinFreeGB } }

function Get-SelectedEntries {
    $list = @()
    foreach ($row in $grid.SelectedRows) { $list += $script:Entries[[int]$row.Cells['Id'].Value] }
    return @($list | Sort-Object Name)
}

function Update-SelectionState {
    $sel = @(Get-SelectedEntries)
    if (-not $sel.Count) {
        Set-ButtonEnabled $btnUninstall $false; Set-ButtonEnabled $btnRepair $false
        $lblSelected.Text = 'Select one or more programs (Ctrl/Shift + click).'
        return
    }
    $canUninstall = $true; $canRepair = $true
    foreach ($e in $sel) {
        if (-not ($e.UninstallString -or $e.QuietUninstallString)) { $canUninstall = $false }
        if (-not (($e.IsMsi -and $e.ProductCode) -or ($e.ModifyPath -and -not $e.NoRepair))) { $canRepair = $false }
    }
    Set-ButtonEnabled $btnUninstall ($canUninstall -and -not $script:Busy)
    Set-ButtonEnabled $btnRepair ($canRepair -and -not $script:Busy)
    if ($sel.Count -eq 1) { $lblSelected.Text = "$($sel[0].Name) $($sel[0].Version)   |   $($sel[0].Publisher)   |   $($sel[0].Scope), $($sel[0].Arch)" }
    else { $lblSelected.Text = "$($sel.Count) programs selected" }
}

function Import-Inventory($Items) {
    $script:Entries = @{}
    $table.Clear()
    $id = 0
    foreach ($e in @($Items)) {
        $id++
        $script:Entries[$id] = $e
        $type = 'EXE'; if ($e.IsMsi) { $type = 'MSI' }
        [void]$table.Rows.Add($id, [string]$e.Name, [string]$e.Version, [string]$e.Publisher, [string]$e.InstallDate, $type, [string]$e.Scope, [double]$e.SizeMB)
    }
    $grid.Columns['Id'].Visible = $false
    $grid.Columns['SizeMB'].HeaderText = 'Size (MB)'
    $weights = @{ Name = 40; Version = 11; Publisher = 22; Installed = 10; Type = 6; Scope = 8; SizeMB = 8 }
    foreach ($k in $weights.Keys) { $grid.Columns[$k].FillWeight = $weights[$k] }
    $lblCount.Text = "$($view.Count) of $($table.Rows.Count) programs"
    Update-SelectionState
}

function Start-Load {
    Start-Op 'Reading installed software' $InventoryBody (Get-ArgBase) {
        param($d, $r)
        if (-not $d) { [void](Show-Box "Could not read the software list.`n$r" 'Software Manager' 'OK' 'Error'); return }
        Import-Inventory $d.Items
        Update-Banner $d.Guard
        Add-LogLine "$(@($d.Items).Count) programs found."
    }
}

$btnLoad.Add_Click({ Start-Load })
$grid.Add_SelectionChanged({ Update-SelectionState })
$txtFilter.Add_TextChanged({
    $t = $txtFilter.Text.Trim() -replace "'", "''"
    $t = $t -replace '([\[\]%*])', '[$1]'
    if ($t) { $view.RowFilter = "Name LIKE '%$t%' OR Publisher LIKE '%$t%'" } else { $view.RowFilter = '' }
    $lblCount.Text = "$($view.Count) of $($table.Rows.Count) programs"
})

# --- Uninstall / Repair of one or more programs: guard -> ONE confirmation -> one program at a time -> leftover scan ---
$script:Pending = $null      # Action, Interactive, Entries
$script:Queue = New-Object System.Collections.ArrayList
$script:Current = $null
$script:Total = 0
$script:OkCount = 0
$script:Done = New-Object System.Collections.ArrayList        # uninstalled programs (to scan)
$script:Problems = New-Object System.Collections.ArrayList
$script:RebootNeeded = $false
$script:ScanQueue = New-Object System.Collections.ArrayList
$script:ScanItems = New-Object System.Collections.ArrayList

function Invoke-EntryAction([string]$Action) {
    $entries = @(Get-SelectedEntries)
    if (-not $entries.Count) { return }
    $interactive = Test-IsLocal $txtComputer.Text
    if (-not $interactive) {
        $bad = @($entries | Where-Object {
            $msi = ($_.IsMsi -and $_.ProductCode)
            if ($Action -eq 'Uninstall') { -not $msi -and -not $_.QuietUninstallString } else { -not $msi }
        })
        if ($bad.Count) {
            [void](Show-Box ("Remote mode only runs silent actions (MSI, or a quiet uninstaller). Not possible for:`n- " + (($bad | ForEach-Object { $_.Name }) -join "`n- ") + "`n`nUnselect them or run the tool on that computer.") 'Software Manager' 'OK' 'Warning')
            return
        }
    }
    $script:Pending = @{ Action = $Action; Interactive = $interactive; Entries = $entries }
    Start-Op "Checking the computer state before $Action" $GuardBody (Get-ArgBase) {
        param($g, $r)
        if (-not $g) { [void](Show-Box "Could not check the computer state. Nothing was changed.`n$r" 'Software Manager' 'OK' 'Error'); return }
        Update-Banner $g
        $p = $script:Pending
        $blockers = @()
        if ($g.RebootPending) { $blockers += "A reboot is pending ($($g.RebootSources))." }
        if ($g.Busy) { $blockers += "An installation is in progress ($($g.Busy))." }
        if ($p.Action -eq 'Repair' -and $g.FreeGB -lt $MinFreeGB) { $blockers += "Free space is $($g.FreeGB) GB, below the minimum of $MinFreeGB GB." }
        if ($blockers) {
            [void](Show-Box ("Blocked by the safety rules. Nothing was changed.`n`n" + ($blockers -join "`n") + "`n`nRestart the computer / wait, then try again. This tool never restarts the computer.") 'Blocked' 'OK' 'Warning')
            return
        }
        $names = @($p.Entries | Select-Object -First 12 | ForEach-Object { "- $($_.Name) $($_.Version)" })
        $msg = "$($p.Action.ToUpper()) $($p.Entries.Count) program(s) on $($g.Computer), one at a time:`n`n" + ($names -join "`n")
        if ($p.Entries.Count -gt 12) { $msg += "`n... and $($p.Entries.Count - 12) more" }
        $msg += "`n`nMSI programs run silently with /norestart. Others use their own uninstaller/repair (interactive ones show a screen on this computer). This tool never forces a restart, but some uninstallers can ask for one."
        if (-not $g.InWindow) { $msg += "`n`nWARNING: outside the maintenance window ($WindowStartHour`:00-$WindowEndHour`:00)." }
        if ($p.Action -eq 'Uninstall') { $msg += "`n`nAfterwards I will scan for leftovers and ask before deleting anything." }
        $msg += "`n`nContinue?"
        if ((Show-Box $msg "Confirm $($p.Action)" 'YesNo' 'Question') -ne 'Yes') { Add-LogLine 'Cancelled by the user. Nothing was changed.'; return }
        $script:Queue = New-Object System.Collections.ArrayList
        foreach ($x in $p.Entries) { [void]$script:Queue.Add($x) }
        $script:Total = $script:Queue.Count
        $script:OkCount = 0; $script:RebootNeeded = $false
        $script:Done = New-Object System.Collections.ArrayList
        $script:Problems = New-Object System.Collections.ArrayList
        Start-NextAction
    }
}

function Start-NextAction {
    $p = $script:Pending
    if ($script:Queue.Count -eq 0) { Complete-Queue; return }
    $e = $script:Queue[0]; $script:Queue.RemoveAt(0)
    $script:Current = $e
    $arg = Get-ArgBase
    $arg.Action = $p.Action; $arg.Entry = $e; $arg.Interactive = $p.Interactive
    $n = $script:Total - $script:Queue.Count
    Start-Op "$($p.Action) $($e.Name) ($n of $($script:Total))" $ActionBody $arg { param($res, $rr) Complete-Action $res $rr }
}

function Complete-Action($res, $reason) {
    $p = $script:Pending; $e = $script:Current
    if (-not $res) {
        [void]$script:Problems.Add("$($e.Name): no answer from the target ($reason). Queue stopped; check the program state.")
        $script:Queue.Clear(); Complete-Queue; return
    }
    if ($res.Guard) { Update-Banner $res.Guard }
    if ($res.RebootRequired -or ($res.Guard -and $res.Guard.RebootPending)) { $script:RebootNeeded = $true }
    if ($p.Action -eq 'Uninstall') {
        if ($res.EntryGone) { $script:OkCount++; [void]$script:Done.Add($e); Add-LogLine "Uninstalled: $($e.Name) - $($res.Message)" }
        elseif ($res.Ok) { [void]$script:Problems.Add("$($e.Name): still listed after the uninstaller finished (leftover scan skipped).") }
        else { [void]$script:Problems.Add("$($e.Name): $($res.Message)") }
    }
    else {
        if ($res.Ok) { $script:OkCount++; Add-LogLine "Repaired: $($e.Name) - $($res.Message)" }
        else { [void]$script:Problems.Add("$($e.Name): $($res.Message)") }
    }
    Complete-Next
}

# Before each next program: re-check the guards (waits for a lingering msiexec). Stops the queue if blocked.
function Complete-Next {
    if ($script:Queue.Count -eq 0) { Complete-Queue; return }
    $arg = Get-ArgBase
    $arg.WaitBusySeconds = 300
    Start-Op 'Checking the computer state before the next program' $GuardBody $arg {
        param($g, $r)
        if ($g) { Update-Banner $g }
        $low = ($script:Pending.Action -eq 'Repair' -and $g -and $g.FreeGB -lt $MinFreeGB)
        if (-not $g -or $g.RebootPending -or $g.Busy -or $low) {
            [void]$script:Problems.Add("Queue stopped by the safety rules (reboot pending, install in progress or low disk): $($script:Queue.Count) program(s) not processed.")
            $script:Queue.Clear(); Complete-Queue; return
        }
        Start-NextAction
    }
}

function Complete-Queue {
    $p = $script:Pending
    $text = "$($script:OkCount) of $($script:Total) program(s) completed."
    if ($script:RebootNeeded) { $text += "`n`nA restart is now pending. This tool does NOT restart the computer. Deleting leftovers stays blocked until you restart; the scan is read-only and you can save its list." }
    if ($script:Problems.Count) {
        $text += "`n`nProblems:`n" + (($script:Problems | Select-Object -First 10) -join "`n")
        foreach ($pr in $script:Problems) { Add-LogLine "PROBLEM: $pr" }
    }
    [void](Show-Box $text 'Software Manager' 'OK' 'Information')
    if ($p.Action -eq 'Uninstall' -and $script:Done.Count) {
        $script:ScanQueue = New-Object System.Collections.ArrayList
        foreach ($x in $script:Done) { [void]$script:ScanQueue.Add($x) }
        $script:ScanItems = New-Object System.Collections.ArrayList
        Start-NextScan
    }
    else { Start-Load }
}

# One read-only scan per uninstalled program, merged into a single list
function Start-NextScan {
    if ($script:ScanQueue.Count -eq 0) { Review-Leftovers @($script:ScanItems) "$($script:Done.Count) program(s)"; return }
    $e = $script:ScanQueue[0]; $script:ScanQueue.RemoveAt(0)
    $arg = Get-ArgBase
    $arg.Entry = $e
    Start-Op "Scanning leftovers of $($e.Name)" $ScanBody $arg { param($s, $sr) Collect-Scan $s $sr }
}

function Collect-Scan($s, $reason) {
    if (-not $s) { Add-LogLine "Leftover scan failed: $reason" }
    else {
        foreach ($n in @($s.Notes)) { Add-LogLine $n }
        foreach ($it in @($s.Items)) {
            $dup = $false
            foreach ($x in $script:ScanItems) { if ($x.Kind -eq $it.Kind -and $x.Path -eq $it.Path -and $x.Extra -eq $it.Extra) { $dup = $true } }
            if (-not $dup) { $it | Add-Member -NotePropertyName Program -NotePropertyValue $s.Name -Force; [void]$script:ScanItems.Add($it) }
        }
    }
    Start-NextScan
}

# --- Leftover dialog: nothing is pre-selected ---
function Show-LeftoverDialog($Items, [string]$Name, $Guard) {
    $script:DlgResult = $null
    $script:dlgItems = @($Items)
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "Leftovers of $Name"
    $dlg.Size = New-Object System.Drawing.Size(1020, 640)
    $dlg.StartPosition = 'CenterParent'; $dlg.BackColor = $White
    $dlg.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    $script:dlgGrid = New-Object System.Windows.Forms.DataGridView
    $g = $script:dlgGrid
    $g.Dock = 'Fill'; $g.AllowUserToAddRows = $false; $g.AllowUserToDeleteRows = $false; $g.AllowUserToResizeRows = $false
    $g.RowHeadersVisible = $false; $g.BackgroundColor = $White; $g.BorderStyle = 'None'
    $g.GridColor = $Concrete; $g.CellBorderStyle = 'SingleHorizontal'; $g.SelectionMode = 'FullRowSelect'
    $g.EnableHeadersVisualStyles = $false
    $g.ColumnHeadersDefaultCellStyle.BackColor = $Black; $g.ColumnHeadersDefaultCellStyle.ForeColor = $White
    $g.ColumnHeadersDefaultCellStyle.SelectionBackColor = $Black
    $g.ColumnHeadersHeight = 32; $g.ColumnHeadersHeightSizeMode = 'DisableResizing'
    $g.DefaultCellStyle.SelectionBackColor = $LightPurp; $g.DefaultCellStyle.SelectionForeColor = $Black
    $g.AlternatingRowsDefaultCellStyle.BackColor = $Tint
    $g.RowTemplate.Height = 26; $g.AutoSizeColumnsMode = 'Fill'
    $chk = New-Object System.Windows.Forms.DataGridViewCheckBoxColumn
    $chk.HeaderText = 'Delete'; $chk.FillWeight = 7
    [void]$g.Columns.Add($chk)
    foreach ($c in @(@('Program', 'Program', 15), @('Category', 'Type', 17), @('Display', 'Item', 40), @('Detail', 'Detail', 21))) {
        $i = $g.Columns.Add($c[0], $c[1]); $g.Columns[$i].FillWeight = $c[2]; $g.Columns[$i].ReadOnly = $true
    }
    foreach ($it in $script:dlgItems) {
        $idx = $g.Rows.Add($false, [string]$it.Program, [string]$it.Category, [string]$it.Display, [string]$it.Detail)
        $g.Rows[$idx].Tag = $it
    }

    $pnlBottom = New-Object System.Windows.Forms.Panel
    $pnlBottom.Dock = 'Bottom'; $pnlBottom.Height = 62; $pnlBottom.BackColor = $Concrete
    $bAll = New-FlatButton 'Select all' $DeepPurple 110;   $bAll.Location = New-Object System.Drawing.Point(16, 14)
    $bNone = New-FlatButton 'Select none' $DeepPurple 110; $bNone.Location = New-Object System.Drawing.Point(136, 14)
    $bSave = New-FlatButton 'Save list (CSV)' $Gray 130;   $bSave.Location = New-Object System.Drawing.Point(256, 14)
    $bKeep = New-FlatButton 'Keep everything' $Black 140;  $bKeep.Anchor = 'Top, Right'; $bKeep.Location = New-Object System.Drawing.Point(700, 14)
    $bDel = New-FlatButton 'Delete selected' $Purple 150;  $bDel.Anchor = 'Top, Right'; $bDel.Location = New-Object System.Drawing.Point(848, 14)
    $pnlBottom.Controls.AddRange(@($bAll, $bNone, $bSave, $bKeep, $bDel))

    $lblNote = New-Object System.Windows.Forms.Label
    $lblNote.Dock = 'Top'; $lblNote.Height = 46; $lblNote.Padding = New-Object System.Windows.Forms.Padding(16, 4, 16, 0)
    $lblNote.ForeColor = $Black; $lblNote.BackColor = $White; $lblNote.TextAlign = 'MiddleLeft'
    $lblNote.Text = "$($script:dlgItems.Count) leftover(s) found. Nothing is selected: tick what you want to delete. Deletion is PERMANENT (no backup). 'User data (AppData)' items may hold settings or documents."
    $blocked = $false
    if ($Guard -and ($Guard.RebootPending -or $Guard.Busy)) {
        $blocked = $true
        $lblNote.BackColor = [System.Drawing.ColorTranslator]::FromHtml('#B00020'); $lblNote.ForeColor = $White
        $lblNote.Text = "BLOCKED: reboot pending or install in progress. Deletion is disabled; restart the computer yourself and use 'Save list' to keep this result."
        Set-ButtonEnabled $bDel $false
    }

    $pnlHead = New-Object System.Windows.Forms.Panel
    $pnlHead.Dock = 'Top'; $pnlHead.Height = 50; $pnlHead.BackColor = $Black
    $lblHead = New-Object System.Windows.Forms.Label
    $lblHead.Text = "Leftovers of  $Name"; $lblHead.ForeColor = $White; $lblHead.AutoSize = $true
    $lblHead.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 14); $lblHead.Location = New-Object System.Drawing.Point(16, 10)
    $pnlHead.Controls.Add($lblHead)
    $acc = New-Object System.Windows.Forms.Panel; $acc.Dock = 'Top'; $acc.Height = 4; $acc.BackColor = $Purple

    $dlg.Controls.Add($g); $dlg.Controls.Add($pnlBottom); $dlg.Controls.Add($lblNote); $dlg.Controls.Add($acc); $dlg.Controls.Add($pnlHead)

    $script:dlgForm = $dlg
    $script:dlgBlocked = $blocked
    $g.Add_CurrentCellDirtyStateChanged({ if ($script:dlgGrid.IsCurrentCellDirty) { $script:dlgGrid.CommitEdit('CurrentCellChange') } })
    $bAll.Add_Click({ foreach ($r in $script:dlgGrid.Rows) { $r.Cells[0].Value = $true } })
    $bNone.Add_Click({ foreach ($r in $script:dlgGrid.Rows) { $r.Cells[0].Value = $false } })
    $bKeep.Add_Click({ $script:DlgResult = $null; $script:dlgForm.Close() })
    $bSave.Add_Click({
        $sfd = New-Object System.Windows.Forms.SaveFileDialog
        $sfd.Filter = 'CSV (*.csv)|*.csv'; $sfd.FileName = "Leftovers_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
        if ($sfd.ShowDialog() -eq 'OK') {
            $script:dlgItems | Select-Object Program, Kind, Category, Display, Path, Extra, Detail | Export-Csv -Path $sfd.FileName -NoTypeInformation -Encoding UTF8
            Add-LogLine "Leftover list saved to $($sfd.FileName)"
        }
    })
    $bDel.Add_Click({
        $sel = @()
        foreach ($r in $script:dlgGrid.Rows) { if ($r.Cells[0].Value -eq $true) { $sel += $r.Tag } }
        if (-not $sel.Count) { [void][System.Windows.Forms.MessageBox]::Show($script:dlgForm, 'Nothing is selected.', 'Software Manager', 'OK', 'Information'); return }
        $script:DlgResult = $sel
        $script:dlgForm.Close()
    })
    [void]$dlg.ShowDialog($form)
    return $script:DlgResult
}

function Complete-Scan($s, $reason) {
    if (-not $s) { [void](Show-Box "The leftover scan failed.`n$reason" 'Software Manager' 'OK' 'Error'); Start-Load; return }
    foreach ($n in @($s.Notes)) { Add-LogLine $n }
    foreach ($it in @($s.Items)) { $it | Add-Member -NotePropertyName Program -NotePropertyValue $s.Name -Force }
    Review-Leftovers @($s.Items) $s.Name
}

# Shows the merged leftover list, asks, then deletes what the user ticked
function Review-Leftovers($Items, [string]$Title) {
    $items = @($Items)
    if ($items.Count -eq 0) {
        Add-LogLine 'No leftovers found.'
        [void](Show-Box "No leftovers of '$Title' were found." 'Software Manager' 'OK' 'Information'); Start-Load; return
    }
    Add-LogLine "$($items.Count) leftover(s) found."
    $chosen = @(Show-LeftoverDialog $items $Title $script:Guard)
    if (-not $chosen.Count -or -not $chosen[0]) { Add-LogLine 'Leftovers kept. Nothing was deleted.'; Start-Load; return }
    $msg = "Delete $($chosen.Count) item(s) PERMANENTLY?`nThere is no backup and no undo.`n`n" + (($chosen | Select-Object -First 8 | ForEach-Object { "- $($_.Display)" }) -join "`n")
    if ($chosen.Count -gt 8) { $msg += "`n... and $($chosen.Count - 8) more" }
    if ((Show-Box $msg 'Confirm deletion' 'YesNo' 'Warning') -ne 'Yes') { Add-LogLine 'Deletion cancelled. Nothing was deleted.'; Start-Load; return }
    $arg = Get-ArgBase
    $arg.Items = $chosen
    Start-Op 'Deleting leftovers' $DeleteBody $arg { param($d, $dr) Complete-Delete $d $dr }
}

function Complete-Delete($d, $reason) {
    if (-not $d) { [void](Show-Box "The deletion failed.`n$reason" 'Software Manager' 'OK' 'Error'); Start-Load; return }
    if ($d.Guard) { Update-Banner $d.Guard }
    if ($d.Blocked) {
        Add-LogLine "Deletion blocked: $($d.Blocked)"
        [void](Show-Box "Deletion blocked by the safety rules: $($d.Blocked). Nothing was deleted." 'Blocked' 'OK' 'Warning'); Start-Load; return
    }
    $ok = 0; $bad = @()
    foreach ($r in @($d.Results)) {
        if ($r.Ok) { $ok++; Add-LogLine "Deleted: $($r.Display)" } else { $bad += "$($r.Display): $($r.Message)"; Add-LogLine "NOT deleted: $($r.Display) - $($r.Message)" }
    }
    $text = "$ok item(s) deleted."
    if ($bad.Count) { $text += "`n`n$($bad.Count) item(s) could not be deleted:`n" + (($bad | Select-Object -First 10) -join "`n") }
    [void](Show-Box $text 'Software Manager' 'OK' 'Information')
    Start-Load
}

# --- "Scan leftovers by name": read-only scan of a program that is already uninstalled (e.g. after a restart) ---
Add-Type -AssemblyName Microsoft.VisualBasic
$btnScan = New-FlatButton 'Scan leftovers...' $Gray 150
$btnScan.Location = New-Object System.Drawing.Point(348, 11)
$pnlActions.Controls.Add($btnScan)
$lblSelected.Location = New-Object System.Drawing.Point(520, 11); $lblSelected.Size = New-Object System.Drawing.Size(600, 34)

$btnScan.Add_Click({
    $typed = [Microsoft.VisualBasic.Interaction]::InputBox('Name of the program that was already uninstalled (read-only scan; you choose what to delete afterwards):', 'Scan leftovers', '')
    if ([string]::IsNullOrWhiteSpace($typed)) { return }
    $arg = Get-ArgBase
    $arg.Entry = @{ Name = $typed.Trim(); Publisher = ''; KeyPath = ''; InstallLocation = ''; UninstallString = '' }
    Start-Op "Scanning leftovers of $($typed.Trim())" $ScanBody $arg { param($s, $sr) Complete-Scan $s $sr }
})

$btnUninstall.Add_Click({ Invoke-EntryAction 'Uninstall' })
$btnRepair.Add_Click({ Invoke-EntryAction 'Repair' })
$grid.Add_CellDoubleClick({ })   # no accidental action on double click

$form.Add_FormClosing({
    param($s, $ev)
    if ($script:Busy) {
        if ((Show-Box 'An operation is still running. Closing now does not stop an uninstaller already started. Close anyway?' 'Software Manager' 'YesNo' 'Warning') -ne 'Yes') { $ev.Cancel = $true }
    }
})
$form.Add_Shown({ Start-Load })

[void]$form.ShowDialog()
