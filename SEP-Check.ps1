#Requires -Version 5.1
<#
.SYNOPSIS
    Checks DNS health and looks for Symantec Endpoint Protection (SEP) traces on Windows machines.

.DESCRIPTION
    For each machine:
      1. DNS   : forward lookup (A record), ping, reverse lookup (PTR, same as "ping -a").
                 Reports OK / WARN / FAIL in the DnsStatus column.
      2. Folders: Program Files, Program Files (x86) and ProgramData (top level + 1 sub-level)
                 for names matching Symantec / SEP.
      3. Registry: HKLM\SOFTWARE\Symantec (32/64-bit), Uninstall entries and Services
                 matching Symantec / SEP.
    Machines not scanned (offline, no DNS, WinRM error) can be retried in more cycles.
    Results are saved to a CSV report after every cycle.

    Requirements:
      - Run as an account with local admin rights on the target machines.
      - WinRM (PowerShell Remoting) enabled on remote targets.
      - Windows 8 / Server 2012 or newer on the machine running the script (Resolve-DnsName).

    This file is also used by SEP-Check-GUI.ps1 (keep both in the same folder).

.EXAMPLE
    .\SEP-Check.ps1 -ComputerName PC001
.EXAMPLE
    .\SEP-Check.ps1 -ListPath .\computers.txt -Cycles 8 -IntervalMinutes 60
#>
[CmdletBinding(DefaultParameterSetName = 'Single')]
param(
    [Parameter(ParameterSetName = 'Single', Position = 0)]
    [string]$ComputerName = $env:COMPUTERNAME,

    [Parameter(ParameterSetName = 'List', Mandatory = $true)]
    [string]$ListPath,

    [ValidateRange(1, 1000)][int]$Cycles = 1,
    [ValidateRange(1, 1440)][int]$IntervalMinutes = 30,
    [string]$OutputPath,
    [switch]$NoPrompt
)

# Matches Symantec / SEP names and known SEP service/driver names.
$SepPattern = '(?i)symantec|(?<![a-z])sepm?(?![a-z])|sepmasterservice|smcservice|ccsvchst|srtsp|symevent|symelam|symefa|symiron|bhdrv|idsvi|eectrl|sysplant'

# Runs ON the target machine. Kept PowerShell 2.0 compatible for old endpoints.
$SepScanBlock = {
    param([string]$Pattern)

    $folders = @(@(
        foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData)) {
            if (-not $root -or -not (Test-Path -LiteralPath $root)) { continue }
            Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.PSIsContainer } | ForEach-Object {
                    if ($_.Name -match $Pattern) { $_.FullName }
                    Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSIsContainer -and $_.Name -match $Pattern } |
                        ForEach-Object { $_.FullName }
                }
        }
    ) | Sort-Object -Unique)

    $reg = New-Object 'System.Collections.Generic.List[string]'
    foreach ($key in 'HKLM:\SOFTWARE\Symantec', 'HKLM:\SOFTWARE\WOW6432Node\Symantec') {
        if (Test-Path $key) {
            $reg.Add($key)
            Get-ChildItem $key -ErrorAction SilentlyContinue |
                ForEach-Object { $reg.Add(($_.Name -replace '^HKEY_LOCAL_MACHINE', 'HKLM:')) }
        }
    }
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { "$($_.DisplayName) $($_.Publisher)" -match $Pattern } |
        ForEach-Object { $reg.Add("Uninstall: $($_.DisplayName) $($_.DisplayVersion) [$($_.PSChildName)]") }
    Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\*' -ErrorAction SilentlyContinue |
        Where-Object { "$($_.PSChildName) $($_.DisplayName) $($_.ImagePath)" -match $Pattern } |
        ForEach-Object { $reg.Add("Service: $($_.PSChildName)") }

    New-Object PSObject -Property @{ Folders = @($folders); Registry = @($reg) }
}

function Resolve-Target([string]$Name) {
    $n = "$Name".Trim()
    if ($n -in 'localhost', '.', '127.0.0.1', '::1') { return $env:COMPUTERNAME }
    $n
}

function Read-ComputerList([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw "List file not found: $Path" }
    @(Get-Content -LiteralPath $Path |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith('#') } |
        ForEach-Object { Resolve-Target $_ } |
        Sort-Object -Unique)
}

function Test-Ping([string]$Address) {
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        foreach ($i in 1..2) {
            try { if ($ping.Send($Address, 1000).Status -eq 'Success') { return $true } } catch { }
        }
        $false
    } finally { $ping.Dispose() }
}

function Test-DnsHealth([string]$Name) {
    $r = [ordered]@{ IPAddress = ''; Ping = 'Fail'; ReverseName = ''; DnsStatus = '' }

    try { $a = @(Resolve-DnsName -Name $Name -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'A' }) }
    catch { $a = @() }
    if (-not $a) {
        $r.DnsStatus = 'FAIL: no A record (forward lookup failed)'
        return [pscustomobject]$r
    }

    $ip = $a[0].IPAddress
    $r.IPAddress = $ip
    if (Test-Ping $ip) { $r.Ping = 'OK' }

    try { $ptr = Resolve-DnsName -Name $ip -Type PTR -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { $_.Type -eq 'PTR' } | Select-Object -First 1 -ExpandProperty NameHost }
    catch { $ptr = $null }
    $r.ReverseName = "$ptr"

    $r.DnsStatus = if (-not $ptr) { "FAIL: no PTR record for $ip (reverse lookup failed)" }
        elseif (($ptr -split '\.')[0] -ne ($Name -split '\.')[0]) { "FAIL: PTR mismatch, $ip resolves to $ptr" }
        elseif ($a.Count -gt 1) { "WARN: multiple A records ($(($a | ForEach-Object { $_.IPAddress }) -join ', '))" }
        else { 'OK' }
    [pscustomobject]$r
}

# Scans the given machines once. Returns one result row per machine.
function Invoke-SepScan([string[]]$ComputerName, [int]$Cycle = 1) {
    $rows = foreach ($c in $ComputerName) {
        $dns = Test-DnsHealth $c
        [pscustomobject]@{
            Computer     = $c
            Status       = ''
            DnsStatus    = $dns.DnsStatus
            IPAddress    = $dns.IPAddress
            Ping         = $dns.Ping
            ReverseName  = $dns.ReverseName
            SepDetected  = 'Unknown'
            FolderHits   = ''
            RegistryHits = ''
            Error        = ''
            Cycle        = $Cycle
            ScanTime     = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        }
    }

    $results = @{}
    $remoteErrors = @()
    $local = $rows | Where-Object { $_.Computer -eq $env:COMPUTERNAME }
    if ($local) { $results[$local.Computer] = & $SepScanBlock $SepPattern }

    $remote = @($rows | Where-Object { $_.IPAddress -and $_.Computer -ne $env:COMPUTERNAME } | ForEach-Object { $_.Computer })
    if ($remote) {
        $opt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 300000
        try {
            Invoke-Command -ComputerName $remote -ScriptBlock $SepScanBlock -ArgumentList $SepPattern `
                -SessionOption $opt -ErrorAction SilentlyContinue -ErrorVariable remoteErrors |
                ForEach-Object { $results[$_.PSComputerName] = $_ }
        } catch { $remoteErrors += $_ }
    }

    foreach ($r in $rows) {
        $res = $results[$r.Computer]
        if ($res) {
            $r.Status       = 'Scanned'
            $r.FolderHits   = @($res.Folders) -join '; '
            $r.RegistryHits = @($res.Registry) -join '; '
            $r.SepDetected  = if ($r.FolderHits -or $r.RegistryHits) { 'Yes' } else { 'No' }
        }
        elseif (-not $r.IPAddress) { $r.Status = 'NotResolved' }
        elseif ($r.Ping -ne 'OK')  { $r.Status = 'Offline' }
        else {
            $r.Status = 'RemoteError'
            $msg = $remoteErrors | Where-Object { "$_" -like "*$($r.Computer)*" } | Select-Object -First 1
            $r.Error = if ($msg) { "$msg".Trim() } else { 'Remote query failed (check WinRM / admin rights)' }
        }
    }
    $rows
}

# Stop here when dot-sourced (used by the GUI script).
if ($MyInvocation.InvocationName -eq '.') { return }

# ---------------- Main ----------------
if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot "SEP_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv" }
$targets = if ($ListPath) { Read-ComputerList $ListPath } else { @(Resolve-Target $ComputerName) }
if (-not $targets) { Write-Error 'No machines to scan.'; exit 1 }

$report = @{}   # latest result per machine
$cycleNo = 0
$planned = $Cycles

while ($true) {
    for ($i = 1; $i -le $planned -and $targets; $i++) {
        $cycleNo++
        Write-Host "`n[Cycle $cycleNo] Scanning $($targets.Count) machine(s)..." -ForegroundColor Magenta
        $rows = @(Invoke-SepScan -ComputerName $targets -Cycle $cycleNo)
        foreach ($r in $rows) { $report[$r.Computer] = $r }
        $rows | Format-Table Computer, Status, SepDetected, DnsStatus, IPAddress -AutoSize | Out-Host

        $report.Values | Sort-Object Computer | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "Report saved: $OutputPath" -ForegroundColor Green

        $targets = @($rows | Where-Object { $_.Status -ne 'Scanned' } | ForEach-Object { $_.Computer })
        if ($targets -and $i -lt $planned) {
            Write-Host "$($targets.Count) machine(s) pending. Next cycle at $((Get-Date).AddMinutes($IntervalMinutes).ToString('HH:mm'))..." -ForegroundColor Yellow
            Start-Sleep -Seconds ($IntervalMinutes * 60)
        }
    }

    if (-not $targets -or $NoPrompt) { break }

    Write-Host "`n$($targets.Count) machine(s) not scanned: $($targets -join ', ')" -ForegroundColor Yellow
    $answer = Read-Host 'How many more cycles do you want to run? (0 = exit)'
    $n = 0
    if (-not [int]::TryParse($answer, [ref]$n) -or $n -le 0) { break }
    $min = Read-Host "Interval between cycles in minutes [$IntervalMinutes]"
    $m = 0
    if ([int]::TryParse($min, [ref]$m) -and $m -gt 0) { $IntervalMinutes = $m }
    $planned = $n
}

Write-Host "`nDone. Final report: $OutputPath" -ForegroundColor Green
