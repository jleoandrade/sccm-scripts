#Requires -Version 5.1
<#
.SYNOPSIS
    GUI for SEP-Check.ps1: DNS health + Symantec Endpoint Protection (SEP) trace detection.

.DESCRIPTION
    Standalone: does not need SEP-Check.ps1. Scans run in the background so the window stays responsive.
    Run with Windows PowerShell:  powershell.exe -ExecutionPolicy Bypass -File .\SEP-Check-GUI.ps1
#>
Add-Type -AssemblyName System.Windows.Forms, System.Drawing, Microsoft.VisualBasic
[System.Windows.Forms.Application]::EnableVisualStyles()

# ---------------- Scan logic ----------------
# Same logic as SEP-Check.ps1, embedded so this GUI runs on its own (no other file needed).
$Core = {
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

    # Accepts names separated by new lines, commas, semicolons, spaces or tabs.
    function ConvertTo-ComputerList([string[]]$Text) {
        @($Text -split '[\s,;]+' |
            Where-Object { $_ } |
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
}
. $Core

# ---------------- Accenture palette ----------------
function Hex([string]$h) { [System.Drawing.ColorTranslator]::FromHtml($h) }
$Purple     = Hex '#A100FF'
$DarkPurple = Hex '#7500C0'
$DeepPurple = Hex '#460073'
$LightPurp  = Hex '#E6DCFF'
$PalePurp   = Hex '#F7F2FF'
$Black      = Hex '#000000'
$White      = Hex '#FFFFFF'
$Gray       = Hex '#6E6E6E'
$Red        = Hex '#D0021B'
$Font       = New-Object System.Drawing.Font('Segoe UI', 9)
$BoldFont   = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)

function New-Control([string]$Type, [string]$Text, [int]$X, [int]$Y, [int]$W, [int]$H = 24) {
    $c = New-Object "System.Windows.Forms.$Type"
    $c.Text = $Text
    $c.SetBounds($X, $Y, $W, $H)
    $c.Font = $Font
    $c
}

function New-Button([string]$Text, [int]$X, [int]$Y, [int]$W = 110) {
    $b = New-Control Button $Text $X $Y $W 30
    $b.FlatStyle = 'Flat'
    $b.FlatAppearance.BorderSize = 0
    $b.FlatAppearance.MouseOverBackColor = $DarkPurple
    $b.BackColor = $Purple
    $b.ForeColor = $White
    $b.Font = $BoldFont
    $b.Cursor = 'Hand'
    $b
}

# ---------------- Layout ----------------
$form = New-Object System.Windows.Forms.Form
$form.Text = 'SEP Check'
$form.Size = New-Object System.Drawing.Size(1180, 700)
$form.MinimumSize = New-Object System.Drawing.Size(1100, 500)
$form.StartPosition = 'CenterScreen'
$form.BackColor = $White
$form.Font = $Font

$header = New-Object System.Windows.Forms.Panel
$header.Dock = 'Top'; $header.Height = 60; $header.BackColor = $Black
$title = New-Control Label 'SEP / Symantec Detection Tool' 18 8 700 28
$title.Font = New-Object System.Drawing.Font('Segoe UI', 15, [System.Drawing.FontStyle]::Bold)
$title.ForeColor = $White
$subtitle = New-Control Label 'DNS health check (ping / reverse lookup) and Symantec Endpoint Protection footprint' 20 36 800 20
$subtitle.ForeColor = Hex '#BE82FF'
$header.Controls.AddRange(@($title, $subtitle))

$stripe = New-Object System.Windows.Forms.Panel
$stripe.Dock = 'Top'; $stripe.Height = 4; $stripe.BackColor = $Purple

$top = New-Object System.Windows.Forms.Panel
$top.Dock = 'Top'; $top.Height = 92; $top.BackColor = $PalePurp

$rbSingle  = New-Control RadioButton 'Single machine' 16 16 140
$rbSingle.Checked = $true
$txtSingle = New-Control TextBox $env:COMPUTERNAME 160 16 260
$rbList    = New-Control RadioButton 'Multiple machines' 16 52 140
$btnList   = New-Button 'Enter machines...' 160 49 160
$lblCount  = New-Control Label 'No machines entered' 330 55 200
$lblCount.ForeColor = $Gray

$lblCycles   = New-Control Label 'Cycles' 548 19 90
$nudCycles   = New-Control NumericUpDown '' 640 16 70
$nudCycles.Minimum = 1; $nudCycles.Maximum = 1000; $nudCycles.Value = 1
$lblInterval = New-Control Label 'Interval (min)' 548 55 90
$nudInterval = New-Control NumericUpDown '' 640 52 70
$nudInterval.Minimum = 1; $nudInterval.Maximum = 1440; $nudInterval.Value = 30

$btnStart  = New-Button 'Start' 740 13
$btnStop   = New-Button 'Stop' 860 13
$btnStop.Enabled = $false
$btnExport = New-Button 'Export CSV' 740 49 230
$btnExport.BackColor = $DeepPurple

$top.Controls.AddRange(@($rbSingle, $txtSingle, $rbList, $btnList, $lblCount,
    $lblCycles, $nudCycles, $lblInterval, $nudInterval, $btnStart, $btnStop, $btnExport))

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = 'Fill'
$grid.ReadOnly = $true
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.RowHeadersVisible = $false
$grid.SelectionMode = 'FullRowSelect'
$grid.AutoSizeColumnsMode = 'DisplayedCells'
$grid.BackgroundColor = $White
$grid.BorderStyle = 'None'
$grid.GridColor = $LightPurp
$grid.EnableHeadersVisualStyles = $false
$grid.ColumnHeadersDefaultCellStyle.BackColor = $DeepPurple
$grid.ColumnHeadersDefaultCellStyle.ForeColor = $White
$grid.ColumnHeadersDefaultCellStyle.Font = $BoldFont
$grid.ColumnHeadersHeight = 30
$grid.DefaultCellStyle.SelectionBackColor = $Purple
$grid.DefaultCellStyle.SelectionForeColor = $White
$grid.AlternatingRowsDefaultCellStyle.BackColor = $PalePurp

$statusBar = New-Object System.Windows.Forms.StatusStrip
$statusBar.BackColor = $Black
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.ForeColor = $White
$statusLabel.Text = 'Ready.'
[void]$statusBar.Items.Add($statusLabel)

# Fill first, header last (WinForms docking order).
$form.Controls.AddRange(@($grid, $statusBar, $top, $stripe, $header))

# ---------------- State ----------------
$Table = New-Object System.Data.DataTable
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 500
$script:Job = $null          # running background scan
$script:Pending = @()        # machines not scanned yet
$script:CyclesLeft = 0
$script:CycleNo = 0
$script:NextRun = $null
$script:DeviceText = ''      # text typed/pasted in the machine list window

function Set-Status([string]$Text) { $statusLabel.Text = $Text }

function Update-Grid($Rows) {
    foreach ($r in $Rows) {
        if ($Table.Columns.Count -eq 0) {
            foreach ($p in $r.PSObject.Properties) { [void]$Table.Columns.Add($p.Name) }
            $Table.PrimaryKey = @($Table.Columns['Computer'])
            $grid.DataSource = $Table
        }
        $dr = $Table.Rows.Find($r.Computer)
        $isNew = $null -eq $dr
        if ($isNew) { $dr = $Table.NewRow() }
        foreach ($p in $r.PSObject.Properties) { $dr[$p.Name] = [string]$p.Value }
        if ($isNew) { $Table.Rows.Add($dr) }
    }
}

function Show-DeviceListDialog([string]$Text) {
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = 'Machine list'
    $dlg.ClientSize = New-Object System.Drawing.Size(420, 450)
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false
    $dlg.StartPosition = 'CenterParent'
    $dlg.BackColor = $White
    $dlg.Font = $Font

    $lbl = New-Control Label 'Type or paste the machine names (one per line, or separated by comma / space):' 12 10 396 34
    $txt = New-Control TextBox $Text 12 48 396 340
    $txt.Multiline = $true
    $txt.AcceptsReturn = $true
    $txt.ScrollBars = 'Vertical'
    $txt.Font = New-Object System.Drawing.Font('Consolas', 10)
    $ok = New-Button 'OK' 188 402 100
    $ok.DialogResult = 'OK'
    $cancel = New-Button 'Cancel' 298 402 110
    $cancel.DialogResult = 'Cancel'
    $cancel.BackColor = $DeepPurple
    $dlg.CancelButton = $cancel
    $dlg.Controls.AddRange(@($lbl, $txt, $ok, $cancel))

    $result = if ($dlg.ShowDialog($form) -eq 'OK') { $txt.Text } else { $null }
    $dlg.Dispose()
    $result
}

function Start-Cycle {
    $script:CycleNo++
    $script:CyclesLeft--
    Set-Status ("Cycle {0}: scanning {1} machine(s)..." -f $script:CycleNo, $script:Pending.Count)
    $ps = [PowerShell]::Create()
    [void]$ps.AddScript({
        param($CoreText, $Targets, $Cycle)
        . ([scriptblock]::Create($CoreText))
        Invoke-SepScan -ComputerName $Targets -Cycle $Cycle
    }).AddArgument($Core.ToString()).AddArgument($script:Pending).AddArgument($script:CycleNo)
    $script:Job = @{ PS = $ps; Handle = $ps.BeginInvoke() }
}

function Stop-Run([string]$Message) {
    $timer.Stop()
    $script:NextRun = $null
    $script:CyclesLeft = 0
    $btnStart.Enabled = $true
    $btnStop.Enabled = $false
    Set-Status $Message
}

function Complete-Cycle {
    if (-not $script:Pending) { Stop-Run "Done. All machines scanned (cycle $script:CycleNo)."; return }
    if ($script:CyclesLeft -gt 0) { $script:NextRun = (Get-Date).AddMinutes([double]$nudInterval.Value); return }

    $timer.Stop()
    $msg = "$($script:Pending.Count) machine(s) were not scanned (offline / unreachable):`n" +
           (($script:Pending | Select-Object -First 10) -join ', ') +
           "`n`nHow many more cycles do you want to run? (0 = stop)`n" +
           "Interval between cycles: $($nudInterval.Value) min (change it in the main window)."
    $answer = [Microsoft.VisualBasic.Interaction]::InputBox($msg, 'Run more cycles?', '1')
    $n = 0
    if (-not [int]::TryParse($answer, [ref]$n) -or $n -le 0) {
        Stop-Run "Finished. $($script:Pending.Count) machine(s) not scanned."
        return
    }
    $script:CyclesLeft = $n
    $timer.Start()
    Start-Cycle
}

# ---------------- Events ----------------
$timer.Add_Tick({
    if ($script:Job) {
        if (-not $script:Job.Handle.IsCompleted) { return }
        try {
            $rows = @($script:Job.PS.EndInvoke($script:Job.Handle))
            Update-Grid $rows
            $script:Pending = @($rows | Where-Object { $_.Status -ne 'Scanned' } | ForEach-Object { $_.Computer })
        } catch {
            Set-Status "Cycle $script:CycleNo failed: $($_.Exception.Message)"
        }
        $script:Job.PS.Dispose()
        $script:Job = $null
        Complete-Cycle
        return
    }
    if ($script:NextRun) {
        $left = $script:NextRun - (Get-Date)
        if ($left.TotalSeconds -le 0) { $script:NextRun = $null; Start-Cycle }
        else { Set-Status ("{0} machine(s) pending. Next cycle in {1:hh\:mm\:ss}" -f $script:Pending.Count, $left) }
    }
})

$btnList.Add_Click({
    $text = Show-DeviceListDialog $script:DeviceText
    if ($null -eq $text) { return }
    $script:DeviceText = $text
    $count = @(ConvertTo-ComputerList $text).Count
    $lblCount.Text = if ($count) { "$count machine(s) entered" } else { 'No machines entered' }
    $rbList.Checked = $true
})

$btnStart.Add_Click({
    $targets = if ($rbList.Checked) { ConvertTo-ComputerList $script:DeviceText } else { ConvertTo-ComputerList $txtSingle.Text }
    if (-not $targets) {
        [void][System.Windows.Forms.MessageBox]::Show('No machines to scan.', 'SEP Check', 'OK', 'Warning')
        return
    }
    $Table.Rows.Clear()
    $script:Pending = $targets
    $script:CycleNo = 0
    $script:CyclesLeft = [int]$nudCycles.Value
    $btnStart.Enabled = $false
    $btnStop.Enabled = $true
    $timer.Start()
    Start-Cycle
})

$btnStop.Add_Click({
    if ($script:Job) {
        try { $script:Job.PS.Stop() } catch { }
        $script:Job.PS.Dispose()
        $script:Job = $null
    }
    Stop-Run 'Stopped by user.'
})

$btnExport.Add_Click({
    if ($Table.Rows.Count -eq 0) {
        [void][System.Windows.Forms.MessageBox]::Show('Nothing to export yet.', 'SEP Check', 'OK', 'Information')
        return
    }
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV files (*.csv)|*.csv'
    $dlg.FileName = "SEP_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($dlg.ShowDialog() -eq 'OK') {
        $cols = @($Table.Columns | ForEach-Object { $_.ColumnName })
        $Table.Rows | Select-Object $cols | Export-Csv -LiteralPath $dlg.FileName -NoTypeInformation -Encoding UTF8
        Set-Status "Exported: $($dlg.FileName)"
    }
})

$grid.Add_CellFormatting({
    param($s, $e)
    $col = $grid.Columns[$e.ColumnIndex].Name
    $val = [string]$e.Value
    if ($col -eq 'SepDetected' -and $val -eq 'Yes') { $e.CellStyle.ForeColor = $Purple; $e.CellStyle.Font = $BoldFont }
    elseif ($col -eq 'DnsStatus' -and $val -like 'FAIL*') { $e.CellStyle.ForeColor = $Red }
    elseif ($col -eq 'Status' -and $val -and $val -ne 'Scanned') { $e.CellStyle.ForeColor = $Gray }
})

$form.Add_FormClosing({
    $timer.Stop()
    if ($script:Job) { try { $script:Job.PS.Stop(); $script:Job.PS.Dispose() } catch { } }
})

[void]$form.ShowDialog()
$timer.Dispose()
$form.Dispose()
