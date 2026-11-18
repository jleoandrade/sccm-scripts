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
    - Decodes the HRESULT (Severity / Facility / Code) and looks up the Windows error message.
    - Filter, CSV export and clipboard copy.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -STA -File .\ConversorCodigosErro.ps1
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

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
#  Conversion logic
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

$script:DescCache = @{}

function Get-ErrorDescription {
    param([int]$Signed, [int]$Facility, [int]$Code)

    if ($script:DescCache.ContainsKey($Signed)) { return $script:DescCache[$Signed] }

    $msg = ''
    try {
        # Plain Win32 error (e.g. 5) uses the value itself; HRESULT 0x8007xxxx uses the Win32 code.
        $id = if ($Signed -ge 0) { $Signed } elseif ($Facility -eq 7) { $Code } else { $Signed }
        $msg = [System.ComponentModel.Win32Exception]::new($id).Message
        if ($msg -match '^(Unknown error|Erro desconhecido|Error desconocido)') { $msg = '' }
    } catch { $msg = '' }

    $script:DescCache[$Signed] = $msg
    return $msg
}

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

        if ($WithDescription) { $r.Description = Get-ErrorDescription -Signed $signed -Facility $facility -Code $code }
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
$form.Text          = 'Error Code Converter  —  Decimal ⇄ Hexadecimal'
$form.Size          = New-Object System.Drawing.Size(1280, 820)
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
$lblSubtitle.Text      = 'Decimal ⇄ Hexadecimal  •  HRESULT decoder  •  Bulk conversion'
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
$lblStatus.Text      = 'Ready.'
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

$grpQuick = New-Group 'Quick conversion (type a code — converts as you type)'
$quickHost.Controls.Add($grpQuick)

$txtQuick = New-Object System.Windows.Forms.TextBox
$txtQuick.Font        = $fontBig
$txtQuick.ForeColor   = $Theme.Black
$txtQuick.BorderStyle = 'FixedSingle'
$txtQuick.Location    = New-Object System.Drawing.Point(15, 30)
$txtQuick.Width       = 330
$txtQuick.Text        = '-2133837819'

$lblArrow = New-Object System.Windows.Forms.Label
$lblArrow.Text      = '→'
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
$lblQInfo.Size      = New-Object System.Drawing.Size(1220, 40)
$lblQInfo.Anchor    = 'Top, Left, Right'
$lblQInfo.ForeColor = $Theme.GrayText

$grpQuick.Controls.AddRange(@($txtQuick, $lblArrow, $lblQHex, $btnQCopy, $lblQInfo))

function Update-Quick {
    $res = Convert-ErrorCode -Value $txtQuick.Text -WithDescription
    if ($res.Status -like 'ERROR*') {
        $lblQHex.Text      = '—'
        $lblQHex.ForeColor = $Theme.ErrorText
        $lblQInfo.Text     = $res.Status
    } else {
        $lblQHex.Text      = $res.Hex
        $lblQHex.ForeColor = $Theme.Purple
        $info = "Int32: $($res.Int32)   |   UInt32: $($res.UInt32)   |   Severity: $($res.Severity)   |   Facility: $($res.Facility)   |   Code: $($res.Code)"
        if ($res.Status -ne 'OK') { $info += "   |   $($res.Status)" }
        if ($res.Description)     { $info += "`r`n$($res.Description.Trim())" }
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
$tip.SetToolTip($chkDesc, 'Queries the Windows error message (slightly slower on huge lists)')

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
$txtFilter.Width       = 200
$txtFilter.Font        = $fontUI
$txtFilter.BorderStyle = 'FixedSingle'
$txtFilter.Margin      = New-Object System.Windows.Forms.Padding(3, 5, 10, 0)
$tip.SetToolTip($txtFilter, 'Filters by input, hex, facility, description or status')

$btnExport  = New-Btn 'Export CSV' 100
$btnCopyAll = New-Btn 'Copy table' 100
$btnCopyHex = New-Btn 'Copy Hex only' 110
$flowOut.Controls.AddRange(@($lblFilter, $txtFilter, $btnExport, $btnCopyAll, $btnCopyHex))

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
$script:Columns = @('#', 'Input', 'Hex', 'Int32', 'UInt32', 'Severity', 'Facility', 'Code', 'Description', 'Status')
$script:Table = New-Object System.Data.DataTable 'Results'
foreach ($c in $script:Columns) {
    $type = if ($c -eq '#') { [int] } else { [string] }
    [void]$script:Table.Columns.Add($c, $type)
}
$grid.DataSource = $script:Table.DefaultView

$widths = @{ '#'=55; Input=150; Hex=110; Int32=115; UInt32=105; Severity=95; Facility=170; Code=115; Status=150 }
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
    $errors = 0

    for ($i = 0; $i -lt $codes.Count; $i++) {
        $r = Convert-ErrorCode -Value $codes[$i] -WithDescription:$withDesc
        if ($r.Status -like 'ERROR*') { $errors++ }
        [void]$script:Table.Rows.Add(($i + 1), $r.Input, $r.Hex, [string]$r.Int32, [string]$r.UInt32,
                                     $r.Severity, $r.Facility, $r.Code, ([string]$r.Description).Trim(), $r.Status)
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
    $lblStatus.Text = "{0} code(s) converted in {1:N2}s  —  {2} error(s)." -f $codes.Count, $sw.Elapsed.TotalSeconds, $errors
    Apply-Filter
}

function Apply-Filter {
    $f = $txtFilter.Text.Trim().Replace("'", "''").Replace('[', '[[]').Replace('*', '[*]').Replace('%', '[%]')
    if ([string]::IsNullOrEmpty($f)) {
        $script:Table.DefaultView.RowFilter = ''
    } else {
        $cols = 'Input', 'Hex', 'Int32', 'Facility', 'Code', 'Description', 'Status'
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
    $split.SplitterDistance = [int]($split.Width * 0.30)
    Set-GridColumns
    Update-Quick
    Apply-Filter
    $txtQuick.Focus()
    $txtQuick.SelectAll()
})

[void]$form.ShowDialog()
$form.Dispose()
