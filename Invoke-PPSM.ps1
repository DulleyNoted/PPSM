#Requires -Version 5.1
# PPSM Monitor - Ports, Protocols and Services Management
# GUI tool: Start Scan, Load Config, Export Excel

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#region BOOTSTRAP

function Assert-PPSMDependencies {
    $missing = @()
    foreach ($mod in @('powershell-yaml', 'ImportExcel')) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            $missing += $mod
        }
    }
    if ($missing.Count -gt 0) {
        $list = $missing -join "', '"
        Write-Error @"
[ERROR] Missing required PowerShell module(s): $($missing -join ', ')

Install with:
    Install-Module '$list' -Scope CurrentUser -Force

Then re-run the script.
"@ -ErrorAction Stop
    }

    foreach ($mod in @('powershell-yaml', 'ImportExcel')) {
        if (-not (Get-Module -Name $mod)) {
            Import-Module $mod -ErrorAction Stop
        }
    }

    try {
        Add-Type -AssemblyName 'System.Drawing' -ErrorAction Stop
    } catch {
        Write-Warning "[WARN] System.Drawing assembly unavailable: $_"
    }
}

Assert-PPSMDependencies

#endregion BOOTSTRAP

#region DATA-MODEL

$Script:HIGH_RISK_PORTS = [System.Collections.Generic.HashSet[int]]@(
    21, 23, 135, 137, 138, 139, 445, 1433, 3389, 4444, 5900
)
$Script:MEDIUM_RISK_PORTS = [System.Collections.Generic.HashSet[int]]@(
    22, 25, 53, 80, 110, 143, 3306, 5432, 6379, 9200, 27017
)
$Script:WELL_KNOWN_PORTS = @{
    20 = 'FTP-Data';  21 = 'FTP';       22 = 'SSH';       23 = 'Telnet'
    25 = 'SMTP';      53 = 'DNS';        67 = 'DHCP';      68 = 'DHCP'
    69 = 'TFTP';      80 = 'HTTP';      110 = 'POP3';     119 = 'NNTP'
   123 = 'NTP';      135 = 'RPC';      137 = 'NetBIOS';  138 = 'NetBIOS'
   139 = 'NetBIOS'; 143 = 'IMAP';      161 = 'SNMP';     162 = 'SNMP-Trap'
   389 = 'LDAP';    443 = 'HTTPS';     445 = 'SMB';      465 = 'SMTPS'
   500 = 'IKE';     514 = 'Syslog';    515 = 'LPD';      587 = 'SMTP-Sub'
   631 = 'IPP';     636 = 'LDAPS';     993 = 'IMAPS';    995 = 'POP3S'
  1080 = 'SOCKS';  1194 = 'OpenVPN'; 1433 = 'MSSQL';  1521 = 'Oracle'
  1723 = 'PPTP';   2049 = 'NFS';     3306 = 'MySQL';   3389 = 'RDP'
  4444 = 'MSF';    5432 = 'PgSQL';   5900 = 'VNC';     6379 = 'Redis'
  8080 = 'HTTP-Alt'; 8443 = 'HTTPS-Alt'; 9200 = 'Elastic'; 27017 = 'MongoDB'
}

function New-PortRecord {
    param(
        [string]$ApplicationName  = '',
        [object]$ProcessId        = $null,
        [string]$Protocol         = 'TCP',
        [int]   $LocalPort        = 0,
        [string]$LocalAddress     = '0.0.0.0',
        [object]$RemotePort       = $null,
        [object]$RemoteAddress    = $null,
        [string]$Direction        = 'Unknown',
        [string]$State            = 'OTHER',
        [string]$ServiceName      = '',
        [string]$Description      = '',
        [string]$RiskLevel        = 'Unknown',
        [object]$Authorized       = $null,
        [bool]  $SourceLive       = $false,
        [bool]  $SourceConfig     = $false,
        [string]$ConfigSourceFile = '',
        [string]$Notes            = ''
    )
    [PSCustomObject]@{
        ApplicationName  = $ApplicationName
        Pid              = $ProcessId
        Protocol         = $Protocol
        LocalPort        = $LocalPort
        LocalAddress     = $LocalAddress
        RemotePort       = $RemotePort
        RemoteAddress    = $RemoteAddress
        Direction        = $Direction
        State            = $State
        ServiceName      = $ServiceName
        Description      = $Description
        RiskLevel        = $RiskLevel
        Authorized       = $Authorized
        SourceLive       = $SourceLive
        SourceConfig     = $SourceConfig
        ConfigSourceFile = $ConfigSourceFile
        Notes            = $Notes
    }
}

function Get-SourceLabel {
    param([PSCustomObject]$Record)
    if ($Record.SourceLive -and $Record.SourceConfig) { return 'Live + Config' }
    if ($Record.SourceLive)   { return 'Live Scan' }
    if ($Record.SourceConfig) { return 'Config File' }
    return 'Unknown'
}

function Get-MergeKey {
    param([PSCustomObject]$Record)
    return "$($Record.Protocol)|$($Record.LocalPort)|$($Record.LocalAddress)"
}

#endregion DATA-MODEL

#region SCANNER

function Invoke-PPSMScan {
    $records = [System.Collections.Generic.List[PSCustomObject]]::new()
    $seen    = [System.Collections.Generic.HashSet[string]]::new()

    # Build PID -> ProcessName map
    $pidMap = @{}
    try {
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $pidMap[[int]$_.Id] = $_.ProcessName
        }
    } catch {
        Write-Warning "[WARN] Could not enumerate processes: $_"
    }

    # -- TCP connections ----------------------------------------------------------
    $tcpConns = @()
    try {
        $tcpConns = @(Get-NetTCPConnection -ErrorAction Stop)
    } catch {
        Write-Warning "[WARN] TCP scan failed (try running as Administrator): $_"
    }

    foreach ($conn in $tcpConns) {
        if (-not $conn.LocalPort) { continue }

        $localAddr = if ($conn.LocalAddress) { [string]$conn.LocalAddress } else { '0.0.0.0' }
        $procId    = if ($conn.OwningProcess) { [int]$conn.OwningProcess } else { $null }
        $appName   = if ($null -ne $procId -and $pidMap.ContainsKey($procId)) { $pidMap[$procId] } else { 'unknown' }

        $state = switch ($conn.State.ToString()) {
            'Listen'      { 'LISTEN' }
            'Established' { 'ESTABLISHED' }
            'TimeWait'    { 'TIME_WAIT' }
            'CloseWait'   { 'CLOSE_WAIT' }
            default       { 'OTHER' }
        }

        $dedupKey = "$appName|TCP|$($conn.LocalPort)|$state"
        if (-not $seen.Add($dedupKey)) { continue }

        $localPort   = [int]$conn.LocalPort
        $direction   = Get-PPSMDirection -State $state -LocalPort $localPort
        $serviceName = if ($Script:WELL_KNOWN_PORTS.ContainsKey($localPort)) { $Script:WELL_KNOWN_PORTS[$localPort] } else { '' }
        $riskLevel   = Get-PPSMRisk -Port $localPort

        $remotePort = if ($conn.RemotePort -and [int]$conn.RemotePort -ne 0) { [int]$conn.RemotePort } else { $null }
        $remoteAddr = if ($conn.RemoteAddress -and $conn.RemoteAddress -notin @('0.0.0.0', '::')) { [string]$conn.RemoteAddress } else { $null }

        $records.Add((New-PortRecord `
            -ApplicationName $appName `
            -ProcessId       $procId `
            -Protocol        'TCP' `
            -LocalPort       $localPort `
            -LocalAddress    $localAddr `
            -RemotePort      $remotePort `
            -RemoteAddress   $remoteAddr `
            -Direction       $direction `
            -State           $state `
            -ServiceName     $serviceName `
            -RiskLevel       $riskLevel `
            -SourceLive      $true
        ))
    }

    # -- UDP endpoints ------------------------------------------------------------
    $udpEndpoints = @()
    try {
        $udpEndpoints = @(Get-NetUDPEndpoint -ErrorAction Stop)
    } catch {
        Write-Warning "[WARN] UDP scan failed: $_"
    }

    foreach ($ep in $udpEndpoints) {
        if (-not $ep.LocalPort) { continue }

        $localAddr = if ($ep.LocalAddress) { [string]$ep.LocalAddress } else { '0.0.0.0' }
        $procId    = if ($ep.OwningProcess) { [int]$ep.OwningProcess } else { $null }
        $appName   = if ($null -ne $procId -and $pidMap.ContainsKey($procId)) { $pidMap[$procId] } else { 'unknown' }

        $state    = 'LISTEN'
        $dedupKey = "$appName|UDP|$($ep.LocalPort)|$state"
        if (-not $seen.Add($dedupKey)) { continue }

        $localPort   = [int]$ep.LocalPort
        $serviceName = if ($Script:WELL_KNOWN_PORTS.ContainsKey($localPort)) { $Script:WELL_KNOWN_PORTS[$localPort] } else { '' }
        $riskLevel   = Get-PPSMRisk -Port $localPort

        $records.Add((New-PortRecord `
            -ApplicationName $appName `
            -ProcessId       $procId `
            -Protocol        'UDP' `
            -LocalPort       $localPort `
            -LocalAddress    $localAddr `
            -Direction       'Inbound' `
            -State           $state `
            -ServiceName     $serviceName `
            -RiskLevel       $riskLevel `
            -SourceLive      $true
        ))
    }

    return ,$records
}

function Get-PPSMDirection {
    param([string]$State, [int]$LocalPort)
    if ($State -eq 'LISTEN')   { return 'Inbound' }
    if ($LocalPort -gt 49151)  { return 'Outbound' }
    return 'Both'
}

function Get-PPSMRisk {
    param([int]$Port)
    if ($Script:HIGH_RISK_PORTS.Contains($Port))   { return 'High' }
    if ($Script:MEDIUM_RISK_PORTS.Contains($Port)) { return 'Medium' }
    if ($Port -lt 1024)                            { return 'Medium' }
    return 'Low'
}

#endregion SCANNER

#region INGESTOR

function Import-PPSMConfig {
    param([string[]]$Paths)

    $all = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($path in $Paths) {
        if (-not (Test-Path $path -PathType Leaf)) {
            Write-Warning "[WARN] Config file not found: $path"
            continue
        }
        try {
            $raw     = Get-Content -Path $path -Raw -Encoding UTF8
            $data    = ConvertFrom-Yaml $raw
            $records = ConvertFrom-PPSMYaml -Data $data -SourceFile $path
            Write-Host "[INFO] Loaded $($records.Count) entries from $path"
            $all.AddRange($records)
        } catch {
            Write-Warning "[WARN] Failed to parse ${path}: $_"
        }
    }
    return ,$all
}

function ConvertFrom-PPSMYaml {
    param([object]$Data, [string]$SourceFile)

    $records = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($null -eq $Data) { return ,$records }

    if ($Data -is [System.Collections.IList]) {
        # Schema 1: top-level list of app blocks
        foreach ($block in $Data) {
            if ($block -is [System.Collections.IDictionary]) {
                $records.AddRange((Expand-AppBlock -Block $block -SourceFile $SourceFile))
            }
        }
    } elseif ($Data -is [System.Collections.IDictionary]) {
        if ($Data.Contains('ports')) {
            # Schema 2: single app block with 'ports' key
            $records.AddRange((Expand-AppBlock -Block $Data -SourceFile $SourceFile))
        } else {
            # Schema 3: dict of appName -> block
            foreach ($appName in @($Data.Keys)) {
                $block = $Data[$appName]
                if ($block -is [System.Collections.IDictionary] -and $block.Contains('ports')) {
                    if (-not $block.Contains('application')) { $block['application'] = $appName }
                    $records.AddRange((Expand-AppBlock -Block $block -SourceFile $SourceFile))
                }
            }
        }
    }
    return ,$records
}

function Expand-AppBlock {
    param([System.Collections.IDictionary]$Block, [string]$SourceFile)

    $records    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $appName    = if ($Block['application']) { [string]$Block['application'] }
                  elseif ($Block['name'])    { [string]$Block['name'] }
                  else                       { 'unknown' }
    $appDesc    = if ($Block['description']) { [string]$Block['description'] } else { '' }
    $sourceBase = [System.IO.Path]::GetFileName($SourceFile)
    $portList   = $Block['ports']
    if ($null -eq $portList) { return ,$records }

    foreach ($portDef in $portList) {
        if ($portDef -isnot [System.Collections.IDictionary]) { continue }

        $portNums  = Expand-PortRange -PortVal $portDef['port']
        $protocol  = ConvertTo-PPSMProtocol  -Val $portDef['protocol']
        $direction = ConvertTo-PPSMDirection -Val $portDef['direction']

        $riskRaw = if ($portDef['risk'])       { $portDef['risk'] }
                   elseif ($portDef['risk_level']) { $portDef['risk_level'] }
                   else { $null }
        $risk = ConvertTo-PPSMRisk -Val $riskRaw

        $service = if ($portDef['service'])      { [string]$portDef['service'] }
                   elseif ($portDef['service_name']) { [string]$portDef['service_name'] }
                   else { '' }

        $desc = if ($portDef['description']) { [string]$portDef['description'] }
                else { $appDesc }

        $notes = if ($portDef['notes']) { [string]$portDef['notes'] } else { '' }

        $localAddr = if ($portDef['address'])       { [string]$portDef['address'] }
                     elseif ($portDef['local_address']) { [string]$portDef['local_address'] }
                     else { '0.0.0.0' }

        $remotePortRaw = $portDef['remote_port']
        $remotePort = if ($null -ne $remotePortRaw) { [int]$remotePortRaw } else { $null }

        $remoteAddrRaw = if ($portDef['remote_address']) { [string]$portDef['remote_address'] }
                         elseif ($portDef['remote_host'])    { [string]$portDef['remote_host'] }
                         else { $null }

        $authRaw    = $portDef['authorized']
        $authorized = if ($null -eq $authRaw) { $null }
                      elseif ($authRaw -is [bool]) { $authRaw }
                      else { [System.Convert]::ToBoolean([string]$authRaw) }

        foreach ($portNum in $portNums) {
            $records.Add((New-PortRecord `
                -ApplicationName  $appName `
                -Protocol         $protocol `
                -LocalPort        $portNum `
                -LocalAddress     $localAddr `
                -RemotePort       $remotePort `
                -RemoteAddress    $remoteAddrRaw `
                -Direction        $direction `
                -State            'STATIC' `
                -ServiceName      $service `
                -Description      $desc `
                -RiskLevel        $risk `
                -Authorized       $authorized `
                -SourceConfig     $true `
                -ConfigSourceFile $sourceBase `
                -Notes            $notes
            ))
        }
    }
    return ,$records
}

function Expand-PortRange {
    param([object]$PortVal)
    if ($null -eq $PortVal) { return @(0) }
    $s = [string]$PortVal
    if ($s -match '^(\d+)-(\d+)$') {
        return ([int]$Matches[1]..[int]$Matches[2])
    }
    if ($s -match '^\d+$') { return @([int]$s) }
    return @(0)
}

function ConvertTo-PPSMProtocol {
    param([object]$Val)
    if ($null -eq $Val) { return 'TCP' }
    switch (([string]$Val).ToUpper()) {
        'TCP'  { return 'TCP' }
        'UDP'  { return 'UDP' }
        'ICMP' { return 'ICMP' }
        default { return 'OTHER' }
    }
}

function ConvertTo-PPSMDirection {
    param([object]$Val)
    if ($null -eq $Val) { return 'Unknown' }
    switch (([string]$Val).ToLower()) {
        'inbound'  { return 'Inbound' }
        'in'       { return 'Inbound' }
        'outbound' { return 'Outbound' }
        'out'      { return 'Outbound' }
        'both'     { return 'Both' }
        default    { return 'Unknown' }
    }
}

function ConvertTo-PPSMRisk {
    param([object]$Val)
    if ($null -eq $Val) { return 'Unknown' }
    switch (([string]$Val).ToUpper()) {
        'LOW'      { return 'Low' }
        'MEDIUM'   { return 'Medium' }
        'HIGH'     { return 'High' }
        'CRITICAL' { return 'Critical' }
        default    { return 'Unknown' }
    }
}

#endregion INGESTOR


#region RENDERER

function ConvertTo-DrawingColor {
    param([string]$Hex)
    $h = $Hex.TrimStart('#')
    $r = [Convert]::ToInt32($h.Substring(0, 2), 16)
    $g = [Convert]::ToInt32($h.Substring(2, 2), 16)
    $b = [Convert]::ToInt32($h.Substring(4, 2), 16)
    return [System.Drawing.Color]::FromArgb($r, $g, $b)
}

$Script:COLORS = @{
    HeaderBg      = ConvertTo-DrawingColor '1F3864'
    HeaderFont    = [System.Drawing.Color]::White
    SubheaderBg   = ConvertTo-DrawingColor '2E75B6'
    AltRow        = ConvertTo-DrawingColor 'EBF3FB'
    White         = [System.Drawing.Color]::White
    RiskCritical  = ConvertTo-DrawingColor 'FF0000'
    RiskHigh      = ConvertTo-DrawingColor 'FF6600'
    RiskMedium    = ConvertTo-DrawingColor 'FFC000'
    RiskLow       = ConvertTo-DrawingColor '70AD47'
    RiskUnknown   = ConvertTo-DrawingColor 'BFBFBF'
    AuthYes       = ConvertTo-DrawingColor 'E2EFDA'
    AuthNo        = ConvertTo-DrawingColor 'FCE4D6'
    AuthNull      = ConvertTo-DrawingColor 'FFF2CC'
    SourceBoth    = ConvertTo-DrawingColor 'E2EFDA'
    SourceLive    = ConvertTo-DrawingColor 'DEEBF7'
    SourceConfig  = ConvertTo-DrawingColor 'FCE4D6'
    BorderGray    = [System.Drawing.Color]::FromArgb(204, 204, 204)
}

$Script:PPSM_HEADERS = @(
    'Application / Service', 'PID', 'Protocol', 'Local Address', 'Local Port',
    'Remote Address', 'Remote Port', 'Direction', 'Connection State',
    'Service / Function', 'Description', 'Risk Level', 'Authorized',
    'Source', 'Config File', 'Notes'
)
$Script:COL_WIDTHS = @(22, 8, 10, 16, 12, 16, 12, 12, 16, 16, 28, 12, 12, 14, 20, 30)

function Get-RiskColor {
    param([string]$Risk)
    switch ($Risk) {
        'Critical' { return $Script:COLORS.RiskCritical }
        'High'     { return $Script:COLORS.RiskHigh }
        'Medium'   { return $Script:COLORS.RiskMedium }
        'Low'      { return $Script:COLORS.RiskLow }
        default    { return $Script:COLORS.RiskUnknown }
    }
}

function Write-PPSMTitleBlock {
    param($Worksheet, [string]$Title, [string]$Subtitle, [int]$ColCount)

    $lastCol = [char](64 + $ColCount)

    # Row 1: merged title
    $Worksheet.Cells[1, 1].Value = $Title
    $Worksheet.Cells["A1:${lastCol}1"].Merge = $true
    $r1 = $Worksheet.Cells['A1']
    $r1.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $r1.Style.Fill.BackgroundColor.SetColor($Script:COLORS.HeaderBg)
    $r1.Style.Font.Color.SetColor($Script:COLORS.HeaderFont)
    $r1.Style.Font.Bold = $true
    $r1.Style.Font.Size = 14
    $r1.Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
    $r1.Style.VerticalAlignment   = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
    $Worksheet.Row(1).Height = 36

    # Row 2: merged subtitle
    $Worksheet.Cells[2, 1].Value = $Subtitle
    $Worksheet.Cells["A2:${lastCol}2"].Merge = $true
    $r2 = $Worksheet.Cells['A2']
    $r2.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $r2.Style.Fill.BackgroundColor.SetColor($Script:COLORS.SubheaderBg)
    $r2.Style.Font.Color.SetColor($Script:COLORS.HeaderFont)
    $r2.Style.Font.Italic = $true
    $r2.Style.Font.Size   = 10
    $r2.Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
    $r2.Style.VerticalAlignment   = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
    $Worksheet.Row(2).Height = 20
}

function Write-PPSMHeaderRow {
    param($Worksheet, [int]$Row)

    for ($c = 1; $c -le $Script:PPSM_HEADERS.Count; $c++) {
        $cell = $Worksheet.Cells[$Row, $c]
        $cell.Value = $Script:PPSM_HEADERS[$c - 1]
        $cell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $cell.Style.Fill.BackgroundColor.SetColor($Script:COLORS.HeaderBg)
        $cell.Style.Font.Color.SetColor($Script:COLORS.HeaderFont)
        $cell.Style.Font.Bold = $true
        $cell.Style.Font.Size = 10
        $cell.Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
        $cell.Style.VerticalAlignment   = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
        $Worksheet.Column($c).Width = $Script:COL_WIDTHS[$c - 1]
    }
    $Worksheet.Row($Row).Height = 30
}

function Write-PPSMMainSheet {
    param($Worksheet, [System.Collections.Generic.List[PSCustomObject]]$Records)

    $colCount  = $Script:PPSM_HEADERS.Count
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $subtitle  = "Generated: $timestamp  |  Machine: $env:COMPUTERNAME  |  Total Entries: $($Records.Count)"

    Write-PPSMTitleBlock -Worksheet $Worksheet `
        -Title    'PORTS, PROTOCOLS AND SERVICES MANAGEMENT (PPSM)' `
        -Subtitle $subtitle `
        -ColCount $colCount

    Write-PPSMHeaderRow -Worksheet $Worksheet -Row 3

    # Freeze panes below header (row 4)
    $Worksheet.View.FreezePanes(4, 1)

    # AutoFilter on header row
    $lastColLetter = [char](64 + $colCount)
    $Worksheet.Cells["A3:${lastColLetter}3"].AutoFilter = $true

    $borderStyle = [OfficeOpenXml.Style.ExcelBorderStyle]::Thin
    $rowIdx = 4

    foreach ($rec in $Records) {
        $isAlt  = ($rowIdx % 2 -eq 0)
        $baseBg = if ($isAlt) { $Script:COLORS.AltRow } else { $Script:COLORS.White }

        $authStr = if ($rec.Authorized -eq $true)  { 'YES' }
                   elseif ($rec.Authorized -eq $false) { 'NO' }
                   else { 'Pending' }

        $authBg = if ($rec.Authorized -eq $true)  { $Script:COLORS.AuthYes }
                  elseif ($rec.Authorized -eq $false) { $Script:COLORS.AuthNo }
                  else { $Script:COLORS.AuthNull }

        $sourceBg = if ($rec.SourceLive -and $rec.SourceConfig) { $Script:COLORS.SourceBoth }
                    elseif ($rec.SourceLive)   { $Script:COLORS.SourceLive }
                    else                        { $Script:COLORS.SourceConfig }

        $riskBg        = Get-RiskColor -Risk $rec.RiskLevel
        $riskFontWhite = $rec.RiskLevel -in @('Critical', 'High')

        $pidVal        = if ($null -ne $rec.Pid) { $rec.Pid } else { '' }
        $remoteAddrVal = if ($rec.RemoteAddress) { $rec.RemoteAddress } else { 'Any' }
        $remotePortVal = if ($null -ne $rec.RemotePort) { $rec.RemotePort } else { 'Any' }

        $rowValues = @(
            $rec.ApplicationName,
            $pidVal,
            $rec.Protocol,
            $rec.LocalAddress,
            $rec.LocalPort,
            $remoteAddrVal,
            $remotePortVal,
            $rec.Direction,
            $rec.State,
            $rec.ServiceName,
            $rec.Description,
            $rec.RiskLevel,
            $authStr,
            (Get-SourceLabel -Record $rec),
            $rec.ConfigSourceFile,
            $rec.Notes
        )

        for ($c = 1; $c -le $rowValues.Count; $c++) {
            $cell = $Worksheet.Cells[$rowIdx, $c]
            $cell.Value = $rowValues[$c - 1]

            # Border
            $cell.Style.Border.Top.Style    = $borderStyle
            $cell.Style.Border.Bottom.Style = $borderStyle
            $cell.Style.Border.Left.Style   = $borderStyle
            $cell.Style.Border.Right.Style  = $borderStyle
            $cell.Style.Border.Top.Color.SetColor($Script:COLORS.BorderGray)
            $cell.Style.Border.Bottom.Color.SetColor($Script:COLORS.BorderGray)
            $cell.Style.Border.Left.Color.SetColor($Script:COLORS.BorderGray)
            $cell.Style.Border.Right.Color.SetColor($Script:COLORS.BorderGray)

            $cell.Style.VerticalAlignment = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
            $cell.Style.Font.Size = 10

            # Wrap Description (col 11) and Notes (col 16)
            if ($c -eq 11 -or $c -eq 16) { $cell.Style.WrapText = $true }

            # Column-specific background/font
            $cell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            switch ($c) {
                12 {
                    $cell.Style.Fill.BackgroundColor.SetColor($riskBg)
                    $cell.Style.Font.Bold = $true
                    if ($riskFontWhite) { $cell.Style.Font.Color.SetColor($Script:COLORS.HeaderFont) }
                }
                13 {
                    $cell.Style.Fill.BackgroundColor.SetColor($authBg)
                    if ($rec.Authorized -eq $false) { $cell.Style.Font.Bold = $true }
                }
                14 {
                    $cell.Style.Fill.BackgroundColor.SetColor($sourceBg)
                }
                default {
                    $cell.Style.Fill.BackgroundColor.SetColor($baseBg)
                }
            }
        }
        $Worksheet.Row($rowIdx).Height = 18
        $rowIdx++
    }
}

function Write-SummarySection {
    param(
        $Worksheet,
        [int]$StartRow,
        [string]$Title,
        [System.Collections.Specialized.OrderedDictionary]$Data
    )

    # Section header
    $Worksheet.Cells[$StartRow, 1].Value = $Title
    $Worksheet.Cells[$StartRow, 1, $StartRow, 3].Merge = $true
    $hdr = $Worksheet.Cells[$StartRow, 1]
    $hdr.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $hdr.Style.Fill.BackgroundColor.SetColor($Script:COLORS.SubheaderBg)
    $hdr.Style.Font.Color.SetColor($Script:COLORS.HeaderFont)
    $hdr.Style.Font.Bold = $true
    $hdr.Style.Font.Size = 10
    $Worksheet.Row($StartRow).Height = 22

    $r = $StartRow + 1
    foreach ($key in $Data.Keys) {
        $bg = if ($r % 2 -eq 0) { $Script:COLORS.AltRow } else { $Script:COLORS.White }
        $kCell = $Worksheet.Cells[$r, 1]
        $vCell = $Worksheet.Cells[$r, 2]
        $kCell.Value = $key
        $vCell.Value = $Data[$key]
        $kCell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $kCell.Style.Fill.BackgroundColor.SetColor($bg)
        $kCell.Style.Font.Size = 10
        $vCell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $vCell.Style.Fill.BackgroundColor.SetColor($bg)
        $vCell.Style.Font.Bold = $true
        $vCell.Style.Font.Size = 10
        $r++
    }
    return ($r + 1)
}

function Write-PPSMSummarySheet {
    param($Worksheet, [System.Collections.Generic.List[PSCustomObject]]$Records)

    $Worksheet.Cells[1, 1].Value = 'PPSM SUMMARY'
    $Worksheet.Cells['A1:C1'].Merge = $true
    $t = $Worksheet.Cells['A1']
    $t.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $t.Style.Fill.BackgroundColor.SetColor($Script:COLORS.HeaderBg)
    $t.Style.Font.Color.SetColor($Script:COLORS.HeaderFont)
    $t.Style.Font.Bold = $true
    $t.Style.Font.Size = 13
    $t.Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
    $Worksheet.Row(1).Height = 32

    $riskData = [ordered]@{
        'Critical' = @($Records | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
        'High'     = @($Records | Where-Object { $_.RiskLevel -eq 'High' }).Count
        'Medium'   = @($Records | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
        'Low'      = @($Records | Where-Object { $_.RiskLevel -eq 'Low' }).Count
        'Unknown'  = @($Records | Where-Object { $_.RiskLevel -eq 'Unknown' }).Count
    }
    $authData = [ordered]@{
        'Authorized'     = @($Records | Where-Object { $_.Authorized -eq $true }).Count
        'Unauthorized'   = @($Records | Where-Object { $_.Authorized -eq $false }).Count
        'Pending Review' = @($Records | Where-Object { $null -eq $_.Authorized }).Count
    }
    $srcData = [ordered]@{
        'Live Scan Rows'   = @($Records | Where-Object { $_.Source -eq 'Live'   }).Count
        'Config File Rows' = @($Records | Where-Object { $_.Source -eq 'Config' }).Count
    }

    $row = 3
    $row = Write-SummarySection -Worksheet $Worksheet -StartRow $row -Title 'Risk Level Distribution' -Data $riskData
    $row = Write-SummarySection -Worksheet $Worksheet -StartRow $row -Title 'Authorization Status'    -Data $authData
    Write-SummarySection        -Worksheet $Worksheet -StartRow $row -Title 'Source Breakdown'        -Data $srcData | Out-Null

    $Worksheet.Column(1).Width = 22
    $Worksheet.Column(2).Width = 12
    $Worksheet.Column(3).Width = 12
}

function Write-PPSMFilteredSheet {
    param(
        $Worksheet,
        [System.Collections.Generic.List[PSCustomObject]]$Records,
        [string]$Title,
        [string]$Note
    )

    $colCount      = $Script:PPSM_HEADERS.Count
    $lastColLetter = [char](64 + $colCount)

    $Worksheet.Cells[1, 1].Value = $Title
    $Worksheet.Cells["A1:${lastColLetter}1"].Merge = $true
    $t = $Worksheet.Cells['A1']
    $t.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $t.Style.Fill.BackgroundColor.SetColor($Script:COLORS.HeaderBg)
    $t.Style.Font.Color.SetColor($Script:COLORS.HeaderFont)
    $t.Style.Font.Bold = $true
    $t.Style.Font.Size = 12
    $t.Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
    $Worksheet.Row(1).Height = 28

    $Worksheet.Cells[2, 1].Value = $Note
    $Worksheet.Cells["A2:${lastColLetter}2"].Merge = $true
    $s = $Worksheet.Cells['A2']
    $s.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
    $s.Style.Fill.BackgroundColor.SetColor($Script:COLORS.SubheaderBg)
    $s.Style.Font.Color.SetColor($Script:COLORS.HeaderFont)
    $s.Style.Font.Italic = $true
    $s.Style.Font.Size   = 10
    $s.Style.HorizontalAlignment = [OfficeOpenXml.Style.ExcelHorizontalAlignment]::Center
    $Worksheet.Row(2).Height = 20

    Write-PPSMHeaderRow -Worksheet $Worksheet -Row 3
    $Worksheet.View.FreezePanes(4, 1)
    $Worksheet.Cells["A3:${lastColLetter}3"].AutoFilter = $true

    $r = 4
    foreach ($rec in $Records) {
        $bg      = if ($r % 2 -eq 0) { $Script:COLORS.AltRow } else { $Script:COLORS.White }
        $authStr = if ($rec.Authorized -eq $true)  { 'YES' }
                   elseif ($rec.Authorized -eq $false) { 'NO' }
                   else { 'Pending' }

        $pidVal        = if ($null -ne $rec.Pid) { $rec.Pid } else { '' }
        $remoteAddrVal = if ($rec.RemoteAddress) { $rec.RemoteAddress } else { 'Any' }
        $remotePortVal = if ($null -ne $rec.RemotePort) { $rec.RemotePort } else { 'Any' }

        $rowValues = @(
            $rec.ApplicationName, $pidVal, $rec.Protocol,
            $rec.LocalAddress, $rec.LocalPort,
            $remoteAddrVal, $remotePortVal,
            $rec.Direction, $rec.State, $rec.ServiceName,
            $rec.Description, $rec.RiskLevel, $authStr,
            (Get-SourceLabel -Record $rec), $rec.ConfigSourceFile, $rec.Notes
        )
        for ($c = 1; $c -le $rowValues.Count; $c++) {
            $cell = $Worksheet.Cells[$r, $c]
            $cell.Value = $rowValues[$c - 1]
            $cell.Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $cell.Style.Fill.BackgroundColor.SetColor($bg)
            $cell.Style.Font.Size = 10
            $cell.Style.VerticalAlignment = [OfficeOpenXml.Style.ExcelVerticalAlignment]::Center
        }
        $Worksheet.Row($r).Height = 18
        $r++
    }
}

function Export-PPSMReport {
    param(
        $Records,
        [string]$OutputPath
    )

    try {
        $excel = Open-ExcelPackage -Path $OutputPath -Create
    } catch {
        Write-Error "[ERROR] Cannot create output file '${OutputPath}': $_" -ErrorAction Stop
    }

    # Sheet 1: PPSM (main)
    $wsPPSM = Add-Worksheet -ExcelPackage $excel -WorksheetName 'PPSM' -Activate
    Write-PPSMMainSheet -Worksheet $wsPPSM -Records $Records

    # Sheet 2: Summary
    $wsSummary = Add-Worksheet -ExcelPackage $excel -WorksheetName 'Summary'
    Write-PPSMSummarySheet -Worksheet $wsSummary -Records $Records

    # Sheet 3: Live-only rows (no corresponding config entry)
    $undoc    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $liveApps = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $cfgApps  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $Records) {
        if ($r.Source -eq 'Live')   { [void]$liveApps.Add([string]$r.ApplicationName) }
        if ($r.Source -eq 'Config') { [void]$cfgApps.Add([string]$r.ApplicationName) }
    }
    foreach ($r in $Records) {
        if ($r.Source -eq 'Live' -and -not $cfgApps.Contains([string]$r.ApplicationName)) {
            $undoc.Add($r)
        }
    }
    $wsUndoc = Add-Worksheet -ExcelPackage $excel -WorksheetName 'Undocumented Ports'
    Write-PPSMFilteredSheet -Worksheet $wsUndoc -Records $undoc `
        -Title 'UNDOCUMENTED PORTS - REVIEW REQUIRED' `
        -Note  'These ports were observed in the live scan but have no corresponding config entry.'

    # Sheet 4: Config-only rows (not observed in live scan)
    $cfgOnly = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($r in $Records) {
        if ($r.Source -eq 'Config' -and -not $liveApps.Contains([string]$r.ApplicationName)) {
            $cfgOnly.Add($r)
        }
    }
    $wsCfg = Add-Worksheet -ExcelPackage $excel -WorksheetName 'Config Only'
    Write-PPSMFilteredSheet -Worksheet $wsCfg -Records $cfgOnly `
        -Title 'CONFIG-ONLY ENTRIES' `
        -Note  'These ports are defined in config files but were not observed in the live scan.'

    try {
        Close-ExcelPackage $excel
    } catch {
        if ($_.Exception.Message -match 'sharing violation|used by another') {
            Write-Error "[ERROR] Cannot write '${OutputPath}' - close the file in Excel and retry." -ErrorAction Stop
        }
        throw
    }
}

#endregion RENDERER

#region GUI

# -- Script-scope state --
$Script:AllRecords  = [System.Collections.Generic.List[PSCustomObject]]::new()
$Script:ScanNumber  = 0
$Script:LiveCount   = 0
$Script:ConfigCount = 0
$Script:ScanTimer   = $null
$Script:Form        = $null
$Script:IgnoredApps = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$Script:IgnoreFile  = Join-Path (Split-Path $PSCommandPath -Parent) 'ppsm_ignored.txt'
$Script:Grid        = $null
$Script:TsData      = $null
$Script:LblStatus         = $null
$Script:LblCounts         = $null
$Script:LblLastScan       = $null
$Script:LoadedConfigPaths = [System.Collections.Generic.List[string]]::new()
$Script:_tmpSaveCombo     = $null

# -- Column definitions --
$Script:ColumnDefs = @(
    @{ Name = 'Timestamp';  Header = 'Timestamp';   Width = 135 },
    @{ Name = 'ScanNum';    Header = 'Scan#';        Width = 55  },
    @{ Name = 'Source';     Header = 'Source';       Width = 70  },
    @{ Name = 'AppName';    Header = 'Application';  Width = 160 },
    @{ Name = 'PID';        Header = 'PID';          Width = 55  },
    @{ Name = 'Protocol';   Header = 'Protocol';     Width = 65  },
    @{ Name = 'LocalAddr';  Header = 'Local Addr';   Width = 120 },
    @{ Name = 'LocalPort';  Header = 'Port';         Width = 55  },
    @{ Name = 'RemoteAddr'; Header = 'Remote Addr';  Width = 120 },
    @{ Name = 'RemotePort'; Header = 'Remote Port';  Width = 75  },
    @{ Name = 'Direction';  Header = 'Direction';    Width = 75  },
    @{ Name = 'State';      Header = 'State';        Width = 80  },
    @{ Name = 'Service';    Header = 'Service';      Width = 120 },
    @{ Name = 'Risk';       Header = 'Risk';         Width = 70  },
    @{ Name = 'Auth';       Header = 'Authorized';   Width = 80  },
    @{ Name = 'ConfigFile'; Header = 'Config File';  Width = 160 },
    @{ Name = 'Notes';      Header = 'Notes';        Width = 200 }
)
$Script:COL_APPNAME = 3
$Script:COL_RISK    = 13
$Script:COL_AUTH    = 14

# -- Grid construction --

function Build-PPSMColumns {
    param([System.Windows.Forms.DataGridView]$Grid)
    foreach ($def in $Script:ColumnDefs) {
        $col            = [System.Windows.Forms.DataGridViewTextBoxColumn]::new()
        $col.Name       = $def.Name
        $col.HeaderText = $def.Header
        $col.Width      = $def.Width
        $col.ReadOnly   = $true
        $col.SortMode   = [System.Windows.Forms.DataGridViewColumnSortMode]::NotSortable
        $Grid.Columns.Add($col) | Out-Null
    }
}

function Build-PPSMGrid {
    $grid = [System.Windows.Forms.DataGridView]::new()
    $grid.Dock                      = [System.Windows.Forms.DockStyle]::Fill
    $grid.ReadOnly                  = $true
    $grid.AllowUserToAddRows        = $false
    $grid.AllowUserToDeleteRows     = $false
    $grid.AllowUserToResizeRows     = $false
    $grid.RowHeadersVisible         = $false
    $grid.SelectionMode             = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
    $grid.MultiSelect               = $true
    $grid.AutoSizeColumnsMode       = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::None
    $grid.ScrollBars                = [System.Windows.Forms.ScrollBars]::Both
    $grid.ClipboardCopyMode         = [System.Windows.Forms.DataGridViewClipboardCopyMode]::EnableWithoutHeaderText
    $grid.EnableHeadersVisualStyles = $false

    $grid.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(235, 243, 255)
    $grid.DefaultCellStyle.BackColor                = [System.Drawing.Color]::White
    $grid.ColumnHeadersDefaultCellStyle.Font        = [System.Drawing.Font]::new('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $grid.ColumnHeadersDefaultCellStyle.BackColor   = [System.Drawing.Color]::FromArgb(31, 56, 100)
    $grid.ColumnHeadersDefaultCellStyle.ForeColor   = [System.Drawing.Color]::White
    $grid.Font                                      = [System.Drawing.Font]::new('Consolas', 8)

    Build-PPSMColumns -Grid $grid
    return $grid
}

# -- ToolStrip --

function Build-PPSMToolStrip {
    $ts           = [System.Windows.Forms.ToolStrip]::new()
    $ts.GripStyle = [System.Windows.Forms.ToolStripGripStyle]::Hidden
    $ts.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 240)

    $btnStart              = [System.Windows.Forms.ToolStripButton]::new()
    $btnStart.Text         = 'Start Scan'
    $btnStart.ToolTipText  = 'Begin continuous network scanning'
    $btnStart.BackColor    = [System.Drawing.Color]::FromArgb(198, 239, 206)
    $ts.Items.Add($btnStart) | Out-Null

    $btnStop               = [System.Windows.Forms.ToolStripButton]::new()
    $btnStop.Text          = 'Stop Scan'
    $btnStop.Enabled       = $false
    $btnStop.ToolTipText   = 'Halt scanning'
    $btnStop.BackColor     = [System.Drawing.Color]::FromArgb(255, 199, 206)
    $ts.Items.Add($btnStop) | Out-Null

    $ts.Items.Add([System.Windows.Forms.ToolStripSeparator]::new()) | Out-Null

    $lblInterval          = [System.Windows.Forms.ToolStripLabel]::new()
    $lblInterval.Text     = 'Interval:'
    $ts.Items.Add($lblInterval) | Out-Null

    $txtInterval                  = [System.Windows.Forms.ToolStripTextBox]::new()
    $txtInterval.Text             = '10'
    $txtInterval.Width            = 40
    $txtInterval.ToolTipText      = 'Scan interval in seconds (1-3600)'
    $txtInterval.TextBoxTextAlign = [System.Windows.Forms.HorizontalAlignment]::Center
    $ts.Items.Add($txtInterval) | Out-Null

    $lblSec        = [System.Windows.Forms.ToolStripLabel]::new()
    $lblSec.Text   = 's'
    $ts.Items.Add($lblSec) | Out-Null

    $ts.Items.Add([System.Windows.Forms.ToolStripSeparator]::new()) | Out-Null

    $btnLoad              = [System.Windows.Forms.ToolStripButton]::new()
    $btnLoad.Text         = 'Load Config'
    $btnLoad.ToolTipText  = 'Import one or more YAML config files'
    $ts.Items.Add($btnLoad) | Out-Null

    $ts.Items.Add([System.Windows.Forms.ToolStripSeparator]::new()) | Out-Null

    $btnExport             = [System.Windows.Forms.ToolStripButton]::new()
    $btnExport.Text        = 'Export Excel'
    $btnExport.ToolTipText = 'Export all rows to a PPSM Excel report'
    $ts.Items.Add($btnExport) | Out-Null

    $btnClear              = [System.Windows.Forms.ToolStripButton]::new()
    $btnClear.Text         = 'Clear All'
    $btnClear.ToolTipText  = 'Remove all rows from the grid'
    $ts.Items.Add($btnClear) | Out-Null

    $ts.Items.Add([System.Windows.Forms.ToolStripSeparator]::new()) | Out-Null

    $btnIgnored             = [System.Windows.Forms.ToolStripButton]::new()
    $btnIgnored.Text        = 'Ignored Apps'
    $btnIgnored.ToolTipText = 'View and manage the ignored application list'
    $ts.Items.Add($btnIgnored) | Out-Null

    return @{
        Strip       = $ts
        BtnStart    = $btnStart
        BtnStop     = $btnStop
        TxtInterval = $txtInterval
        BtnLoad     = $btnLoad
        BtnExport   = $btnExport
        BtnClear    = $btnClear
        BtnIgnored  = $btnIgnored
    }
}

# -- StatusStrip --

function Build-PPSMStatusStrip {
    $ss = [System.Windows.Forms.StatusStrip]::new()

    $lblStatus        = [System.Windows.Forms.ToolStripStatusLabel]::new()
    $lblStatus.Text   = 'Status: Ready'
    $lblStatus.Spring = $false
    $ss.Items.Add($lblStatus) | Out-Null

    $ss.Items.Add([System.Windows.Forms.ToolStripSeparator]::new()) | Out-Null

    $lblCounts        = [System.Windows.Forms.ToolStripStatusLabel]::new()
    $lblCounts.Text   = 'Live rows: 0 | Config rows: 0'
    $lblCounts.Spring = $false
    $ss.Items.Add($lblCounts) | Out-Null

    $ss.Items.Add([System.Windows.Forms.ToolStripSeparator]::new()) | Out-Null

    $lblLastScan        = [System.Windows.Forms.ToolStripStatusLabel]::new()
    $lblLastScan.Text   = 'Last scan: never'
    $lblLastScan.Spring = $true
    $ss.Items.Add($lblLastScan) | Out-Null

    return @{
        Strip       = $ss
        LblStatus   = $lblStatus
        LblCounts   = $lblCounts
        LblLastScan = $lblLastScan
    }
}

# -- Helpers --

function Update-PPSMStatus {
    param(
        $LblStatus,
        $LblCounts,
        $LblLastScan,
        [string]$StatusText   = '',
        [string]$LastScanText = ''
    )
    if ($StatusText   -ne '') { $LblStatus.Text   = $StatusText }
    $LblCounts.Text = "Live rows: $Script:LiveCount | Config rows: $Script:ConfigCount"
    if ($LastScanText -ne '') { $LblLastScan.Text = "Last scan: $LastScanText" }
}

function Import-PPSMIgnoreList {
    if (Test-Path $Script:IgnoreFile) {
        Get-Content $Script:IgnoreFile -Encoding UTF8 |
            Where-Object { $_ -ne '' } |
            ForEach-Object { [void]$Script:IgnoredApps.Add($_.Trim()) }
    }
}

function Export-PPSMIgnoreList {
    $Script:IgnoredApps | Sort-Object | Set-Content $Script:IgnoreFile -Encoding UTF8
}

function Show-PPSMIgnoreDialog {
    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text          = 'Ignored Applications'
    $dlg.Size          = [System.Drawing.Size]::new(380, 320)
    $dlg.MinimumSize   = [System.Drawing.Size]::new(280, 220)
    $dlg.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent

    $lbl          = [System.Windows.Forms.Label]::new()
    $lbl.Text     = 'One application name per line. Delete a line to un-ignore.'
    $lbl.Location = [System.Drawing.Point]::new(8, 8)
    $lbl.Size     = [System.Drawing.Size]::new(350, 30)
    $lbl.Anchor   = [System.Windows.Forms.AnchorStyles]::Top -bor
                    [System.Windows.Forms.AnchorStyles]::Left -bor
                    [System.Windows.Forms.AnchorStyles]::Right

    $txt             = [System.Windows.Forms.TextBox]::new()
    $txt.Multiline   = $true
    $txt.ScrollBars  = [System.Windows.Forms.ScrollBars]::Vertical
    $txt.Location    = [System.Drawing.Point]::new(8, 42)
    $txt.Size        = [System.Drawing.Size]::new(350, 190)
    $txt.Anchor      = [System.Windows.Forms.AnchorStyles]::Top -bor
                       [System.Windows.Forms.AnchorStyles]::Left -bor
                       [System.Windows.Forms.AnchorStyles]::Right -bor
                       [System.Windows.Forms.AnchorStyles]::Bottom
    $txt.Text        = ($Script:IgnoredApps | Sort-Object) -join "`r`n"

    $btnOK              = [System.Windows.Forms.Button]::new()
    $btnOK.Text         = 'OK'
    $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $btnOK.Location     = [System.Drawing.Point]::new(192, 246)
    $btnOK.Size         = [System.Drawing.Size]::new(75, 26)
    $btnOK.Anchor       = [System.Windows.Forms.AnchorStyles]::Bottom -bor
                          [System.Windows.Forms.AnchorStyles]::Right

    $btnCancel              = [System.Windows.Forms.Button]::new()
    $btnCancel.Text         = 'Cancel'
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $btnCancel.Location     = [System.Drawing.Point]::new(276, 246)
    $btnCancel.Size         = [System.Drawing.Size]::new(75, 26)
    $btnCancel.Anchor       = [System.Windows.Forms.AnchorStyles]::Bottom -bor
                              [System.Windows.Forms.AnchorStyles]::Right

    $dlg.AcceptButton = $btnOK
    $dlg.CancelButton = $btnCancel
    $dlg.Controls.AddRange(@($lbl, $txt, $btnOK, $btnCancel))

    if ($dlg.ShowDialog($Script:Form) -eq [System.Windows.Forms.DialogResult]::OK) {
        $Script:IgnoredApps.Clear()
        $txt.Lines |
            Where-Object { $_ -ne '' } |
            ForEach-Object { [void]$Script:IgnoredApps.Add($_.Trim()) }
        Export-PPSMIgnoreList
    }
    $dlg.Dispose()
}

function Add-PPSMConfigEntry {
    param(
        [string]$FilePath,
        [string]$ApplicationName,
        [string]$Port,
        [string]$Protocol,
        [string]$Direction,
        [string]$Risk,
        [string]$Notes,
        [bool]$Authorized
    )
    $authStr   = if ($Authorized) { 'true' } else { 'false' }
    $notesSafe = $Notes -replace '"', "'"
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = @"

# Added by PPSM Monitor - $timestamp
- application: $ApplicationName
  ports:
    - port: $Port
      protocol: $Protocol
      direction: $Direction
      risk: $Risk
      authorized: $authStr
      notes: "$notesSafe"
"@
    Add-Content -Path $FilePath -Value $entry -Encoding UTF8
}

function Show-PPSMAddToConfigDialog {
    if ($Script:Grid.SelectedRows.Count -eq 0) { return }
    $row = $Script:Grid.SelectedRows[0]

    # Column indices: 3=App, 5=Protocol, 7=LocalPort, 10=Direction, 13=Risk
    $appName   = [string]$row.Cells[$Script:COL_APPNAME].Value
    $port      = [string]$row.Cells[7].Value
    $protocol  = [string]$row.Cells[5].Value
    $direction = [string]$row.Cells[10].Value
    $rowRisk   = [string]$row.Cells[$Script:COL_RISK].Value

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text            = 'Add to Config File'
    $dlg.Size            = [System.Drawing.Size]::new(450, 370)
    $dlg.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $dlg.MaximizeBox     = $false
    $dlg.MinimizeBox     = $false
    $dlg.StartPosition   = [System.Windows.Forms.FormStartPosition]::CenterParent

    $y = 12

    # Application
    $ctrl = [System.Windows.Forms.Label]::new(); $ctrl.Text = 'Application:'; $ctrl.Location = [System.Drawing.Point]::new(10,$y); $ctrl.Size = [System.Drawing.Size]::new(88,20); $dlg.Controls.Add($ctrl)
    $txtApp = [System.Windows.Forms.TextBox]::new(); $txtApp.Text = $appName; $txtApp.Location = [System.Drawing.Point]::new(103,$y); $txtApp.Size = [System.Drawing.Size]::new(320,22); $dlg.Controls.Add($txtApp)
    $y += 30

    # Port / Protocol
    $ctrl = [System.Windows.Forms.Label]::new(); $ctrl.Text = 'Port:'; $ctrl.Location = [System.Drawing.Point]::new(10,$y); $ctrl.Size = [System.Drawing.Size]::new(88,20); $dlg.Controls.Add($ctrl)
    $txtPort = [System.Windows.Forms.TextBox]::new(); $txtPort.Text = $port; $txtPort.Location = [System.Drawing.Point]::new(103,$y); $txtPort.Size = [System.Drawing.Size]::new(70,22); $dlg.Controls.Add($txtPort)
    $ctrl = [System.Windows.Forms.Label]::new(); $ctrl.Text = 'Protocol:'; $ctrl.Location = [System.Drawing.Point]::new(185,$y); $ctrl.Size = [System.Drawing.Size]::new(62,20); $dlg.Controls.Add($ctrl)
    $cboProto = [System.Windows.Forms.ComboBox]::new(); $cboProto.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList; $cboProto.Location = [System.Drawing.Point]::new(252,$y); $cboProto.Size = [System.Drawing.Size]::new(171,22)
    @('TCP','UDP','ICMP') | ForEach-Object { [void]$cboProto.Items.Add($_) }
    $cboProto.SelectedItem = if ($cboProto.Items.Contains($protocol)) { $protocol } else { 'TCP' }
    $dlg.Controls.Add($cboProto)
    $y += 30

    # Direction
    $ctrl = [System.Windows.Forms.Label]::new(); $ctrl.Text = 'Direction:'; $ctrl.Location = [System.Drawing.Point]::new(10,$y); $ctrl.Size = [System.Drawing.Size]::new(88,20); $dlg.Controls.Add($ctrl)
    $cboDir = [System.Windows.Forms.ComboBox]::new(); $cboDir.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList; $cboDir.Location = [System.Drawing.Point]::new(103,$y); $cboDir.Size = [System.Drawing.Size]::new(150,22)
    @('Inbound','Outbound','Both','Unknown') | ForEach-Object { [void]$cboDir.Items.Add($_) }
    $cboDir.SelectedItem = if ($cboDir.Items.Contains($direction)) { $direction } else { 'Unknown' }
    $dlg.Controls.Add($cboDir)
    $y += 30

    # Authorization
    $ctrl = [System.Windows.Forms.Label]::new(); $ctrl.Text = 'Authorization:'; $ctrl.Location = [System.Drawing.Point]::new(10,$y); $ctrl.Size = [System.Drawing.Size]::new(88,20); $dlg.Controls.Add($ctrl)
    $radYes = [System.Windows.Forms.RadioButton]::new(); $radYes.Text = 'Authorized (YES)'; $radYes.Location = [System.Drawing.Point]::new(103,$y); $radYes.Size = [System.Drawing.Size]::new(145,22); $radYes.Checked = $true; $dlg.Controls.Add($radYes)
    $radNo  = [System.Windows.Forms.RadioButton]::new(); $radNo.Text  = 'Denied (NO)';      $radNo.Location  = [System.Drawing.Point]::new(255,$y); $radNo.Size  = [System.Drawing.Size]::new(110,22); $dlg.Controls.Add($radNo)
    $y += 30

    # Risk
    $ctrl = [System.Windows.Forms.Label]::new(); $ctrl.Text = 'Risk:'; $ctrl.Location = [System.Drawing.Point]::new(10,$y); $ctrl.Size = [System.Drawing.Size]::new(88,20); $dlg.Controls.Add($ctrl)
    $cboRisk = [System.Windows.Forms.ComboBox]::new(); $cboRisk.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList; $cboRisk.Location = [System.Drawing.Point]::new(103,$y); $cboRisk.Size = [System.Drawing.Size]::new(150,22)
    @('Low','Medium','High','Critical','Unknown') | ForEach-Object { [void]$cboRisk.Items.Add($_) }
    $cboRisk.SelectedItem = if ($rowRisk -and $cboRisk.Items.Contains($rowRisk)) { $rowRisk } else { 'Unknown' }
    $dlg.Controls.Add($cboRisk)
    $y += 30

    # Notes
    $ctrl = [System.Windows.Forms.Label]::new(); $ctrl.Text = 'Notes:'; $ctrl.Location = [System.Drawing.Point]::new(10,$y); $ctrl.Size = [System.Drawing.Size]::new(88,20); $dlg.Controls.Add($ctrl)
    $txtNotes = [System.Windows.Forms.TextBox]::new(); $txtNotes.Location = [System.Drawing.Point]::new(103,$y); $txtNotes.Size = [System.Drawing.Size]::new(320,22); $dlg.Controls.Add($txtNotes)
    $y += 35

    # Separator
    $sep = [System.Windows.Forms.Label]::new(); $sep.BorderStyle = [System.Windows.Forms.BorderStyle]::Fixed3D; $sep.Location = [System.Drawing.Point]::new(10,$y); $sep.Size = [System.Drawing.Size]::new(415,2); $dlg.Controls.Add($sep)
    $y += 10

    # Save to file
    $ctrl = [System.Windows.Forms.Label]::new(); $ctrl.Text = 'Save to:'; $ctrl.Location = [System.Drawing.Point]::new(10,$y); $ctrl.Size = [System.Drawing.Size]::new(88,20); $dlg.Controls.Add($ctrl)
    $cboSavePath = [System.Windows.Forms.ComboBox]::new(); $cboSavePath.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDown; $cboSavePath.Location = [System.Drawing.Point]::new(103,$y); $cboSavePath.Size = [System.Drawing.Size]::new(240,22)
    $defaultSave = Join-Path (Split-Path $PSCommandPath -Parent) 'ppsm_config.yaml'
    [void]$cboSavePath.Items.Add($defaultSave)
    foreach ($p in $Script:LoadedConfigPaths) { if ($p -ne $defaultSave) { [void]$cboSavePath.Items.Add($p) } }
    $cboSavePath.SelectedIndex = 0
    $dlg.Controls.Add($cboSavePath)
    $Script:_tmpSaveCombo = $cboSavePath

    $btnBrowse = [System.Windows.Forms.Button]::new(); $btnBrowse.Text = '...'; $btnBrowse.Location = [System.Drawing.Point]::new(352,$y); $btnBrowse.Size = [System.Drawing.Size]::new(71,24)
    $btnBrowse.Add_Click({
        $sfd = [System.Windows.Forms.SaveFileDialog]::new()
        $sfd.Title  = 'Select or Create a YAML Config File'
        $sfd.Filter = 'YAML Files (*.yaml;*.yml)|*.yaml;*.yml|All Files (*.*)|*.*'
        $sfd.FileName = 'ppsm_config.yaml'
        if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            if (-not $Script:_tmpSaveCombo.Items.Contains($sfd.FileName)) {
                [void]$Script:_tmpSaveCombo.Items.Add($sfd.FileName)
            }
            $Script:_tmpSaveCombo.SelectedItem = $sfd.FileName
        }
    })
    $dlg.Controls.Add($btnBrowse)
    $y += 35

    # OK / Cancel
    $btnOK = [System.Windows.Forms.Button]::new(); $btnOK.Text = 'Save Entry'; $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK; $btnOK.Location = [System.Drawing.Point]::new(243,$y); $btnOK.Size = [System.Drawing.Size]::new(90,28); $dlg.AcceptButton = $btnOK; $dlg.Controls.Add($btnOK)
    $btnCancel = [System.Windows.Forms.Button]::new(); $btnCancel.Text = 'Cancel'; $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; $btnCancel.Location = [System.Drawing.Point]::new(342,$y); $btnCancel.Size = [System.Drawing.Size]::new(81,28); $dlg.CancelButton = $btnCancel; $dlg.Controls.Add($btnCancel)

    if ($dlg.ShowDialog($Script:Form) -eq [System.Windows.Forms.DialogResult]::OK) {
        $targetFile = $cboSavePath.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($targetFile)) {
            [System.Windows.Forms.MessageBox]::Show('Please select a file to save to.','No File Selected',[System.Windows.Forms.MessageBoxButtons]::OK,[System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
        } else {
            Add-PPSMConfigEntry `
                -FilePath        $targetFile `
                -ApplicationName $txtApp.Text.Trim() `
                -Port            $txtPort.Text.Trim() `
                -Protocol        ([string]$cboProto.SelectedItem) `
                -Direction       ([string]$cboDir.SelectedItem) `
                -Risk            ([string]$cboRisk.SelectedItem) `
                -Notes           $txtNotes.Text.Trim() `
                -Authorized      $radYes.Checked

            if (-not $Script:LoadedConfigPaths.Contains($targetFile)) {
                $Script:LoadedConfigPaths.Add($targetFile)
            }

            $reload = [System.Windows.Forms.MessageBox]::Show(
                "Entry saved to:`n$targetFile`n`nReload this config file now to see it in the grid?",
                'Entry Saved',
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($reload -eq [System.Windows.Forms.DialogResult]::Yes) {
                $rawRecords = Import-PPSMConfig -Paths @($targetFile)
                $timestamp  = Get-Date
                $stamped    = [System.Collections.Generic.List[PSCustomObject]]::new()
                foreach ($rec in $rawRecords) {
                    $rec | Add-Member -NotePropertyName Timestamp  -NotePropertyValue $timestamp -Force
                    $rec | Add-Member -NotePropertyName ScanNumber -NotePropertyValue 'Config'  -Force
                    $rec | Add-Member -NotePropertyName Source     -NotePropertyValue 'Config'  -Force
                    $stamped.Add($rec)
                }
                Add-RecordsToGrid -Grid $Script:Grid -Records $stamped -CountTarget 'Config'
                Update-PPSMStatus -LblStatus $Script:LblStatus -LblCounts $Script:LblCounts -LblLastScan $Script:LblLastScan `
                    -StatusText "Status: Config entry saved and loaded from $([System.IO.Path]::GetFileName($targetFile))"
            }
        }
    }
    $Script:_tmpSaveCombo = $null
    $dlg.Dispose()
}

function Add-RecordsToGrid {
    param(
        $Grid,
        $Records,
        [string]$CountTarget   # 'Live' or 'Config'
    )

    if ($Records.Count -eq 0) { return }

    $Grid.SuspendLayout()
    try {
        foreach ($rec in $Records) {
            if ($Script:IgnoredApps.Contains([string]$rec.ApplicationName)) { continue }
            $authStr = if ($rec.Authorized -eq $true)  { 'YES' }
                       elseif ($rec.Authorized -eq $false) { 'NO' }
                       else { 'Pending' }

            $remoteAddr = if ($rec.RemoteAddress) { $rec.RemoteAddress } else { 'Any' }
            $remotePort = if ($null -ne $rec.RemotePort) { $rec.RemotePort } else { 'Any' }
            $pidVal     = if ($null -ne $rec.Pid) { $rec.Pid } else { '' }

            $Grid.Rows.Add(
                $rec.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'),
                $rec.ScanNumber,
                $rec.Source,
                $rec.ApplicationName,
                $pidVal,
                $rec.Protocol,
                $rec.LocalAddress,
                $rec.LocalPort,
                $remoteAddr,
                $remotePort,
                $rec.Direction,
                $rec.State,
                $rec.ServiceName,
                $rec.RiskLevel,
                $authStr,
                $rec.ConfigSourceFile,
                $rec.Notes
            ) | Out-Null

            $Script:AllRecords.Add($rec)

            if ($CountTarget -eq 'Live')   { $Script:LiveCount++ }
            if ($CountTarget -eq 'Config') { $Script:ConfigCount++ }
        }
    } finally {
        $Grid.ResumeLayout()
    }

    if ($Grid.RowCount -gt 0) {
        $Grid.FirstDisplayedScrollingRowIndex = $Grid.RowCount - 1
    }
}

function Start-PPSMScan {
    param(
        $Grid,
        $LblStatus,
        $LblCounts,
        $LblLastScan
    )

    $Script:ScanNumber++
    $timestamp = Get-Date
    $scanLabel = "S$Script:ScanNumber"

    try {
        $rawRecords = Invoke-PPSMScan

        $stamped = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($rec in $rawRecords) {
            $rec | Add-Member -NotePropertyName Timestamp  -NotePropertyValue $timestamp -Force
            $rec | Add-Member -NotePropertyName ScanNumber -NotePropertyValue $scanLabel -Force
            $rec | Add-Member -NotePropertyName Source     -NotePropertyValue 'Live'     -Force
            $stamped.Add($rec)
        }

        Add-RecordsToGrid -Grid $Grid -Records $stamped -CountTarget 'Live'
        Update-PPSMStatus -LblStatus $LblStatus -LblCounts $LblCounts -LblLastScan $LblLastScan `
            -StatusText   "Status: Scanning ($scanLabel - $($stamped.Count) entries)" `
            -LastScanText $timestamp.ToString('HH:mm:ss')
    } catch {
        Update-PPSMStatus -LblStatus $LblStatus -LblCounts $LblCounts -LblLastScan $LblLastScan `
            -StatusText "Status: ERROR during scan - $($_.Exception.Message)"
    }
}

# -- Main form --

function Build-PPSMForm {

    $Script:Form               = [System.Windows.Forms.Form]::new()
    $Script:Form.Text          = 'PPSM Monitor - Ports, Protocols and Services Management'
    $Script:Form.Size          = [System.Drawing.Size]::new(1400, 800)
    $Script:Form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $Script:Form.MinimumSize   = [System.Drawing.Size]::new(900, 500)

    $Script:Grid   = Build-PPSMGrid
    $Script:TsData = Build-PPSMToolStrip
    $ssData        = Build-PPSMStatusStrip
    $ts            = $Script:TsData.Strip
    $ss            = $ssData.Strip

    $Script:LblStatus   = $ssData.LblStatus
    $Script:LblCounts   = $ssData.LblCounts
    $Script:LblLastScan = $ssData.LblLastScan

    $Script:ScanTimer          = [System.Windows.Forms.Timer]::new()
    $Script:ScanTimer.Interval = 10000

    Import-PPSMIgnoreList

    # -- Right-click context menu --
    $ctx            = [System.Windows.Forms.ContextMenuStrip]::new()
    $ctxIgnore      = [System.Windows.Forms.ToolStripMenuItem]::new('Ignore Application')
    $ctxIgnore.Add_Click({
        if ($Script:Grid.SelectedRows.Count -eq 0) { return }
        $appName = [string]$Script:Grid.SelectedRows[0].Cells[$Script:COL_APPNAME].Value
        if ([string]::IsNullOrWhiteSpace($appName)) { return }
        [void]$Script:IgnoredApps.Add($appName)
        Export-PPSMIgnoreList

        $removeExisting = [System.Windows.Forms.MessageBox]::Show(
            "Added '$appName' to ignore list.`nRemove existing rows for this application from the grid?",
            'Ignore Application',
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($removeExisting -eq [System.Windows.Forms.DialogResult]::Yes) {
            for ($i = $Script:Grid.RowCount - 1; $i -ge 0; $i--) {
                if ($Script:Grid.Rows[$i].Cells[$Script:COL_APPNAME].Value -eq $appName) {
                    $Script:Grid.Rows.RemoveAt($i)
                }
            }
            $toRemove = @($Script:AllRecords | Where-Object { $_.ApplicationName -eq $appName })
            foreach ($r in $toRemove) { [void]$Script:AllRecords.Remove($r) }
            $Script:LiveCount   = @($Script:AllRecords | Where-Object { $_.Source -eq 'Live'   }).Count
            $Script:ConfigCount = @($Script:AllRecords | Where-Object { $_.Source -eq 'Config' }).Count
            Update-PPSMStatus -LblStatus $Script:LblStatus -LblCounts $Script:LblCounts -LblLastScan $Script:LblLastScan
        }
    })
    $ctxAddConfig = [System.Windows.Forms.ToolStripMenuItem]::new('Add to Config...')
    $ctxAddConfig.Add_Click({ Show-PPSMAddToConfigDialog })
    [void]$ctx.Items.Add($ctxIgnore)
    [void]$ctx.Items.Add([System.Windows.Forms.ToolStripSeparator]::new())
    [void]$ctx.Items.Add($ctxAddConfig)
    $Script:Grid.ContextMenuStrip = $ctx

    # -- CellFormatting: color-code Risk and Authorized columns --
    $Script:Grid.Add_CellFormatting({
        param($s, $e)
        if ($e.RowIndex -lt 0) { return }
        if ($e.ColumnIndex -eq $Script:COL_RISK) {
            switch ($e.Value) {
                'Critical' { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 80,  80 ); $e.CellStyle.ForeColor = [System.Drawing.Color]::White }
                'High'     { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 160, 50 ); $e.CellStyle.ForeColor = [System.Drawing.Color]::White }
                'Medium'   { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 230, 80 ); $e.CellStyle.ForeColor = [System.Drawing.Color]::Black }
                'Low'      { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(140, 210, 100); $e.CellStyle.ForeColor = [System.Drawing.Color]::Black }
            }
        }
        if ($e.ColumnIndex -eq $Script:COL_AUTH) {
            switch ($e.Value) {
                'YES'     { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(140, 210, 100); $e.CellStyle.ForeColor = [System.Drawing.Color]::Black }
                'NO'      { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 80,  80 ); $e.CellStyle.ForeColor = [System.Drawing.Color]::White }
                'Pending' { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(255, 230, 80 ); $e.CellStyle.ForeColor = [System.Drawing.Color]::Black }
            }
        }
    })

    # -- Start Scan --
    $Script:TsData.BtnStart.Add_Click({
        $intervalSec = 10
        [int]::TryParse($Script:TsData.TxtInterval.Text, [ref]$intervalSec) | Out-Null
        $intervalSec = [Math]::Max(1, [Math]::Min(3600, $intervalSec))
        $Script:ScanTimer.Interval = $intervalSec * 1000

        $Script:TsData.BtnStart.Enabled = $false
        $Script:TsData.BtnStop.Enabled  = $true

        Start-PPSMScan -Grid $Script:Grid -LblStatus $Script:LblStatus -LblCounts $Script:LblCounts -LblLastScan $Script:LblLastScan
        $Script:ScanTimer.Start()
        Update-PPSMStatus -LblStatus $Script:LblStatus -LblCounts $Script:LblCounts -LblLastScan $Script:LblLastScan `
            -StatusText "Status: Scanning every ${intervalSec}s (running)"
    })

    # -- Stop Scan --
    $Script:TsData.BtnStop.Add_Click({
        $Script:ScanTimer.Stop()
        $Script:TsData.BtnStart.Enabled = $true
        $Script:TsData.BtnStop.Enabled  = $false
        Update-PPSMStatus -LblStatus $Script:LblStatus -LblCounts $Script:LblCounts -LblLastScan $Script:LblLastScan `
            -StatusText 'Status: Stopped'
    })

    # -- Timer Tick --
    $Script:ScanTimer.Add_Tick({
        Start-PPSMScan -Grid $Script:Grid -LblStatus $Script:LblStatus -LblCounts $Script:LblCounts -LblLastScan $Script:LblLastScan
    })

    # -- Load Config --
    $Script:TsData.BtnLoad.Add_Click({
        $ofd             = [System.Windows.Forms.OpenFileDialog]::new()
        $ofd.Title       = 'Select PPSM Config File(s)'
        $ofd.Filter      = 'YAML Files (*.yaml;*.yml)|*.yaml;*.yml|All Files (*.*)|*.*'
        $ofd.Multiselect = $true

        if ($ofd.ShowDialog($Script:Form) -ne [System.Windows.Forms.DialogResult]::OK) { return }

        try {
            $rawRecords = Import-PPSMConfig -Paths $ofd.FileNames
            $timestamp  = Get-Date

            $stamped = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($rec in $rawRecords) {
                $rec | Add-Member -NotePropertyName Timestamp  -NotePropertyValue $timestamp -Force
                $rec | Add-Member -NotePropertyName ScanNumber -NotePropertyValue 'Config'  -Force
                $rec | Add-Member -NotePropertyName Source     -NotePropertyValue 'Config'  -Force
                $stamped.Add($rec)
            }

            foreach ($p in $ofd.FileNames) {
                if (-not $Script:LoadedConfigPaths.Contains($p)) { $Script:LoadedConfigPaths.Add($p) }
            }
            Add-RecordsToGrid -Grid $Script:Grid -Records $stamped -CountTarget 'Config'
            Update-PPSMStatus -LblStatus $Script:LblStatus -LblCounts $Script:LblCounts -LblLastScan $Script:LblLastScan `
                -StatusText "Status: Loaded $($stamped.Count) config record(s) from $($ofd.FileNames.Count) file(s)"
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to load config file(s):`n$($_.Exception.Message)",
                'Load Error',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
    })

    # -- Export Excel --
    $Script:TsData.BtnExport.Add_Click({
        if ($Script:AllRecords.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show(
                'No records to export. Run a scan or load a config file first.',
                'Export',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            ) | Out-Null
            return
        }

        $sfd          = [System.Windows.Forms.SaveFileDialog]::new()
        $sfd.Title    = 'Export PPSM Report'
        $sfd.Filter   = 'Excel Workbook (*.xlsx)|*.xlsx'
        $sfd.FileName = "PPSM_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').xlsx"

        if ($sfd.ShowDialog($Script:Form) -ne [System.Windows.Forms.DialogResult]::OK) { return }

        try {
            # Deduplicate: exclude ignored apps and rows identical in all fields except Timestamp/ScanNumber
            $seen    = [System.Collections.Generic.HashSet[string]]::new()
            $deduped = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($rec in $Script:AllRecords) {
                if ($Script:IgnoredApps.Contains([string]$rec.ApplicationName)) { continue }
                $key = [string]::Join('|', @(
                    $rec.Source, $rec.ApplicationName, $rec.Pid,
                    $rec.Protocol, $rec.LocalAddress, $rec.LocalPort,
                    $rec.RemoteAddress, $rec.RemotePort,
                    $rec.Direction, $rec.State, $rec.ServiceName,
                    $rec.RiskLevel, $rec.Authorized, $rec.ConfigSourceFile, $rec.Notes
                ))
                if ($seen.Add($key)) { $deduped.Add($rec) }
            }
            Export-PPSMReport -Records $deduped -OutputPath $sfd.FileName
            Update-PPSMStatus -LblStatus $Script:LblStatus -LblCounts $Script:LblCounts -LblLastScan $Script:LblLastScan `
                -StatusText "Status: Exported $($deduped.Count) unique rows to $($sfd.FileName)"

            $open = [System.Windows.Forms.MessageBox]::Show(
                "Report saved to:`n$($sfd.FileName)`n`nOpen now?",
                'Export Complete',
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($open -eq [System.Windows.Forms.DialogResult]::Yes) {
                Start-Process $sfd.FileName
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Export failed:`n$($_.Exception.Message)",
                'Export Error',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        }
    })

    # -- Clear All --
    $Script:TsData.BtnClear.Add_Click({
        $confirm = [System.Windows.Forms.MessageBox]::Show(
            'Remove all rows from the grid? This cannot be undone.',
            'Clear All',
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        $Script:Grid.Rows.Clear()
        $Script:AllRecords.Clear()
        $Script:LiveCount   = 0
        $Script:ConfigCount = 0
        $Script:ScanNumber  = 0

        Update-PPSMStatus -LblStatus $Script:LblStatus -LblCounts $Script:LblCounts -LblLastScan $Script:LblLastScan `
            -StatusText 'Status: Cleared' -LastScanText 'never'
    })

    # -- Ignored Apps --
    $Script:TsData.BtnIgnored.Add_Click({
        Show-PPSMIgnoreDialog
    })

    # -- Form closing --
    $Script:Form.Add_FormClosing({
        $Script:ScanTimer.Stop()
        $Script:ScanTimer.Dispose()
    })

    # -- Assemble --
    $Script:Form.Controls.Add($Script:Grid)
    $Script:Form.Controls.Add($ts)
    $Script:Form.Controls.Add($ss)

    return $Script:Form
}

function Start-PPSMApp {
    try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch {}
    try { [System.Windows.Forms.Application]::EnableVisualStyles() } catch {}
    $form = Build-PPSMForm
    $form.ShowDialog() | Out-Null
    $form.Dispose()
}

#endregion GUI

#region MAIN
Start-PPSMApp
#endregion MAIN
