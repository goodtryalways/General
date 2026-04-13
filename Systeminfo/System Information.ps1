<#
.SYNOPSIS
    Collects comprehensive server information before migration.
    Compatible with PowerShell v4 and PowerShell ISE.

.DESCRIPTION
    Gathers OS, hardware, network, disk, services, scheduled tasks,
    installed software, roles, hotfixes, users, and firewall details.
    Exports an HTML report AND two CSV files (detail + summary) per run.

.PARAMETER Action
    'Local'  - Collect from the local machine only (no WinRM required).
    'Remote' - Collect from one or more remote servers via WinRM/WMI.

.PARAMETER ComputerName
    Target server(s). Used only when Action = 'Remote'.
    Comma-separated:  -ComputerName SRV01,SRV02

.PARAMETER OutputPath
    Folder where reports are saved. Defaults to C:\Temp.

.PARAMETER Credential
    PSCredential for remote connections (optional).
    If omitted the current user context is used.

.EXAMPLE
    # Run locally - press F5 in ISE
    .\Get-ServerMigrationInfo.ps1 -Action Local

.EXAMPLE
    .\Get-ServerMigrationInfo.ps1 -Action Remote -ComputerName SRV01

.EXAMPLE
    .\Get-ServerMigrationInfo.ps1 -Action Remote -ComputerName SRV01,SRV02 `
        -OutputPath D:\Reports -Credential (Get-Credential)
#>

param(
    [ValidateSet('Local','Remote')]
    [string]$Action = 'Local',

    [string[]]$ComputerName = @(),

    [string]$OutputPath = 'C:\Temp',

    [System.Management.Automation.PSCredential]$Credential = $null
)

# ---------------------------------------------------------------------------
# PS v4 / ISE guards
# ---------------------------------------------------------------------------
$ErrorActionPreference = 'SilentlyContinue'
# Set-StrictMode intentionally OFF – causes scoping edge cases in PS v4 ISE

# ---------------------------------------------------------------------------
# Resolve target list
# ---------------------------------------------------------------------------
if ($Action -eq 'Local') {
    $targets = @($env:COMPUTERNAME)
} else {
    if ($ComputerName.Count -eq 0) {
        Write-Warning "Action=Remote but no -ComputerName specified. Targeting local machine."
        $targets = @($env:COMPUTERNAME)
    } else {
        $targets = $ComputerName
    }
}

# ---------------------------------------------------------------------------
# Ensure output folder exists
# ---------------------------------------------------------------------------
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Host "Created output folder: $OutputPath" -ForegroundColor DarkGray
}

# ===========================================================================
# HELPERS
# ===========================================================================

function Format-Bytes {
    param([double]$Bytes)
    if     ($Bytes -ge 1TB) { return ('{0:N2} TB' -f ($Bytes / 1TB)) }
    elseif ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    elseif ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    elseif ($Bytes -ge 1KB) { return ('{0:N2} KB' -f ($Bytes / 1KB)) }
    else                    { return "$Bytes B" }
}

function ConvertFrom-WmiDate {
    param($WmiDate)
    if ($WmiDate -and ($WmiDate -ne '')) {
        try   { return [System.Management.ManagementDateTimeConverter]::ToDateTime($WmiDate) }
        catch { return $WmiDate }
    }
    return 'N/A'
}

# Flatten a PSObject to a "key=value | key=value" string – PS v4 safe
function ConvertTo-FlatString {
    param($Obj)
    if ($Obj -eq $null) { return '' }
    $props = $Obj | Get-Member -MemberType NoteProperty,Property -ErrorAction SilentlyContinue |
             Select-Object -ExpandProperty Name
    $parts = New-Object System.Collections.ArrayList
    foreach ($p in $props) {
        [void]$parts.Add("$p=$($Obj.$p)")
    }
    return ($parts -join ' | ')
}

# Execute a scriptblock locally or on a remote machine
function Invoke-Collect {
    param(
        [string]$Computer,
        [scriptblock]$ScriptBlock,
        [System.Management.Automation.PSCredential]$Cred
    )
    $isLocal = ($Computer -ieq $env:COMPUTERNAME) -or
               ($Computer -ieq 'localhost')        -or
               ($Computer -eq '.')

    if ($isLocal) {
        return (& $ScriptBlock)
    } else {
        $p = @{
            ComputerName = $Computer
            ScriptBlock  = $ScriptBlock
            ErrorAction  = 'Stop'
        }
        if ($Cred -ne $null) { $p['Credential'] = $Cred }
        return (Invoke-Command @p)
    }
}

# ===========================================================================
# DATA COLLECTION  – returns a plain hashtable (PS v4 safe, no [ordered])
# ===========================================================================

function Get-ServerInfo {
    param(
        [string]$Computer,
        [System.Management.Automation.PSCredential]$Cred
    )

    Write-Host "  [Collecting] $Computer ..." -ForegroundColor Cyan

    $d = New-Object System.Collections.Hashtable
    $d['ComputerName'] = $Computer
    $d['CollectedAt']  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $d['Action']       = $Action

    # -----------------------------------------------------------------------
    # 1. OS / System
    # -----------------------------------------------------------------------
    $os = Invoke-Collect $Computer {
        Get-WmiObject Win32_OperatingSystem |
        Select-Object Caption,Version,BuildNumber,OSArchitecture,
                      InstallDate,LastBootUpTime,
                      TotalVisibleMemorySize,FreePhysicalMemory,SystemDirectory
    } -Cred $Cred

    $cs = Invoke-Collect $Computer {
        Get-WmiObject Win32_ComputerSystem |
        Select-Object Manufacturer,Model,NumberOfProcessors,
                      NumberOfLogicalProcessors,TotalPhysicalMemory,
                      Domain,DNSHostName,SystemType
    } -Cred $Cred

    $bios = Invoke-Collect $Computer {
        Get-WmiObject Win32_BIOS |
        Select-Object Manufacturer,SMBIOSBIOSVersion,ReleaseDate,SerialNumber
    } -Cred $Cred

    $installDt = ConvertFrom-WmiDate $os.InstallDate
    $lastBoot  = ConvertFrom-WmiDate $os.LastBootUpTime

    $d['OS']           = $os.Caption
    $d['OSVersion']    = $os.Version
    $d['OSBuild']      = $os.BuildNumber
    $d['OSArch']       = $os.OSArchitecture
    $d['InstallDate']  = $installDt
    $d['LastBoot']     = $lastBoot
    $d['UptimeDays']   = if ($lastBoot -is [datetime]) { [math]::Round(((Get-Date) - $lastBoot).TotalDays, 1) } else { 'N/A' }
    $d['TotalRAM']     = Format-Bytes ([double]$cs.TotalPhysicalMemory)
    $d['FreeRAM']      = Format-Bytes ([double]$os.FreePhysicalMemory * 1024)
    $d['Manufacturer'] = $cs.Manufacturer
    $d['Model']        = $cs.Model
    $d['NumCPUs']      = $cs.NumberOfProcessors
    $d['LogicalCPUs']  = $cs.NumberOfLogicalProcessors
    $d['Domain']       = $cs.Domain
    $d['DNSHostName']  = $cs.DNSHostName
    $d['BIOSVersion']  = $bios.SMBIOSBIOSVersion
    $d['BIOSDate']     = ConvertFrom-WmiDate $bios.ReleaseDate
    $d['SerialNo']     = $bios.SerialNumber
    $d['SystemDir']    = $os.SystemDirectory

    # -----------------------------------------------------------------------
    # 2. Processors
    # -----------------------------------------------------------------------
    $d['CPUs'] = Invoke-Collect $Computer {
        Get-WmiObject Win32_Processor |
        Select-Object Name,MaxClockSpeed,NumberOfCores,
                      NumberOfLogicalProcessors,SocketDesignation,LoadPercentage
    } -Cred $Cred

    # -----------------------------------------------------------------------
    # 3. Physical Disks
    # -----------------------------------------------------------------------
    $d['Disks'] = Invoke-Collect $Computer {
        Get-WmiObject Win32_DiskDrive |
        Select-Object Index, Model,
            @{N='SizeGB';E={if($_.Size){[math]::Round($_.Size/1GB,2)}else{0}}},
            InterfaceType, MediaType, SerialNumber, FirmwareRevision
    } -Cred $Cred

    # -----------------------------------------------------------------------
    # 4. Logical Volumes
    # -----------------------------------------------------------------------
    $d['Volumes'] = Invoke-Collect $Computer {
        Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" |
        Select-Object DeviceID, VolumeName, FileSystem,
            @{N='TotalGB'; E={if($_.Size)     {[math]::Round($_.Size/1GB,2)}     else{0}}},
            @{N='FreeGB';  E={if($_.FreeSpace){[math]::Round($_.FreeSpace/1GB,2)}else{0}}},
            @{N='UsedPct'; E={if($_.Size -gt 0){[math]::Round((($_.Size-$_.FreeSpace)/$_.Size)*100,1)}else{0}}}
    } -Cred $Cred

    # -----------------------------------------------------------------------
    # 5. Network Adapters
    # -----------------------------------------------------------------------
    $d['Network'] = Invoke-Collect $Computer {
        Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" |
        Select-Object Description, MACAddress,
            @{N='IPAddresses'; E={if($_.IPAddress)          {$_.IPAddress -join ', '}          else{''}}},
            @{N='SubnetMasks'; E={if($_.IPSubnet)           {$_.IPSubnet -join ', '}           else{''}}},
            @{N='DefaultGW';   E={if($_.DefaultIPGateway)   {$_.DefaultIPGateway -join ', '}   else{''}}},
            @{N='DNSServers';  E={if($_.DNSServerSearchOrder){$_.DNSServerSearchOrder -join ', '}else{''}}},
            DHCPEnabled, DHCPServer, DNSDomain
    } -Cred $Cred

    # -----------------------------------------------------------------------
    # 6. Windows Roles & Features
    # -----------------------------------------------------------------------
    $d['Roles'] = Invoke-Collect $Computer {
        $cmd = Get-Command 'Get-WindowsFeature' -ErrorAction SilentlyContinue
        if ($cmd) {
            Get-WindowsFeature | Where-Object { $_.Installed -eq $true } |
            Select-Object Name, DisplayName, FeatureType
        } else {
            @([PSCustomObject]@{
                Name='N/A'
                DisplayName='Get-WindowsFeature not available (non-Server OS)'
                FeatureType=''
            })
        }
    } -Cred $Cred

    # -----------------------------------------------------------------------
    # 7. Installed Software
    # -----------------------------------------------------------------------
    $d['Software'] = Invoke-Collect $Computer {
        $regPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $list = New-Object System.Collections.ArrayList
        foreach ($p in $regPaths) {
            if (Test-Path $p) {
                $items = Get-ItemProperty $p -ErrorAction SilentlyContinue |
                         Where-Object { $_.DisplayName -ne $null -and $_.DisplayName -ne '' }
                foreach ($i in $items) { [void]$list.Add($i) }
            }
        }
        $list | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate |
                Sort-Object DisplayName
    } -Cred $Cred

    # -----------------------------------------------------------------------
    # 8. Services
    # -----------------------------------------------------------------------
    $d['Services'] = Invoke-Collect $Computer {
        Get-WmiObject Win32_Service |
        Select-Object Name,DisplayName,State,StartMode,PathName,StartName |
        Sort-Object State,DisplayName
    } -Cred $Cred

    # -----------------------------------------------------------------------
    # 9. Scheduled Tasks  (schtasks.exe – no PS v5 module required)
    # -----------------------------------------------------------------------
    $d['ScheduledTasks'] = Invoke-Collect $Computer {
        $raw = schtasks.exe /Query /FO CSV /NH 2>$null
        if ($raw) {
            $parsed = $raw | ConvertFrom-Csv -Header 'TaskName','NextRunTime','Status'
            $result = New-Object System.Collections.ArrayList
            foreach ($t in $parsed) {
                if ($t.Status -ne 'Disabled') {
                    [void]$result.Add([PSCustomObject]@{
                        TaskName    = $t.TaskName
                        NextRunTime = $t.NextRunTime
                        Status      = $t.Status
                    })
                }
            }
            $result | Sort-Object TaskName
        } else {
            @([PSCustomObject]@{ TaskName='N/A'; NextRunTime=''; Status='Could not retrieve' })
        }
    } -Cred $Cred

    # -----------------------------------------------------------------------
    # 10. Local Users  (WMI – no Get-LocalUser)
    # -----------------------------------------------------------------------
    $d['LocalUsers'] = Invoke-Collect $Computer {
        Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" |
        Select-Object Name,Disabled,Lockout,PasswordRequired,
                      PasswordExpires,Description,SID |
        Sort-Object Name
    } -Cred $Cred

    # -----------------------------------------------------------------------
    # 11. Local Groups & Members  (WMI – no Get-LocalGroup)
    # -----------------------------------------------------------------------
    $d['LocalGroups'] = Invoke-Collect $Computer {
        $groups = Get-WmiObject Win32_Group -Filter "LocalAccount=True"
        $result = New-Object System.Collections.ArrayList
        foreach ($grp in $groups) {
            $wql     = "SELECT * FROM Win32_GroupUser WHERE GroupComponent=""Win32_Group.Domain='$($grp.Domain)',Name='$($grp.Name)'"""
            $members = Get-WmiObject -Query $wql -ErrorAction SilentlyContinue
            $mList   = New-Object System.Collections.ArrayList
            foreach ($m in $members) {
                if ($m.PartComponent -match 'Name="([^"]+)"') {
                    [void]$mList.Add($Matches[1])
                }
            }
            [void]$result.Add([PSCustomObject]@{
                GroupName   = $grp.Name
                Description = $grp.Description
                Members     = ($mList -join '; ')
            })
        }
        $result
    } -Cred $Cred

    # -----------------------------------------------------------------------
    # 12. Firewall Rules  (netsh – works on all Windows/PS versions)
    # -----------------------------------------------------------------------
    $d['FirewallRules'] = Invoke-Collect $Computer {
        $lines  = netsh advfirewall firewall show rule name=all 2>$null
        $rules  = New-Object System.Collections.ArrayList
        $cur    = $null
        foreach ($line in $lines) {
            if ($line -match '^Rule Name:\s+(.+)$') {
                if ($cur -ne $null) { [void]$rules.Add([PSCustomObject]$cur) }
                $cur = New-Object System.Collections.Hashtable
                $cur['RuleName'] = $Matches[1].Trim()
            } elseif ($cur -ne $null) {
                if ($line -match '^Enabled:\s+(.+)$')   { $cur['Enabled']   = $Matches[1].Trim() }
                if ($line -match '^Direction:\s+(.+)$') { $cur['Direction'] = $Matches[1].Trim() }
                if ($line -match '^Action:\s+(.+)$')    { $cur['Action']    = $Matches[1].Trim() }
                if ($line -match '^Profiles:\s+(.+)$')  { $cur['Profiles']  = $Matches[1].Trim() }
            }
        }
        if ($cur -ne $null) { [void]$rules.Add([PSCustomObject]$cur) }
        $rules | Where-Object { $_.Enabled -eq 'Yes' } | Sort-Object Direction,RuleName
    } -Cred $Cred

    # -----------------------------------------------------------------------
    # 13. System Environment Variables
    # -----------------------------------------------------------------------
    $d['EnvVars'] = Invoke-Collect $Computer {
        $envVars = [System.Environment]::GetEnvironmentVariables('Machine')
        $result  = New-Object System.Collections.ArrayList
        foreach ($key in ($envVars.Keys | Sort-Object)) {
            [void]$result.Add([PSCustomObject]@{ Name=$key; Value=$envVars[$key] })
        }
        $result
    } -Cred $Cred

    # -----------------------------------------------------------------------
    # 14. Hotfixes
    # -----------------------------------------------------------------------
    $d['Hotfixes'] = Invoke-Collect $Computer {
        Get-WmiObject Win32_QuickFixEngineering |
        Select-Object HotFixID, Description, InstalledBy,
            @{N='InstalledOn'; E={
                if ($_.InstalledOn) {
                    try { ([datetime]$_.InstalledOn).ToString('yyyy-MM-dd') }
                    catch { $_.InstalledOn }
                } else { '' }
            }} |
        Sort-Object InstalledOn -Descending
    } -Cred $Cred

    return $d
}

# ===========================================================================
# EXPORT: HTML REPORT
# ===========================================================================

function New-HtmlTable {
    param($DataSet)
    if ($DataSet -eq $null) { return '<p><em>No data collected.</em></p>' }
    $arr = @($DataSet)
    if ($arr.Count -eq 0)   { return '<p><em>No data collected.</em></p>' }
    return ($arr | ConvertTo-Html -Fragment -As Table | Out-String)
}

function Export-HtmlReport {
    param($Info, [string]$FilePath)

    $css = @'
<style>
  body  { font-family:"Segoe UI",Arial,sans-serif; margin:24px; background:#f0f2f5; color:#1a1a1a; }
  h1    { background:#004578; color:#fff; padding:16px 22px; border-radius:6px; margin-bottom:8px; }
  .badge{ display:inline-block; background:#e8f0fe; color:#004578; border:1px solid #b3c6e7;
          border-radius:4px; padding:3px 10px; font-size:12px; margin:3px; }
  .summary{ background:#fff; padding:14px 20px; border-radius:6px; margin-bottom:24px;
            box-shadow:0 1px 5px rgba(0,0,0,.10); }
  h2    { border-left:5px solid #0078d4; padding-left:10px; margin-top:32px;
          color:#004578; font-size:15px; }
  table { border-collapse:collapse; width:100%; margin:8px 0 18px 0; background:#fff;
          box-shadow:0 1px 4px rgba(0,0,0,.10); border-radius:5px; overflow:hidden; font-size:13px; }
  th    { background:#004578; color:#fff; padding:8px 12px; text-align:left; white-space:nowrap; }
  td    { padding:6px 12px; border-bottom:1px solid #e8e8e8; vertical-align:top; word-break:break-word; }
  tr:last-child td { border-bottom:none; }
  tr:nth-child(even) td { background:#f7f9fc; }
  tr:hover td { background:#ddeeff; }
  .footer{ margin-top:32px; font-size:11px; color:#888; text-align:center; }
</style>
'@

    $pageTitle = "Pre-Migration Report: $($Info['ComputerName'])"

    $summaryBlock = "<div class='summary'>" +
        "<span class='badge'>Mode: $($Info['Action'])</span> " +
        "<span class='badge'>Collected: $($Info['CollectedAt'])</span> " +
        "<span class='badge'>OS: $($Info['OS'])</span> " +
        "<span class='badge'>RAM: $($Info['TotalRAM']) total / $($Info['FreeRAM']) free</span> " +
        "<span class='badge'>CPUs: $($Info['NumCPUs']) socket / $($Info['LogicalCPUs']) logical</span> " +
        "<span class='badge'>Uptime: $($Info['UptimeDays']) days</span> " +
        "<span class='badge'>Domain: $($Info['Domain'])</span> " +
        "<span class='badge'>Serial: $($Info['SerialNo'])</span>" +
        "</div>"

    $sysRows = New-Object System.Collections.ArrayList
    [void]$sysRows.Add([PSCustomObject]@{Property='Computer Name';    Value=$Info['ComputerName']})
    [void]$sysRows.Add([PSCustomObject]@{Property='DNS Host Name';    Value=$Info['DNSHostName']})
    [void]$sysRows.Add([PSCustomObject]@{Property='Operating System'; Value=$Info['OS']})
    [void]$sysRows.Add([PSCustomObject]@{Property='OS Version';       Value=$Info['OSVersion']})
    [void]$sysRows.Add([PSCustomObject]@{Property='Build Number';     Value=$Info['OSBuild']})
    [void]$sysRows.Add([PSCustomObject]@{Property='Architecture';     Value=$Info['OSArch']})
    [void]$sysRows.Add([PSCustomObject]@{Property='Install Date';     Value=$Info['InstallDate']})
    [void]$sysRows.Add([PSCustomObject]@{Property='Last Boot';        Value=$Info['LastBoot']})
    [void]$sysRows.Add([PSCustomObject]@{Property='Uptime (days)';    Value=$Info['UptimeDays']})
    [void]$sysRows.Add([PSCustomObject]@{Property='Total RAM';        Value=$Info['TotalRAM']})
    [void]$sysRows.Add([PSCustomObject]@{Property='Free RAM';         Value=$Info['FreeRAM']})
    [void]$sysRows.Add([PSCustomObject]@{Property='Manufacturer';     Value=$Info['Manufacturer']})
    [void]$sysRows.Add([PSCustomObject]@{Property='Model';            Value=$Info['Model']})
    [void]$sysRows.Add([PSCustomObject]@{Property='Serial Number';    Value=$Info['SerialNo']})
    [void]$sysRows.Add([PSCustomObject]@{Property='BIOS Version';     Value=$Info['BIOSVersion']})
    [void]$sysRows.Add([PSCustomObject]@{Property='BIOS Date';        Value=$Info['BIOSDate']})
    [void]$sysRows.Add([PSCustomObject]@{Property='Domain';           Value=$Info['Domain']})
    [void]$sysRows.Add([PSCustomObject]@{Property='System Directory'; Value=$Info['SystemDir']})

    # Build body as ArrayList of strings – avoids PSObject op_Addition issue in PS v4
    $bodyParts = New-Object System.Collections.ArrayList
    [void]$bodyParts.Add('<h2>1. System Overview</h2>'                + (New-HtmlTable $sysRows))
    [void]$bodyParts.Add('<h2>2. Processors</h2>'                     + (New-HtmlTable $Info['CPUs']))
    [void]$bodyParts.Add('<h2>3. Physical Disks</h2>'                 + (New-HtmlTable $Info['Disks']))
    [void]$bodyParts.Add('<h2>4. Logical Volumes</h2>'                + (New-HtmlTable $Info['Volumes']))
    [void]$bodyParts.Add('<h2>5. Network Adapters</h2>'               + (New-HtmlTable $Info['Network']))
    [void]$bodyParts.Add('<h2>6. Windows Roles &amp; Features</h2>'   + (New-HtmlTable $Info['Roles']))
    [void]$bodyParts.Add('<h2>7. Installed Software</h2>'             + (New-HtmlTable $Info['Software']))
    [void]$bodyParts.Add('<h2>8. Services</h2>'                       + (New-HtmlTable $Info['Services']))
    [void]$bodyParts.Add('<h2>9. Scheduled Tasks</h2>'                + (New-HtmlTable $Info['ScheduledTasks']))
    [void]$bodyParts.Add('<h2>10. Local Users</h2>'                   + (New-HtmlTable $Info['LocalUsers']))
    [void]$bodyParts.Add('<h2>11. Local Groups</h2>'                  + (New-HtmlTable $Info['LocalGroups']))
    [void]$bodyParts.Add('<h2>12. Firewall Rules (Enabled)</h2>'      + (New-HtmlTable $Info['FirewallRules']))
    [void]$bodyParts.Add('<h2>13. System Environment Variables</h2>'  + (New-HtmlTable $Info['EnvVars']))
    [void]$bodyParts.Add('<h2>14. Hotfixes / Windows Updates</h2>'    + (New-HtmlTable $Info['Hotfixes']))
    [void]$bodyParts.Add("<div class='footer'>Generated by Get-ServerMigrationInfo.ps1 on $($Info['CollectedAt'])</div>")

    $bodyHtml = [string]::Join("`n", $bodyParts.ToArray())

    $html = "<!DOCTYPE html>`n<html lang='en'>`n<head>`n" +
            "  <meta charset='utf-8'>`n" +
            "  <title>$pageTitle</title>`n" +
            "  $css`n" +
            "</head>`n<body>`n" +
            "  <h1>$pageTitle</h1>`n" +
            "  $summaryBlock`n" +
            "  $bodyHtml`n" +
            "</body>`n</html>"

    $html | Out-File -FilePath $FilePath -Encoding UTF8
}

# ===========================================================================
# EXPORT: DETAIL CSV  (one row per item per section)
# ===========================================================================

function Export-DetailCsv {
    param($Info, [string]$FilePath)

    # Use ArrayList – avoids the PS v4 PSObject op_Addition bug entirely
    $rows = New-Object System.Collections.ArrayList

    $sections = @(
        @{ Name='SystemOverview'; Data= @([PSCustomObject]@{
                OS=$Info['OS']; Version=$Info['OSVersion']; Build=$Info['OSBuild']
                Arch=$Info['OSArch']; TotalRAM=$Info['TotalRAM']; FreeRAM=$Info['FreeRAM']
                CPUSockets=$Info['NumCPUs']; LogicalCPUs=$Info['LogicalCPUs']
                Manufacturer=$Info['Manufacturer']; Model=$Info['Model']
                Serial=$Info['SerialNo']; BIOS=$Info['BIOSVersion']
                Domain=$Info['Domain']; LastBoot=$Info['LastBoot']; UptimeDays=$Info['UptimeDays']
           }) }
        @{ Name='Processors';       Data=$Info['CPUs']           }
        @{ Name='PhysicalDisks';    Data=$Info['Disks']          }
        @{ Name='LogicalVolumes';   Data=$Info['Volumes']        }
        @{ Name='NetworkAdapters';  Data=$Info['Network']        }
        @{ Name='RolesFeatures';    Data=$Info['Roles']          }
        @{ Name='InstalledSoftware';Data=$Info['Software']       }
        @{ Name='Services';         Data=$Info['Services']       }
        @{ Name='ScheduledTasks';   Data=$Info['ScheduledTasks'] }
        @{ Name='LocalUsers';       Data=$Info['LocalUsers']     }
        @{ Name='LocalGroups';      Data=$Info['LocalGroups']    }
        @{ Name='FirewallRules';    Data=$Info['FirewallRules']  }
        @{ Name='EnvVariables';     Data=$Info['EnvVars']        }
        @{ Name='Hotfixes';         Data=$Info['Hotfixes']       }
    )

    foreach ($sec in $sections) {
        if ($sec.Data -eq $null) { continue }
        foreach ($item in @($sec.Data)) {
            if ($item -eq $null) { continue }
            $row = New-Object PSObject
            $row | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Info['ComputerName']
            $row | Add-Member -MemberType NoteProperty -Name CollectedAt  -Value $Info['CollectedAt']
            $row | Add-Member -MemberType NoteProperty -Name Action       -Value $Info['Action']
            $row | Add-Member -MemberType NoteProperty -Name Section      -Value $sec.Name
            $row | Add-Member -MemberType NoteProperty -Name Detail       -Value (ConvertTo-FlatString $item)
            [void]$rows.Add($row)
        }
    }

    $rows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
}

# ===========================================================================
# MAIN
# ===========================================================================

Write-Host ''
Write-Host '=====================================================' -ForegroundColor White
Write-Host '  Server Pre-Migration Collector'                       -ForegroundColor Cyan
Write-Host "  Action   : $Action"                                   -ForegroundColor White
Write-Host "  Target(s): $($targets -join ', ')"                   -ForegroundColor White
Write-Host "  Output   : $OutputPath"                               -ForegroundColor White
Write-Host '=====================================================' -ForegroundColor White
Write-Host ''

# Use ArrayList for summary – no PSObject op_Addition issues
$summaryList = New-Object System.Collections.ArrayList
$stamp       = Get-Date -Format 'yyyyMMdd_HHmm'

foreach ($server in $targets) {

    Write-Host "Processing: $server" -ForegroundColor Yellow

    try {
        $info = Get-ServerInfo -Computer $server -Cred $Credential

        # HTML report
        $htmlFile = Join-Path $OutputPath ($server + '_MigrationReport_' + $stamp + '.html')
        Export-HtmlReport -Info $info -FilePath $htmlFile
        Write-Host ("  [HTML] " + $htmlFile) -ForegroundColor Green

        # Detail CSV
        $detailCsv = Join-Path $OutputPath ($server + '_MigrationDetail_' + $stamp + '.csv')
        Export-DetailCsv -Info $info -FilePath $detailCsv
        Write-Host ("  [CSV]  " + $detailCsv) -ForegroundColor Green

        # Build summary row using Add-Member (PS v4 safe)
        $row = New-Object PSObject
        $row | Add-Member NoteProperty ComputerName    $info['ComputerName']
        $row | Add-Member NoteProperty CollectedAt     $info['CollectedAt']
        $row | Add-Member NoteProperty Action          $info['Action']
        $row | Add-Member NoteProperty Status          'OK'
        $row | Add-Member NoteProperty OS              $info['OS']
        $row | Add-Member NoteProperty OSVersion       $info['OSVersion']
        $row | Add-Member NoteProperty OSBuild         $info['OSBuild']
        $row | Add-Member NoteProperty Architecture    $info['OSArch']
        $row | Add-Member NoteProperty TotalRAM        $info['TotalRAM']
        $row | Add-Member NoteProperty FreeRAM         $info['FreeRAM']
        $row | Add-Member NoteProperty CPUSockets      $info['NumCPUs']
        $row | Add-Member NoteProperty LogicalCPUs     $info['LogicalCPUs']
        $row | Add-Member NoteProperty Manufacturer    $info['Manufacturer']
        $row | Add-Member NoteProperty Model           $info['Model']
        $row | Add-Member NoteProperty SerialNumber    $info['SerialNo']
        $row | Add-Member NoteProperty BIOSVersion     $info['BIOSVersion']
        $row | Add-Member NoteProperty Domain          $info['Domain']
        $row | Add-Member NoteProperty LastBoot        $info['LastBoot']
        $row | Add-Member NoteProperty UptimeDays      $info['UptimeDays']
        $row | Add-Member NoteProperty DiskCount       (@($info['Disks'])      | Measure-Object).Count
        $row | Add-Member NoteProperty VolumeCount     (@($info['Volumes'])    | Measure-Object).Count
        $row | Add-Member NoteProperty NICCount        (@($info['Network'])    | Measure-Object).Count
        $row | Add-Member NoteProperty InstalledSW     (@($info['Software'])   | Measure-Object).Count
        $row | Add-Member NoteProperty TotalServices   (@($info['Services'])   | Measure-Object).Count
        $row | Add-Member NoteProperty RunningServices (@($info['Services'])   | Where-Object { $_.State -eq 'Running' } | Measure-Object).Count
        $row | Add-Member NoteProperty HotfixCount     (@($info['Hotfixes'])   | Measure-Object).Count
        $row | Add-Member NoteProperty LocalUserCount  (@($info['LocalUsers']) | Measure-Object).Count
        $row | Add-Member NoteProperty HTMLReport      $htmlFile
        $row | Add-Member NoteProperty DetailCSV       $detailCsv
        $row | Add-Member NoteProperty ErrorMessage    ''
        [void]$summaryList.Add($row)

    } catch {
        Write-Warning ("  [FAILED] " + $server + " : " + $_.Exception.Message)

        $row = New-Object PSObject
        $row | Add-Member NoteProperty ComputerName    $server
        $row | Add-Member NoteProperty CollectedAt     (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        $row | Add-Member NoteProperty Action          $Action
        $row | Add-Member NoteProperty Status          'FAILED'
        $row | Add-Member NoteProperty OS              ''
        $row | Add-Member NoteProperty OSVersion       ''
        $row | Add-Member NoteProperty OSBuild         ''
        $row | Add-Member NoteProperty Architecture    ''
        $row | Add-Member NoteProperty TotalRAM        ''
        $row | Add-Member NoteProperty FreeRAM         ''
        $row | Add-Member NoteProperty CPUSockets      ''
        $row | Add-Member NoteProperty LogicalCPUs     ''
        $row | Add-Member NoteProperty Manufacturer    ''
        $row | Add-Member NoteProperty Model           ''
        $row | Add-Member NoteProperty SerialNumber    ''
        $row | Add-Member NoteProperty BIOSVersion     ''
        $row | Add-Member NoteProperty Domain          ''
        $row | Add-Member NoteProperty LastBoot        ''
        $row | Add-Member NoteProperty UptimeDays      ''
        $row | Add-Member NoteProperty DiskCount       ''
        $row | Add-Member NoteProperty VolumeCount     ''
        $row | Add-Member NoteProperty NICCount        ''
        $row | Add-Member NoteProperty InstalledSW     ''
        $row | Add-Member NoteProperty TotalServices   ''
        $row | Add-Member NoteProperty RunningServices ''
        $row | Add-Member NoteProperty HotfixCount     ''
        $row | Add-Member NoteProperty LocalUserCount  ''
        $row | Add-Member NoteProperty HTMLReport      ''
        $row | Add-Member NoteProperty DetailCSV       ''
        $row | Add-Member NoteProperty ErrorMessage    $_.Exception.Message
        [void]$summaryList.Add($row)
    }

    Write-Host ''
}

# Master summary CSV
$summaryFile = Join-Path $OutputPath ('MigrationSummary_All_' + $stamp + '.csv')
$summaryList | Export-Csv -Path $summaryFile -NoTypeInformation -Encoding UTF8
Write-Host "Summary CSV  -> $summaryFile" -ForegroundColor Cyan

Write-Host ''
Write-Host '=====================================================' -ForegroundColor White
Write-Host "  Done. All reports saved to: $OutputPath"             -ForegroundColor Green
Write-Host '=====================================================' -ForegroundColor White