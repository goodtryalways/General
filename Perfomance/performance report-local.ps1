# HTML content
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Local Server Performance Status</title>
    <style>
        body { font-family: 'Segoe UI'; }
        table { border-collapse: collapse; width: 100%; }
        th, td {
            border: 1px solid #dddddd;
            text-align: center;
            padding: 8px;
        }
        th { background-color: #f2f2f2; }
        .highlight { background-color: red; }
    </style>
</head>
<body>

<h3>Local Server Performance Status</h3>

<table>
<tr>
    <th>Timestamp</th>
    <th>ServerName</th>
    <th>Status</th>
    <th>UpTime</th>
    <th>CPU</th>
    <th>HighCPUProcess</th>
    <th>Memory</th>
    <th>HighMemoryProcess</th>
    <th>HighMemoryValue</th>
</tr>
"@

$cpuThreshold = 80
$memoryThreshold = 80

try {
    $server = $env:COMPUTERNAME

    # Uptime
    $os = Get-CimInstance Win32_OperatingSystem
    $uptime = (Get-Date) - $os.LastBootUpTime
    $uptimeFormatted = $uptime.ToString("dd\.hh\:mm\:ss")

    # CPU
    $cpuLoad = Get-WmiObject Win32_Processor | 
        Measure-Object -Property LoadPercentage -Average | 
        Select-Object -ExpandProperty Average
    $cpu = "{0}%" -f $cpuLoad

    # Memory
    $mem = Get-WmiObject Win32_OperatingSystem
    $totalMemory = $mem.TotalVisibleMemorySize
    $freeMemory = $mem.FreePhysicalMemory
    $usedMemory = $totalMemory - $freeMemory
    $memoryPercent = "{0:N2}%" -f ($usedMemory / $totalMemory * 100)

    # High CPU process
    $highCpuProcess = Get-Process | Sort-Object CPU -Descending | Select-Object -First 1

    # High Memory process
    $highMemProcess = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 1
    $highMemValue = ($highMemProcess.WorkingSet / 1GB).ToString("N2") + " GB"

    # Threshold check
    $highlightCpu = [double]($cpu -replace '%') -gt $cpuThreshold
    $highlightMemory = [double]($memoryPercent -replace '%') -gt $memoryThreshold

    $serverNameCssClass = if ($highlightCpu -or $highlightMemory) { 'class="highlight"' } else { '' }

    # Add row
    $htmlContent += @"
<tr>
    <td>$([DateTime]::Now)</td>
    <td $serverNameCssClass>$server</td>
    <td>Online</td>
    <td>$uptimeFormatted</td>
    <td>$cpu</td>
    <td>$($highCpuProcess.Name)</td>
    <td>$memoryPercent</td>
    <td>$($highMemProcess.Name)</td>
    <td>$highMemValue</td>
</tr>
"@
}
catch {
    Write-Host "Error: $_"
}

# Close HTML
$htmlContent += @"
</table>
</body>
</html>
"@

# Save file
$htmlFile = "C:\Temp\Local_Server_Status.html"
$htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8

Write-Host "Report generated at: $htmlFile"