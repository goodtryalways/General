# ================= CONFIG =================
$mode = "local"   # local / remote
$serverList = "server1"
$serviceNames = "WinRM"
$action = "services"   # start, stop, restart, status, services, diagnostic
$path_output = "yes"

$outputArray = @()

# Override for local
if ($mode -eq "local") {
    $serverList = @($env:COMPUTERNAME)
}

foreach ($server in $serverList) {

    Write-Host "Server: $server | Mode: $mode | Action: $action"

    switch ($action) {

        # ================= SERVICES =================
        "services" {

            if ($mode -eq "local") {

                $services = Get-Service
                $cimData = Get-CimInstance Win32_Service

                foreach ($svc in $services) {

                    $path = if ($path_output -eq "yes") {
                        ($cimData | Where-Object Name -eq $svc.Name).PathName
                    }

                    $outputArray += [PSCustomObject]@{
                        ServerName  = $server
                        ServiceName = $svc.Name
                        DisplayName = $svc.DisplayName
                        Status      = $svc.Status
                        Path        = $path
                    }
                }

            } else {

                $data = Invoke-Command -ComputerName $server {

                    Get-Service | ForEach-Object {
                        $svc = $_
                        $cim = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'"

                        [PSCustomObject]@{
                            ServiceName = $svc.Name
                            DisplayName = $svc.DisplayName
                            Status      = $svc.Status
                            Path        = $cim.PathName
                        }
                    }

                }

                foreach ($d in $data) {
                    $outputArray += [PSCustomObject]@{
                        ServerName  = $server
                        ServiceName = $d.ServiceName
                        DisplayName = $d.DisplayName
                        Status      = $d.Status
                        Path        = $d.Path
                    }
                }
            }
        }

        # ================= STATUS (FIXED) =================
        "status" {

            if ($mode -eq "local") {

                foreach ($serviceName in $serviceNames) {

                    try {
                        $svc = Get-Service -Name $serviceName -ErrorAction Stop
                    } catch {
                        Write-Warning "Service not found: $serviceName"
                        continue
                    }

                    $cim = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
                    $path = if ($path_output -eq "yes") { $cim.PathName } else { $null }

                    # 🔥 Accurate Event Query (EventID 7036)
                    $events = Get-WinEvent -LogName System -FilterXPath "*[System/EventID=7036]" -MaxEvents 500

                    $serviceEvents = $events | Where-Object {
                        $_.Properties[0].Value -eq $serviceName
                    }

                    $lastStop = $serviceEvents | Where-Object {
                        $_.Properties[1].Value -eq "stopped"
                    } | Select-Object -First 1

                    $lastStart = $serviceEvents | Where-Object {
                        $_.Properties[1].Value -eq "running"
                    } | Select-Object -First 1

                    $outputArray += [PSCustomObject]@{
                        ServerName   = $server
                        ServiceName  = $svc.Name
                        DisplayName  = $svc.DisplayName
                        Status       = $svc.Status
                        StartType    = $cim.StartMode
                        LastStopped  = if ($lastStop) { $lastStop.TimeCreated } else { "N/A" }
                        LastStarted  = if ($lastStart) { $lastStart.TimeCreated } else { "N/A" }
                        Path         = $path
                    }
                }

            } else {

                $data = Invoke-Command -ComputerName $server {

                    param($serviceNames, $path_output)

                    foreach ($serviceName in $serviceNames) {

                        try {
                            $svc = Get-Service -Name $serviceName -ErrorAction Stop
                        } catch {
                            continue
                        }

                        $cim = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"

                        $events = Get-WinEvent -LogName System -FilterXPath "*[System/EventID=7036]" -MaxEvents 500

                        $serviceEvents = $events | Where-Object {
                            $_.Properties[0].Value -eq $serviceName
                        }

                        $lastStop = $serviceEvents | Where-Object {
                            $_.Properties[1].Value -eq "stopped"
                        } | Select-Object -First 1

                        $lastStart = $serviceEvents | Where-Object {
                            $_.Properties[1].Value -eq "running"
                        } | Select-Object -First 1

                        [PSCustomObject]@{
                            ServiceName  = $svc.Name
                            DisplayName  = $svc.DisplayName
                            Status       = $svc.Status
                            StartType    = $cim.StartMode
                            LastStopped  = if ($lastStop) { $lastStop.TimeCreated } else { "N/A" }
                            LastStarted  = if ($lastStart) { $lastStart.TimeCreated } else { "N/A" }
                            Path         = if ($path_output -eq "yes") { $cim.PathName } else { $null }
                        }
                    }

                } -ArgumentList ($serviceNames, $path_output)

                foreach ($d in $data) {
                    $outputArray += [PSCustomObject]@{
                        ServerName  = $server
                        ServiceName = $d.ServiceName
                        DisplayName = $d.DisplayName
                        Status      = $d.Status
                        StartType   = $d.StartType
                        LastStopped = $d.LastStopped
                        LastStarted = $d.LastStarted
                        Path        = $d.Path
                    }
                }
            }
        }

        # ================= DIAGNOSTIC =================
        "diagnostic" {

            foreach ($serviceName in $serviceNames) {

                try {
                    $svc = if ($mode -eq "local") {
                        Get-Service $serviceName -ErrorAction Stop
                    } else {
                        Invoke-Command -ComputerName $server { Get-Service -Name $using:serviceName }
                    }
                } catch {
                    Write-Warning "Service not found: $serviceName"
                    continue
                }

                $cim = if ($mode -eq "local") {
                    Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
                } else {
                    Invoke-Command -ComputerName $server {
                        Get-CimInstance Win32_Service -Filter "Name='$using:serviceName'"
                    }
                }

                $exe = ($cim.PathName -replace '"','') -split '\.exe' | Select -First 1
                $exe = "$exe.exe"

                $exists = if ($mode -eq "local") { Test-Path $exe } else { "RemoteCheck" }

                $outputArray += [PSCustomObject]@{
                    ServerName  = $server
                    ServiceName = $svc.Name
                    Status      = $svc.Status
                    StartType   = $cim.StartMode
                    RunAs       = $cim.StartName
                    Path        = $cim.PathName
                    ExeExists   = $exists
                }
            }
        }

        # ================= START / STOP / RESTART =================
        default {

            foreach ($serviceName in $serviceNames) {

                try {

                    $before = if ($mode -eq "local") {
                        Get-Service $serviceName -ErrorAction Stop
                    } else {
                        Invoke-Command -ComputerName $server { Get-Service -Name $using:serviceName }
                    }

                    Write-Host "Before: $($before.Status)"

                    if ($mode -eq "local") {

                        switch ($action) {
                            "start"   { Start-Service $serviceName -ErrorAction Stop }
                            "stop"    { Stop-Service $serviceName -ErrorAction Stop }
                            "restart" { Restart-Service $serviceName -ErrorAction Stop }
                        }

                        $after = Get-Service $serviceName

                    } else {

                        Invoke-Command -ComputerName $server {
                            param($serviceName, $action)

                            switch ($action) {
                                "start"   { Start-Service $serviceName -ErrorAction Stop }
                                "stop"    { Stop-Service $serviceName -ErrorAction Stop }
                                "restart" { Restart-Service $serviceName -ErrorAction Stop }
                            }

                        } -ArgumentList $serviceName, $action

                        $after = Invoke-Command -ComputerName $server {
                            Get-Service -Name $using:serviceName
                        }
                    }

                    Write-Host "After : $($after.Status)"

                } catch {

                    Write-Host "❌ FAILED: $serviceName" -ForegroundColor Red
                    Write-Host $_.Exception.Message -ForegroundColor Yellow

                    $outputArray += [PSCustomObject]@{
                        ServerName  = $server
                        ServiceName = $serviceName
                        Action      = $action
                        Result      = "FAILED"
                        Error       = $_.Exception.Message
                    }
                }
            }
        }
    }

    Write-Host "--------------------------------------------------"
}

# ================= OUTPUT =================
$outputArray | Out-GridView