# ================================================================
#  SERVICE MANAGER - ENHANCED DIAGNOSTIC EDITION
#  Actions: start | stop | restart | status | services | diagnostic | health
# ================================================================

# ================= CONFIG =================
$mode         = "local"        # local / remote
$serverList   = "AJITHSAI"
$serviceNames = "WinRM"
$action       = "status"   # start, stop, restart, status, services, diagnostic, health
$path_output  = "yes"

$outputArray  = @()

# Override for local
if ($mode -eq "local") {
    $serverList = @($env:COMPUTERNAME)
}

# ----------------------------------------------------------------
# Helper: Retrieve enriched service events from the System log
# Returns a structured list: time, eventId, state, stopReason, source
# ----------------------------------------------------------------
function Get-ServiceEvents {
    param([string]$ServiceName, [int]$MaxEvents = 1000)

    $relevantIDs = "7036,7034,7031,7024,7000,7001,7009,7040"
    $xPath = "*[System[EventID=7036 or EventID=7034 or EventID=7031 or EventID=7024 or EventID=7000 or EventID=7001 or EventID=7009 or EventID=7040]]"

    try {
        $rawEvents = Get-WinEvent -LogName System -FilterXPath $xPath -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
    } catch {
        return @()
    }

    $results = foreach ($ev in $rawEvents) {
        $msg = $ev.Message

        # Filter to events mentioning this service
        $isRelevant = switch ($ev.Id) {
            7036 { $ev.Properties[0].Value -eq $ServiceName }
            7034 { $msg -match [regex]::Escape($ServiceName) }
            7031 { $msg -match [regex]::Escape($ServiceName) }
            7024 { $msg -match [regex]::Escape($ServiceName) }
            7000 { $msg -match [regex]::Escape($ServiceName) }
            7001 { $msg -match [regex]::Escape($ServiceName) }
            7009 { $msg -match [regex]::Escape($ServiceName) }
            7040 { $msg -match [regex]::Escape($ServiceName) }
            default { $false }
        }

        if (-not $isRelevant) { continue }

        $stateChange = switch ($ev.Id) {
            7036 { $ev.Properties[1].Value }      # "running" / "stopped"
            7034 { "crashed (unexpected stop)"    }
            7031 { "stopped (recovery triggered)" }
            7024 { "stopped (exit error)"         }
            7000 { "failed to start"              }
            7001 { "failed (dependency error)"    }
            7009 { "timed out on start"           }
            7040 { "start type changed"           }
        }

        $exitCode = if ($ev.Id -in @(7024, 7034)) {
            if ($ev.Properties.Count -ge 2) { "Exit code: $($ev.Properties[1].Value)" } else { "N/A" }
        } else { $null }

        [PSCustomObject]@{
            Time        = $ev.TimeCreated
            EventID     = $ev.Id
            State       = $stateChange
            ExitCode    = $exitCode
            Message     = ($msg -split "`n")[0]   # first line only
            Source      = $ev.ProviderName
        }
    }

    return $results | Sort-Object Time -Descending
}

# ----------------------------------------------------------------
# Helper: Try to identify WHO stopped the service
# Checks Security log (requires audit policy) and SCM events
# ----------------------------------------------------------------
function Get-StopInitiator {
    param([string]$ServiceName, [datetime]$StopTime)

    $window = 120   # seconds around the stop event

    # EventID 4689 = Process terminated, 7040 = start-type change by user
    try {
        $secEvents = Get-WinEvent -LogName Security -MaxEvents 500 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Id -in @(4689, 4674) -and
                [Math]::Abs(($_.TimeCreated - $StopTime).TotalSeconds) -le $window
            }

        $match = $secEvents | Where-Object { $_.Message -match [regex]::Escape($ServiceName) } | Select-Object -First 1
        if ($match) {
            # Extract SubjectUserName from Security event
            $user = ($match.Message | Select-String -Pattern "Account Name:\s+(.+)").Matches[0].Groups[1].Value.Trim()
            return "User: $user (Security log EventID $($match.Id))"
        }
    } catch {}

    # Fallback: check SCM stop type via 7036 message context
    return "System/SCM (no user audit entry found — enable Security auditing for exact identity)"
}

# ----------------------------------------------------------------
# Helper: Get service recovery/failure actions
# ----------------------------------------------------------------
function Get-RecoveryActions {
    param([string]$ServiceName)
    try {
        $sc = & sc.exe qfailure $ServiceName 2>&1
        return ($sc -join " | ").Trim()
    } catch {
        return "Unable to read recovery config"
    }
}

# ----------------------------------------------------------------
# Helper: Get service dependencies
# ----------------------------------------------------------------
function Get-DependencyStatus {
    param([string]$ServiceName)
    try {
        $svc = Get-Service -Name $ServiceName -ErrorAction Stop
        $deps = $svc.ServicesDependedOn
        if ($deps.Count -eq 0) { return "None" }
        return ($deps | ForEach-Object { "$($_.Name) [$($_.Status)]" }) -join ", "
    } catch {
        return "Unable to read"
    }
}

# ================================================================
foreach ($server in $serverList) {

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " Server: $server  |  Mode: $mode  |  Action: $action" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    switch ($action) {

        # ==============================================================
        # SERVICES — List all services with path
        # ==============================================================
        "services" {

            if ($mode -eq "local") {

                $services = Get-Service
                $cimData  = Get-CimInstance Win32_Service

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
                        $cim = Get-CimInstance Win32_Service -Filter "Name='$($_.Name)'"
                        [PSCustomObject]@{
                            ServiceName = $_.Name
                            DisplayName = $_.DisplayName
                            Status      = $_.Status
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

        # ==============================================================
        # STATUS — Current state + event history + recovery info
        # Enhanced: shows last start/stop, recent errors, recovery config
        # ==============================================================
        "status" {

            foreach ($serviceName in $serviceNames) {

                Write-Host "`n[STATUS] Checking: $serviceName" -ForegroundColor Yellow

                if ($mode -eq "local") {

                    # --- Core service info ---
                    try {
                        $svc = Get-Service -Name $serviceName -ErrorAction Stop
                    } catch {
                        Write-Warning "Service not found: $serviceName"
                        continue
                    }

                    $cim      = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
                    $path     = if ($path_output -eq "yes") { $cim.PathName } else { $null }

                    # --- Event history ---
                    $events       = Get-ServiceEvents -ServiceName $serviceName -MaxEvents 1000
                    $lastStop     = $events | Where-Object { $_.State -like "*stop*" }  | Select-Object -First 1
                    $lastStart    = $events | Where-Object { $_.State -eq "running" }   | Select-Object -First 1
                    $lastCrash    = $events | Where-Object { $_.EventID -in @(7034,7031,7024) } | Select-Object -First 1
                    $lastError    = $events | Where-Object { $_.EventID -in @(7000,7001,7009) } | Select-Object -First 1

                    # --- Recovery config ---
                    $recovery = Get-RecoveryActions -ServiceName $serviceName

                    # --- WMI exit code (non-zero = error on last stop) ---
                    $exitCode = $cim.ExitCode

                    # --- Console output for quick visibility ---
                    $statusColor = if ($svc.Status -eq "Running") { "Green" } else { "Red" }
                    Write-Host "  Status     : $($svc.Status)"          -ForegroundColor $statusColor
                    Write-Host "  Start Type : $($cim.StartMode)"
                    Write-Host "  Last Start : $(if ($lastStart) { $lastStart.Time } else { 'N/A' })"
                    Write-Host "  Last Stop  : $(if ($lastStop)  { $lastStop.Time  } else { 'N/A' })"
                    if ($lastCrash) {
                        Write-Host "  !! CRASH   : $($lastCrash.Time) — $($lastCrash.State) | $($lastCrash.ExitCode)" -ForegroundColor Red
                    }
                    if ($lastError) {
                        Write-Host "  !! ERROR   : $($lastError.Time) — $($lastError.State)" -ForegroundColor Red
                    }
                    if ($exitCode -ne 0) {
                        Write-Host "  Exit Code  : $exitCode (non-zero — check stop reason)" -ForegroundColor Yellow
                    }
                    Write-Host "  Recovery   : $recovery"

                    # --- Collect for grid view ---
                    $outputArray += [PSCustomObject]@{
                        ServerName      = $server
                        ServiceName     = $svc.Name
                        DisplayName     = $svc.DisplayName
                        Status          = $svc.Status
                        StartType       = $cim.StartMode
                        RunAs           = $cim.StartName
                        LastStarted     = if ($lastStart) { $lastStart.Time }  else { "N/A" }
                        LastStopped     = if ($lastStop)  { $lastStop.Time }   else { "N/A" }
                        LastCrash       = if ($lastCrash) { "$($lastCrash.Time) | $($lastCrash.State) | $($lastCrash.ExitCode)" } else { "None" }
                        LastStartError  = if ($lastError) { "$($lastError.Time) | $($lastError.State)" } else { "None" }
                        ExitCode        = $exitCode
                        RecoveryActions = $recovery
                        Path            = $path
                    }

                } else {

                    # --- Remote mode ---
                    $data = Invoke-Command -ComputerName $server -ArgumentList ($serviceName, $path_output) {
                        param($serviceName, $path_output)

                        function Get-ServiceEventsRemote {
                            param([string]$ServiceName)
                            $xPath = "*[System[EventID=7036 or EventID=7034 or EventID=7031 or EventID=7024 or EventID=7000 or EventID=7001 or EventID=7009]]"
                            try { $rawEvents = Get-WinEvent -LogName System -FilterXPath $xPath -MaxEvents 1000 -ErrorAction SilentlyContinue }
                            catch { return @() }

                            $rawEvents | Where-Object {
                                ($_.Id -eq 7036 -and $_.Properties[0].Value -eq $ServiceName) -or
                                ($_.Id -ne 7036 -and $_.Message -match [regex]::Escape($ServiceName))
                            } | ForEach-Object {
                                $state = switch ($_.Id) {
                                    7036 { $_.Properties[1].Value }
                                    7034 { "crashed" }; 7031 { "stopped (recovery)" }
                                    7024 { "stopped (exit error)" }; 7000 { "failed to start" }
                                    7001 { "dependency error" }; 7009 { "timed out" }
                                }
                                [PSCustomObject]@{ Time=$_.TimeCreated; EventID=$_.Id; State=$state; ExitCode=if($_.Id -in @(7024,7034)){$_.Properties[1].Value}else{$null} }
                            } | Sort-Object Time -Descending
                        }

                        try { $svc = Get-Service -Name $serviceName -ErrorAction Stop } catch { return $null }
                        $cim      = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
                        $events   = Get-ServiceEventsRemote -ServiceName $serviceName
                        $lastStop  = $events | Where-Object { $_.State -like "*stop*" -or $_.State -like "*crash*" } | Select-Object -First 1
                        $lastStart = $events | Where-Object { $_.State -eq "running" } | Select-Object -First 1
                        $lastCrash = $events | Where-Object { $_.EventID -in @(7034,7031,7024) } | Select-Object -First 1
                        $lastError = $events | Where-Object { $_.EventID -in @(7000,7001,7009) } | Select-Object -First 1
                        $recovery  = (& sc.exe qfailure $serviceName 2>&1) -join " | "

                        [PSCustomObject]@{
                            ServiceName     = $svc.Name
                            DisplayName     = $svc.DisplayName
                            Status          = $svc.Status
                            StartType       = $cim.StartMode
                            RunAs           = $cim.StartName
                            LastStarted     = if ($lastStart) { $lastStart.Time } else { "N/A" }
                            LastStopped     = if ($lastStop)  { $lastStop.Time  } else { "N/A" }
                            LastCrash       = if ($lastCrash) { "$($lastCrash.Time) | $($lastCrash.State) | $($lastCrash.ExitCode)" } else { "None" }
                            LastStartError  = if ($lastError) { "$($lastError.Time) | $($lastError.State)" } else { "None" }
                            ExitCode        = $cim.ExitCode
                            RecoveryActions = $recovery
                            Path            = if ($path_output -eq "yes") { $cim.PathName } else { $null }
                        }
                    }

                    if ($data) {
                        $outputArray += [PSCustomObject]@{ ServerName = $server } + $data
                    }
                }
            }
        }

        # ==============================================================
        # DIAGNOSTIC — Deep forensic view
        # Shows: who stopped it, why, crash codes, dependency failures,
        #        recovery config, exe validation, full event timeline
        # ==============================================================
        "diagnostic" {

            foreach ($serviceName in $serviceNames) {

                Write-Host "`n[DIAGNOSTIC] ====== $serviceName ======" -ForegroundColor Magenta

                if ($mode -eq "local") {

                    # --- Basic service objects ---
                    try {
                        $svc = Get-Service -Name $serviceName -ErrorAction Stop
                    } catch {
                        Write-Warning "Service not found: $serviceName"
                        continue
                    }

                    $cim = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"

                    # --- Executable path validation ---
                    $rawPath  = $cim.PathName
                    $exePath  = (($rawPath -replace '"','') -split '\.exe')[0] + ".exe"
                    $exeExists = Test-Path $exePath

                    # --- Full event timeline ---
                    $events = Get-ServiceEvents -ServiceName $serviceName -MaxEvents 2000

                    $lastStop    = $events | Where-Object { $_.State -like "*stop*" -or $_.State -like "*crash*" } | Select-Object -First 1
                    $lastStart   = $events | Where-Object { $_.State -eq "running" }  | Select-Object -First 1
                    $crashEvents = $events | Where-Object { $_.EventID -in @(7034,7031) }
                    $errorEvents = $events | Where-Object { $_.EventID -in @(7024,7000,7001,7009) }

                    # --- Who/how stopped ---
                    $stopInitiator = "N/A"
                    $stopMethod    = "N/A"
                    $stopReason    = "N/A"

                    if ($lastStop) {
                        $stopInitiator = Get-StopInitiator -ServiceName $serviceName -StopTime $lastStop.Time

                        $stopMethod = switch ($lastStop.EventID) {
                            7036 { "Clean stop (SCM or user request)" }
                            7034 { "Unexpected termination / crash"    }
                            7031 { "Terminated — recovery action triggered" }
                            7024 { "Service exited with error code"    }
                            default { "Unknown" }
                        }

                        $stopReason = if ($lastStop.ExitCode) {
                            "Exit Code: $($lastStop.ExitCode)"
                        } elseif ($cim.ExitCode -ne 0) {
                            "WMI Exit Code: $($cim.ExitCode)"
                        } else {
                            "Exit code 0 (clean) — may be intentional stop"
                        }
                    }

                    # --- Dependency chain ---
                    $depStatus = Get-DependencyStatus -ServiceName $serviceName

                    # --- Recovery config ---
                    $recovery = Get-RecoveryActions -ServiceName $serviceName

                    # --- Console drill-down output ---
                    Write-Host "`n  --- CURRENT STATE ---" -ForegroundColor Cyan
                    $c = if ($svc.Status -eq "Running") { "Green" } else { "Red" }
                    Write-Host "  Status     : $($svc.Status)"    -ForegroundColor $c
                    Write-Host "  Start Type : $($cim.StartMode)"
                    Write-Host "  Run As     : $($cim.StartName)"
                    Write-Host "  WMI Exit   : $($cim.ExitCode)"
                    Write-Host "  Exe Exists : $exeExists  [$exePath]" -ForegroundColor $(if ($exeExists) { "Green" } else { "Red" })

                    Write-Host "`n  --- LAST START / STOP ---" -ForegroundColor Cyan
                    Write-Host "  Last Start : $(if ($lastStart) { $lastStart.Time } else { 'N/A (no event found)' })"
                    Write-Host "  Last Stop  : $(if ($lastStop)  { $lastStop.Time  } else { 'N/A (no event found)' })"
                    Write-Host "  Stop Method: $stopMethod"
                    Write-Host "  Stop Reason: $stopReason"
                    Write-Host "  Initiator  : $stopInitiator"

                    Write-Host "`n  --- CRASH / ERROR EVENTS (last 5) ---" -ForegroundColor Cyan
                    if ($crashEvents.Count -gt 0) {
                        $crashEvents | Select-Object -First 5 | ForEach-Object {
                            Write-Host "  [CRASH $($_.EventID)] $($_.Time) — $($_.State) | $($_.ExitCode)" -ForegroundColor Red
                        }
                    } else {
                        Write-Host "  No crash events found." -ForegroundColor Green
                    }

                    if ($errorEvents.Count -gt 0) {
                        $errorEvents | Select-Object -First 5 | ForEach-Object {
                            Write-Host "  [ERROR $($_.EventID)] $($_.Time) — $($_.State)" -ForegroundColor Yellow
                        }
                    } else {
                        Write-Host "  No start/timeout errors found." -ForegroundColor Green
                    }

                    Write-Host "`n  --- DEPENDENCIES ---" -ForegroundColor Cyan
                    Write-Host "  $depStatus"

                    Write-Host "`n  --- RECOVERY CONFIG ---" -ForegroundColor Cyan
                    Write-Host "  $recovery"

                    Write-Host "`n  --- RECENT EVENT TIMELINE (last 10) ---" -ForegroundColor Cyan
                    $events | Select-Object -First 10 | ForEach-Object {
                        $color = switch -Wildcard ($_.State) {
                            "*crash*"  { "Red"    }
                            "*error*"  { "Red"    }
                            "*failed*" { "Red"    }
                            "*timed*"  { "Yellow" }
                            "running"  { "Green"  }
                            default    { "White"  }
                        }
                        Write-Host "  [$($_.EventID)] $($_.Time)  $($_.State)  $(if($_.ExitCode){"| $($_.ExitCode)"})" -ForegroundColor $color
                    }

                    # --- Structured output ---
                    $outputArray += [PSCustomObject]@{
                        ServerName      = $server
                        ServiceName     = $svc.Name
                        DisplayName     = $svc.DisplayName
                        Status          = $svc.Status
                        StartType       = $cim.StartMode
                        RunAs           = $cim.StartName
                        WMIExitCode     = $cim.ExitCode
                        ExeExists       = $exeExists
                        ExecutablePath  = $exePath
                        LastStarted     = if ($lastStart) { $lastStart.Time } else { "N/A" }
                        LastStopped     = if ($lastStop)  { $lastStop.Time  } else { "N/A" }
                        StopMethod      = $stopMethod
                        StopReason      = $stopReason
                        StopInitiator   = $stopInitiator
                        CrashCount      = $crashEvents.Count
                        ErrorCount      = $errorEvents.Count
                        Dependencies    = $depStatus
                        RecoveryActions = $recovery
                        FullPath        = $rawPath
                    }

                } else {

                    # --- Remote diagnostic ---
                    $data = Invoke-Command -ComputerName $server -ArgumentList $serviceName {
                        param($serviceName)

                        try { $svc = Get-Service -Name $serviceName -ErrorAction Stop } catch { return $null }
                        $cim     = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
                        $rawPath = $cim.PathName
                        $exePath = (($rawPath -replace '"','') -split '\.exe')[0] + ".exe"

                        $xPath = "*[System[EventID=7036 or EventID=7034 or EventID=7031 or EventID=7024 or EventID=7000 or EventID=7001 or EventID=7009]]"
                        $rawEvs = try { Get-WinEvent -LogName System -FilterXPath $xPath -MaxEvents 2000 -ErrorAction SilentlyContinue } catch { @() }

                        $events = $rawEvs | Where-Object {
                            ($_.Id -eq 7036 -and $_.Properties[0].Value -eq $serviceName) -or
                            ($_.Id -ne 7036 -and $_.Message -match [regex]::Escape($serviceName))
                        } | ForEach-Object {
                            $state = switch ($_.Id) {
                                7036 { $_.Properties[1].Value }
                                7034 { "crashed" }; 7031 { "stopped (recovery)" }
                                7024 { "stopped (exit error)" }; 7000 { "failed to start" }
                                7001 { "dependency error" }; 7009 { "timed out" }
                            }
                            [PSCustomObject]@{ Time=$_.TimeCreated; EventID=$_.Id; State=$state; ExitCode=if($_.Id -in @(7024,7034)){$_.Properties[1].Value}else{$null} }
                        } | Sort-Object Time -Descending

                        $deps     = (Get-Service -Name $serviceName).ServicesDependedOn
                        $depStr   = if ($deps.Count -eq 0) { "None" } else { ($deps | ForEach-Object {"$($_.Name)[$($_.Status)]"}) -join ", " }
                        $recovery = (& sc.exe qfailure $serviceName 2>&1) -join " | "

                        $lastStop  = $events | Where-Object { $_.State -like "*stop*" -or $_.State -like "*crash*" } | Select-Object -First 1
                        $lastStart = $events | Where-Object { $_.State -eq "running" } | Select-Object -First 1
                        $crashes   = @($events | Where-Object { $_.EventID -in @(7034,7031) })
                        $errors    = @($events | Where-Object { $_.EventID -in @(7024,7000,7001,7009) })

                        [PSCustomObject]@{
                            ServiceName    = $svc.Name
                            DisplayName    = $svc.DisplayName
                            Status         = $svc.Status
                            StartType      = $cim.StartMode
                            RunAs          = $cim.StartName
                            WMIExitCode    = $cim.ExitCode
                            ExeExists      = Test-Path $exePath
                            ExecutablePath = $exePath
                            LastStarted    = if ($lastStart) { $lastStart.Time } else { "N/A" }
                            LastStopped    = if ($lastStop)  { $lastStop.Time  } else { "N/A" }
                            StopState      = if ($lastStop)  { $lastStop.State } else { "N/A" }
                            StopExitCode   = if ($lastStop)  { $lastStop.ExitCode } else { $null }
                            CrashCount     = $crashes.Count
                            ErrorCount     = $errors.Count
                            Dependencies   = $depStr
                            RecoveryActions= $recovery
                            FullPath       = $rawPath
                            RecentEvents   = ($events | Select-Object -First 10 | ForEach-Object { "[$($_.EventID)] $($_.Time) $($_.State)" }) -join " || "
                        }
                    }

                    if ($data) {
                        $outputArray += [PSCustomObject]@{ ServerName = $server } + $data
                    }
                }
            }
        }

        # ==============================================================
        # HEALTH — Quick one-stop health summary for NOC / monitoring
        # ==============================================================
        "health" {

            foreach ($serviceName in $serviceNames) {

                Write-Host "`n[HEALTH CHECK] $serviceName" -ForegroundColor Cyan

                try {
                    $svc = Get-Service -Name $serviceName -ErrorAction Stop
                } catch {
                    Write-Warning "Service not found: $serviceName"
                    continue
                }

                $cim    = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
                $events = Get-ServiceEvents -ServiceName $serviceName -MaxEvents 500

                # Uptime estimate: time since last "running" event
                $lastRunning = $events | Where-Object { $_.State -eq "running" } | Select-Object -First 1
                $uptime = if ($svc.Status -eq "Running" -and $lastRunning) {
                    $span = (Get-Date) - $lastRunning.Time
                    "{0}d {1}h {2}m" -f [int]$span.TotalDays, $span.Hours, $span.Minutes
                } else { "Not running" }

                $crashCount = @($events | Where-Object { $_.EventID -in @(7034,7031) }).Count
                $errorCount = @($events | Where-Object { $_.EventID -in @(7024,7000,7001,7009) }).Count
                $depStatus  = Get-DependencyStatus -ServiceName $serviceName

                $healthStatus = if ($svc.Status -ne "Running") {
                    "DEGRADED"
                } elseif ($crashCount -gt 0 -or $errorCount -gt 0) {
                    "WARNING"
                } else {
                    "HEALTHY"
                }

                $color = switch ($healthStatus) {
                    "HEALTHY"  { "Green"  }
                    "WARNING"  { "Yellow" }
                    "DEGRADED" { "Red"    }
                }

                Write-Host "  Health     : $healthStatus" -ForegroundColor $color
                Write-Host "  Status     : $($svc.Status)"
                Write-Host "  Start Type : $($cim.StartMode)"
                Write-Host "  Uptime     : $uptime"
                Write-Host "  Crashes    : $crashCount (in last 500 events)"
                Write-Host "  Errors     : $errorCount (in last 500 events)"
                Write-Host "  Run As     : $($cim.StartName)"
                Write-Host "  Depends On : $depStatus"

                $outputArray += [PSCustomObject]@{
                    ServerName   = $server
                    ServiceName  = $svc.Name
                    DisplayName  = $svc.DisplayName
                    HealthStatus = $healthStatus
                    Status       = $svc.Status
                    StartType    = $cim.StartMode
                    Uptime       = $uptime
                    CrashCount   = $crashCount
                    ErrorCount   = $errorCount
                    RunAs        = $cim.StartName
                    Dependencies = $depStatus
                }
            }
        }

        # ==============================================================
        # START / STOP / RESTART — with before/after status + error capture
        # ==============================================================
        default {

            foreach ($serviceName in $serviceNames) {

                Write-Host "`n[$($action.ToUpper())] $serviceName" -ForegroundColor Yellow

                try {

                    $before = if ($mode -eq "local") {
                        Get-Service $serviceName -ErrorAction Stop
                    } else {
                        Invoke-Command -ComputerName $server { Get-Service -Name $using:serviceName }
                    }

                    Write-Host "  Before : $($before.Status)"

                    if ($mode -eq "local") {

                        switch ($action) {
                            "start"   { Start-Service   $serviceName -ErrorAction Stop }
                            "stop"    { Stop-Service    $serviceName -ErrorAction Stop }
                            "restart" { Restart-Service $serviceName -ErrorAction Stop }
                        }

                        Start-Sleep -Seconds 2   # brief settle time
                        $after = Get-Service $serviceName

                    } else {

                        Invoke-Command -ComputerName $server -ArgumentList $serviceName, $action {
                            param($svcName, $act)
                            switch ($act) {
                                "start"   { Start-Service   $svcName -ErrorAction Stop }
                                "stop"    { Stop-Service    $svcName -ErrorAction Stop }
                                "restart" { Restart-Service $svcName -ErrorAction Stop }
                            }
                        }

                        $after = Invoke-Command -ComputerName $server { Get-Service -Name $using:serviceName }
                    }

                    $resultColor = if ($after.Status -eq "Running") { "Green" } else { "Yellow" }
                    Write-Host "  After  : $($after.Status)" -ForegroundColor $resultColor

                    # Post-action: show any new event
                    $recentEv = Get-ServiceEvents -ServiceName $serviceName -MaxEvents 20 |
                        Select-Object -First 1
                    if ($recentEv) {
                        Write-Host "  Latest Event [$($recentEv.EventID)]: $($recentEv.Time) — $($recentEv.State)" -ForegroundColor Cyan
                    }

                    $outputArray += [PSCustomObject]@{
                        ServerName  = $server
                        ServiceName = $serviceName
                        Action      = $action
                        Before      = $before.Status
                        After       = $after.Status
                        Result      = "SUCCESS"
                        LatestEvent = if ($recentEv) { "$($recentEv.Time) | $($recentEv.State)" } else { "N/A" }
                        Error       = $null
                    }

                } catch {

                    Write-Host "  FAILED: $serviceName" -ForegroundColor Red
                    Write-Host "  $($_.Exception.Message)" -ForegroundColor Yellow

                    # Grab the most recent error event to explain WHY
                    $failEv = Get-ServiceEvents -ServiceName $serviceName -MaxEvents 50 |
                        Where-Object { $_.EventID -in @(7000,7001,7009,7024,7034) } |
                        Select-Object -First 1

                    if ($failEv) {
                        Write-Host "  Related Event [$($failEv.EventID)]: $($failEv.Time) — $($failEv.State)" -ForegroundColor Red
                    }

                    $outputArray += [PSCustomObject]@{
                        ServerName   = $server
                        ServiceName  = $serviceName
                        Action       = $action
                        Before       = "Unknown"
                        After        = "Failed"
                        Result       = "FAILED"
                        LatestEvent  = if ($failEv) { "[$($failEv.EventID)] $($failEv.Time) | $($failEv.State)" } else { "No event found" }
                        Error        = $_.Exception.Message
                    }
                }
            }
        }
    }

    Write-Host "`n--------------------------------------------------" -ForegroundColor DarkGray
}

# ================================================================
# OUTPUT — Grid view
# ================================================================
if ($outputArray.Count -gt 0) {
    $outputArray | Out-GridView -Title "Service Manager Results — $action on $server"
} else {
    Write-Host "`nNo output collected." -ForegroundColor Yellow
}