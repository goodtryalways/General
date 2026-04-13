# ================================================================
#  SERVICE MANAGER - ENHANCED DIAGNOSTIC EDITION
#  Actions: start | stop | restart | status | services | diagnostic | health
# ================================================================

# ================= CONFIG =================
$mode         = "local"        # local / remote
$serverList   = "Server1"
$serviceNames = "WinRM"
$action       = "diagnostic"   # start, stop, restart, status, services, diagnostic, health
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
# OUTPUT — Word-wrapped HTML report (opens in default browser)
# ================================================================
if ($outputArray.Count -eq 0) {
    Write-Host "`nNo output collected." -ForegroundColor Yellow
    return
}

# ---- Build column headers from the first object ----
$columns = $outputArray[0].PSObject.Properties.Name

# ---- Status/keyword colour mapping ----
function Get-CellClass {
    param([string]$ColName, [string]$Value)
    $v = $Value.ToLower()
    $c = $ColName.ToLower()

    # Explicit status columns
    if ($c -in @("status","healthstatus","result","after","before")) {
        if ($v -match "running|healthy|success")  { return "ok"   }
        if ($v -match "stopped|degraded|failed")  { return "bad"  }
        if ($v -match "warning|paused|pending")   { return "warn" }
    }
    # Crash / error counts
    if ($c -in @("crashcount","errorcount") -and $Value -match '^\d+$' -and [int]$Value -gt 0) {
        return "bad"
    }
    # Exit code
    if ($c -eq "wmiexit code" -or $c -eq "exitcode") {
        if ($Value -ne "0" -and $Value -ne "" -and $Value -ne "N/A") { return "warn" }
    }
    # Exe exists
    if ($c -eq "exeexists") {
        if ($v -eq "false") { return "bad" }
        if ($v -eq "true")  { return "ok"  }
    }
    # Any cell containing error/crash keywords
    if ($v -match "crash|failed|error|timed out|unexpected") { return "bad"  }
    if ($v -match "warning|recovery|stopped")               { return "warn" }
    return ""
}

# ---- Build HTML rows ----
$rowsHtml = foreach ($obj in $outputArray) {
    $cells = foreach ($col in $columns) {
        $raw   = if ($null -ne $obj.$col) { "$($obj.$col)" } else { "" }
        $cls   = Get-CellClass -ColName $col -Value $raw
        $safe  = [System.Web.HttpUtility]::HtmlEncode($raw)
        # Insert <wbr> hints after common delimiters so long paths wrap cleanly
        $safe  = $safe -replace '(\\|/|,|\|{2})', '$1<wbr>'
        "<td class=`"$cls`">$safe</td>"
    }
    "<tr>$($cells -join '')</tr>"
}

$headerHtml = ($columns | ForEach-Object { "<th>$_</th>" }) -join ''

$timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$title      = "Service Manager — $($action.ToUpper()) — $server — $timestamp"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$title</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: Consolas, 'Cascadia Code', 'Courier New', monospace;
    font-size: 13px;
    background: #0d1117;
    color: #c9d1d9;
    padding: 24px;
  }

  h1 {
    font-size: 15px;
    font-weight: 600;
    color: #58a6ff;
    margin-bottom: 6px;
    letter-spacing: .02em;
  }

  .meta {
    font-size: 11px;
    color: #8b949e;
    margin-bottom: 14px;
  }

  /* ---- toolbar ---- */
  .toolbar {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 16px;
    flex-wrap: wrap;
  }

  #search {
    width: 300px;
    padding: 6px 10px;
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-size: 13px;
    outline: none;
  }
  #search:focus { border-color: #58a6ff; }

  /* Screenshot button */
  #btn-snip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 14px;
    background: #21262d;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-size: 12px;
    font-family: inherit;
    cursor: pointer;
    user-select: none;
    transition: background .15s, border-color .15s;
  }
  #btn-snip:hover  { background: #2d333b; border-color: #58a6ff; color: #58a6ff; }
  #btn-snip.active { background: #1f3a5f; border-color: #58a6ff; color: #58a6ff; }
  #btn-snip svg    { width: 14px; height: 14px; flex-shrink: 0; }

  /* ---- snip overlay ---- */
  #snip-overlay {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 9999;
    cursor: crosshair;
  }
  #snip-overlay.active { display: block; }

  /* dim layer behind the selection */
  #snip-dim {
    position: absolute;
    inset: 0;
    background: rgba(0,0,0,.45);
  }

  /* bright selection rectangle */
  #snip-rect {
    position: absolute;
    border: 2px solid #58a6ff;
    background: transparent;
    box-shadow: 0 0 0 9999px rgba(0,0,0,.45);
    display: none;
  }

  /* size label that follows the rectangle */
  #snip-label {
    position: absolute;
    background: #58a6ff;
    color: #0d1117;
    font-size: 10px;
    font-family: Consolas, monospace;
    padding: 2px 5px;
    border-radius: 3px;
    pointer-events: none;
    display: none;
    white-space: nowrap;
  }

  /* instruction banner at top of overlay */
  #snip-hint {
    position: absolute;
    top: 12px;
    left: 50%;
    transform: translateX(-50%);
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 6px 16px;
    font-size: 12px;
    color: #8b949e;
    white-space: nowrap;
    pointer-events: none;
  }

  /* toast notification */
  #snip-toast {
    position: fixed;
    bottom: 28px;
    left: 50%;
    transform: translateX(-50%) translateY(20px);
    background: #238636;
    color: #fff;
    font-size: 12px;
    padding: 8px 20px;
    border-radius: 6px;
    opacity: 0;
    transition: opacity .3s, transform .3s;
    pointer-events: none;
    z-index: 99999;
    white-space: nowrap;
  }
  #snip-toast.show {
    opacity: 1;
    transform: translateX(-50%) translateY(0);
  }
  #snip-toast.error { background: #da3633; }

  /* Table wrapper */
  .tbl-wrap {
    overflow-x: auto;
    border-radius: 8px;
    border: 1px solid #21262d;
  }

  table {
    width: 100%;
    border-collapse: collapse;
    table-layout: auto;
  }

  thead tr {
    background: #161b22;
    position: sticky;
    top: 0;
    z-index: 2;
  }

  th {
    padding: 9px 12px;
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .06em;
    color: #8b949e;
    border-bottom: 1px solid #21262d;
    white-space: nowrap;
    cursor: pointer;
    user-select: none;
  }
  th:hover { color: #58a6ff; }
  th.asc::after  { content: " ↑"; color: #58a6ff; }
  th.desc::after { content: " ↓"; color: #58a6ff; }

  td {
    padding: 8px 12px;
    border-bottom: 1px solid #21262d;
    vertical-align: top;
    white-space: pre-wrap;
    word-break: break-word;
    overflow-wrap: anywhere;
    max-width: 420px;
    line-height: 1.55;
  }

  tbody tr:nth-child(even) { background: #0d1117; }
  tbody tr:nth-child(odd)  { background: #111820; }
  tbody tr:hover           { background: #1c2128; }

  td.ok   { color: #3fb950; }
  td.bad  { color: #f85149; font-weight: 600; }
  td.warn { color: #d29922; }

  tr.hidden { display: none; }

  .row-count {
    font-size: 11px;
    color: #8b949e;
    margin-top: 10px;
  }
</style>
</head>
<body>
<h1>$title</h1>
<div class="meta">Action: <b>$action</b> &nbsp;|&nbsp; Server: <b>$server</b> &nbsp;|&nbsp; Rows: <b>$($outputArray.Count)</b></div>

<div class="toolbar">
  <input id="search" type="search" placeholder="Filter rows…" oninput="filterRows(this.value)">

  <button id="btn-snip" title="Click then drag to select any area — copies to clipboard">
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <rect x="1" y="1" width="6" height="6" rx="1"/>
      <rect x="9" y="1" width="6" height="6" rx="1"/>
      <rect x="1" y="9" width="6" height="6" rx="1"/>
      <path d="M9 12h6M12 9v6"/>
    </svg>
    Screenshot
  </button>
</div>

<div class="tbl-wrap">
<table id="tbl">
  <thead><tr>$headerHtml</tr></thead>
  <tbody>
$($rowsHtml -join "`n")
  </tbody>
</table>
</div>
<div class="row-count" id="rowcount">Showing $($outputArray.Count) of $($outputArray.Count) rows</div>

<!-- Snip overlay -->
<div id="snip-overlay">
  <div id="snip-dim"></div>
  <div id="snip-rect"></div>
  <div id="snip-label"></div>
  <div id="snip-hint">Drag to select area &nbsp;·&nbsp; ESC to cancel</div>
</div>

<!-- Toast -->
<div id="snip-toast"></div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
<script>
// ================================================================
//  LIVE FILTER
// ================================================================
function filterRows(q) {
  const term = q.toLowerCase();
  const rows = document.querySelectorAll('#tbl tbody tr');
  let visible = 0;
  rows.forEach(r => {
    const match = r.textContent.toLowerCase().includes(term);
    r.classList.toggle('hidden', !match);
    if (match) visible++;
  });
  document.getElementById('rowcount').textContent =
    'Showing ' + visible + ' of ' + rows.length + ' rows';
}

// ================================================================
//  COLUMN SORT
// ================================================================
(function(){
  const headers = document.querySelectorAll('#tbl thead th');
  headers.forEach((th, colIdx) => {
    let asc = true;
    th.addEventListener('click', () => {
      headers.forEach(h => h.classList.remove('asc','desc'));
      th.classList.add(asc ? 'asc' : 'desc');
      const tbody = document.querySelector('#tbl tbody');
      const rows  = Array.from(tbody.querySelectorAll('tr'));
      rows.sort((a, b) => {
        const av = a.cells[colIdx]?.textContent.trim() ?? '';
        const bv = b.cells[colIdx]?.textContent.trim() ?? '';
        const an = parseFloat(av), bn = parseFloat(bv);
        if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
        return asc ? av.localeCompare(bv) : bv.localeCompare(av);
      });
      rows.forEach(r => tbody.appendChild(r));
      asc = !asc;
    });
  });
})();

// ================================================================
//  LIGHTSHOT-STYLE SNIP TOOL
// ================================================================
(function () {
  const btnSnip  = document.getElementById('btn-snip');
  const overlay  = document.getElementById('snip-overlay');
  const rectEl   = document.getElementById('snip-rect');
  const labelEl  = document.getElementById('snip-label');
  const toast    = document.getElementById('snip-toast');

  let dragging = false, sx = 0, sy = 0;

  // ---- show toast ----
  function showToast(msg, isError) {
    toast.textContent  = msg;
    toast.className    = 'show' + (isError ? ' error' : '');
    clearTimeout(toast._t);
    toast._t = setTimeout(() => { toast.className = ''; }, 2800);
  }

  // ---- activate snip mode ----
  btnSnip.addEventListener('click', () => {
    btnSnip.classList.add('active');
    overlay.classList.add('active');
    rectEl.style.display  = 'none';
    labelEl.style.display = 'none';
  });

  // ---- cancel on ESC ----
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && overlay.classList.contains('active')) {
      cancelSnip();
    }
  });

  function cancelSnip() {
    overlay.classList.remove('active');
    btnSnip.classList.remove('active');
    dragging = false;
  }

  // ---- drag to select ----
  overlay.addEventListener('mousedown', e => {
    if (e.button !== 0) return;
    dragging = true;
    sx = e.clientX;
    sy = e.clientY;
    updateRect(e.clientX, e.clientY);
    rectEl.style.display  = 'block';
    labelEl.style.display = 'block';
  });

  overlay.addEventListener('mousemove', e => {
    if (!dragging) return;
    updateRect(e.clientX, e.clientY);
  });

  overlay.addEventListener('mouseup', e => {
    if (!dragging) return;
    dragging = false;

    const x = Math.min(sx, e.clientX);
    const y = Math.min(sy, e.clientY);
    const w = Math.abs(e.clientX - sx);
    const h = Math.abs(e.clientY - sy);

    overlay.classList.remove('active');
    btnSnip.classList.remove('active');
    rectEl.style.display  = 'none';
    labelEl.style.display = 'none';

    if (w < 8 || h < 8) return;   // too small — ignore

    captureRegion(x, y, w, h);
  });

  // ---- update selection rectangle ----
  function updateRect(cx, cy) {
    const x = Math.min(sx, cx);
    const y = Math.min(sy, cy);
    const w = Math.abs(cx - sx);
    const h = Math.abs(cy - sy);

    rectEl.style.left   = x + 'px';
    rectEl.style.top    = y + 'px';
    rectEl.style.width  = w + 'px';
    rectEl.style.height = h + 'px';

    // size label — position below-right of selection, flip if near edge
    const lx = (x + w + 6 + 60 < window.innerWidth)  ? x + w + 6 : x - 66;
    const ly = (y + h + 6 + 20 < window.innerHeight) ? y + h + 6 : y - 22;
    labelEl.style.left = lx + 'px';
    labelEl.style.top  = ly + 'px';
    labelEl.textContent = w + ' x ' + h;
  }

  // ---- capture & copy to clipboard ----
  function captureRegion(x, y, w, h) {
    // Scroll offset compensation
    const scrollX = window.scrollX || document.documentElement.scrollLeft;
    const scrollY = window.scrollY || document.documentElement.scrollTop;
    const dpr = window.devicePixelRatio || 1;

    html2canvas(document.body, {
      x:           x + scrollX,
      y:           y + scrollY,
      width:       w,
      height:      h,
      scale:       dpr,
      useCORS:     true,
      logging:     false,
      backgroundColor: '#0d1117'
    }).then(canvas => {
      canvas.toBlob(blob => {
        if (!blob) { showToast('Capture failed — try again', true); return; }

        // Clipboard API (modern browsers)
        if (navigator.clipboard && window.ClipboardItem) {
          navigator.clipboard.write([
            new ClipboardItem({ 'image/png': blob })
          ]).then(() => {
            showToast('Copied to clipboard — ready to paste!');
          }).catch(() => {
            fallbackDownload(canvas);
          });
        } else {
          fallbackDownload(canvas);
        }
      }, 'image/png');
    }).catch(() => {
      showToast('Capture failed — check browser permissions', true);
    });
  }

  // ---- fallback: download as PNG if clipboard API blocked ----
  function fallbackDownload(canvas) {
    const a = document.createElement('a');
    a.download = 'service-snip-' + Date.now() + '.png';
    a.href = canvas.toDataURL('image/png');
    a.click();
    showToast('Saved as PNG (clipboard blocked by browser)');
  }

})();
</script>
</body>
</html>
"@

# ---- Write and open ----
Add-Type -AssemblyName System.Web   # needed for HtmlEncode
$reportPath = Join-Path $env:TEMP "ServiceManager_$($action)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
$html | Out-File -FilePath $reportPath -Encoding UTF8 -Force
Write-Host "`nReport saved: $reportPath" -ForegroundColor Cyan
Start-Process $reportPath   # opens in default browser