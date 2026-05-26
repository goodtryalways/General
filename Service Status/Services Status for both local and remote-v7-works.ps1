# ================================================================
#  SERVICE MANAGER - ENHANCED DIAGNOSTIC EDITION
#  Actions: start | stop | restart | status | services | diagnostic | health
#
#  EVENT RETRIEVAL - UNIVERSAL 3-TIER FALLBACK (works for ANY service):
#
#  TIER 1 — System log  (EventID 7036/7034/7031/7024/7000/7001/7009/7040)
#            Standard Windows SCM events. Present on most machines.
#            If no start/stop events found here, move to Tier 2.
#
#  TIER 2 — All available Operational/Analytic logs
#            Dynamically discovers every installed event log on the machine,
#            searches ALL of them for events mentioning the service name.
#            Covers WinRM, built-in Windows services, and any third-party/
#            custom application that registers its own event log channel.
#            No hardcoded map needed — works for Asus, SQL, custom apps, etc.
#            If still no start/stop events found, move to Tier 3.
#
#  TIER 3 — Application log (message-text search)
#            Last resort. Many third-party and custom services write plain
#            start/stop messages to the Application log using their service
#            name as the Source/Provider. Searches message text for the
#            service name and infers state from keywords.
#
#  PROD-SAFE: zero internet calls, zero CDN, zero Add-Type System.Web
#             runs on PowerShell 5.1+ with no extra modules
# ================================================================

# ================= CONFIG =================
$mode         = "local"        # local / remote
$serverList   = "AJITHSAI"
$serviceNames = "asusm"
$action       = "start"   # start | stop | restart | status | services | diagnostic | health
$path_output  = "yes"

$outputArray  = @()

# Override for local
if ($mode -eq "local") {
    $serverList = @($env:COMPUTERNAME)
}

# ----------------------------------------------------------------
# Helper: HTML-encode without System.Web (pure PowerShell, no Add-Type)
# ----------------------------------------------------------------
function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $Text = $Text.Replace('&',  '&amp;')
    $Text = $Text.Replace('<',  '&lt;')
    $Text = $Text.Replace('>',  '&gt;')
    $Text = $Text.Replace('"',  '&quot;')
    $Text = $Text.Replace("'",  '&#39;')
    return $Text
}

# ----------------------------------------------------------------
# Helper: Infer state from raw message text.
# Used by Tier 2 and Tier 3 when there are no fixed event ID mappings.
# ----------------------------------------------------------------
function Get-StateFromMessage {
    param([string]$Message)
    $m = $Message.ToLower()
    if     ($m -match 'start(?:ed|ing)|running|gestartet|en cours|activ') { return "running"  }
    elseif ($m -match 'stop(?:ped|ping)|arrêt|beend|deten')               { return "stopped"  }
    elseif ($m -match 'crash|terminat|unexpect')                          { return "crashed (unexpected stop)" }
    elseif ($m -match 'fail|error|timeout|timed.?out')                    { return "failed"   }
    else                                                                   { return ""         }
}

# ----------------------------------------------------------------
# Helper: Retrieve enriched service events.
#
# TIER 1 — System log  (EventID 7036 / 7034 / 7031 / 7024 / 7000 / 7001 / 7009 / 7040)
# TIER 2 — ALL installed event log channels (dynamic discovery, no hardcoded map)
#           Finds every log whose provider/source name contains the service
#           name, then reads start/stop events from message text.
#           Covers WinRM, SQL, Asus, any custom app — automatically.
# TIER 3 — Application log (message-text search)
#           Last resort for services that write plain text to Application log.
# ----------------------------------------------------------------
function Get-ServiceEvents {
    param([string]$ServiceName, [int]$MaxEvents = 1000)

    $startStopStates = @("running","stopped","starting","stopping")

    # ==============================================================
    # TIER 1: System log — standard SCM event IDs
    # ==============================================================
    $xPath = "*[System[EventID=7036 or EventID=7034 or EventID=7031 or EventID=7024 or EventID=7000 or EventID=7001 or EventID=7009 or EventID=7040]]"
    $systemEvents = @()
    try {
        $rawEvents = Get-WinEvent -LogName System -FilterXPath $xPath -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
    } catch { $rawEvents = @() }

    if ($rawEvents) {
        $systemEvents = foreach ($ev in $rawEvents) {
            $msg = $ev.Message
            $isRelevant = switch ($ev.Id) {
                7036    { $ev.Properties[0].Value -eq $ServiceName }
                default { $msg -match [regex]::Escape($ServiceName) }
            }
            if (-not $isRelevant) { continue }

            $stateChange = switch ($ev.Id) {
                7036 {
                    $raw = "$($ev.Properties[1].Value)".Trim().ToLower()
                    if     ($raw -match 'run|start|gestartet|en cours|activ') { "running" }
                    elseif ($raw -match 'stop|arret|beend|deten')             { "stopped" }
                    else   { $raw }
                }
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
                Time     = $ev.TimeCreated
                EventID  = $ev.Id
                State    = $stateChange
                ExitCode = $exitCode
                Message  = ($msg -split "`n")[0]
                Source   = "System"
            }
        }
        $systemEvents = @($systemEvents | Sort-Object Time -Descending)
    }

    # If Tier 1 has start/stop events, return immediately — no need for fallback
    $hasStartStop = @($systemEvents | Where-Object { $_.State -in $startStopStates }).Count -gt 0
    if ($hasStartStop) { return $systemEvents }

    # ==============================================================
    # TIER 2: Dynamic discovery — search ALL installed log channels
    # No hardcoded map. Discovers any log whose ProviderName or
    # LogName contains the service name, then reads its events.
    # Covers: WinRM, SQL Server, Asus, custom apps — automatically.
    # ==============================================================
    Write-Verbose "Tier 1 found no start/stop for '$ServiceName' — scanning all log channels (Tier 2)..."

    $tier2Events = @()
    try {
        # Get all log names registered on this machine
        $allLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
            Where-Object { $_.RecordCount -gt 0 -and $_.LogName -notmatch '^(Security|System|Application)$' }

        # Find logs whose channel name contains the service name
        # e.g. "Microsoft-Windows-WinRM/Operational" contains "WinRM"
        $matchingLogs = $allLogs | Where-Object {
            $_.LogName -match [regex]::Escape($ServiceName)
        }

        foreach ($log in $matchingLogs) {
            try {
                $rawOp = Get-WinEvent -LogName $log.LogName -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
                if (-not $rawOp) { continue }

                foreach ($ev in $rawOp) {
                    # For service-specific operational logs, ALL events are relevant
                    # Infer state from well-known IDs first, then message text
                    $state = switch ($ev.Id) {
                        # WinRM / generic MS service operational IDs
                        {$_ -in @(208,7)} { "starting" }
                        {$_ -in @(209,6)} { "running"  }
                        {$_ -in @(211,5)} { "stopping" }
                        {$_ -in @(212,4)} { "stopped"  }
                        {$_ -in @(214)}   { "crashed (unexpected stop)" }
                        {$_ -in @(215)}   { "failed to start" }
                        default           { Get-StateFromMessage -Message $ev.Message }
                    }

                    # Only keep events we could map to a meaningful state
                    if (-not $state) { continue }

                    $tier2Events += [PSCustomObject]@{
                        Time     = $ev.TimeCreated
                        EventID  = $ev.Id
                        State    = $state
                        ExitCode = $null
                        Message  = ($ev.Message -split "`n")[0]
                        Source   = "Operational/$($log.LogName)"
                    }
                }
            } catch { continue }
        }
    } catch {}

    $tier2Events = @($tier2Events | Sort-Object Time -Descending)
    $hasStartStop = @($tier2Events | Where-Object { $_.State -in $startStopStates }).Count -gt 0

    # Merge Tier 1 (non-start/stop events like crashes) + Tier 2
    if ($hasStartStop) {
        $combined = @($systemEvents) + @($tier2Events) |
            Sort-Object Time -Descending |
            Group-Object { "$($_.Time)_$($_.State)" } |
            ForEach-Object { $_.Group | Select-Object -First 1 }
        return @($combined | Sort-Object Time -Descending)
    }

    # ==============================================================
    # TIER 3: Application log — message-text search
    # Last resort for third-party / custom services that write plain
    # start/stop messages to Application log (e.g. most vendor services,
    # custom .NET Windows services, Asus utilities, etc.)
    # ==============================================================
    Write-Verbose "Tier 2 found no start/stop for '$ServiceName' — searching Application log (Tier 3)..."

    $tier3Events = @()
    try {
        # First try: match by ProviderName (fastest, most accurate)
        $appByProvider = Get-WinEvent -LogName Application -MaxEvents $MaxEvents -ErrorAction SilentlyContinue |
            Where-Object { $_.ProviderName -match [regex]::Escape($ServiceName) }

        # Second try: match by message text if provider match returns nothing
        if (-not $appByProvider) {
            $appByProvider = Get-WinEvent -LogName Application -MaxEvents $MaxEvents -ErrorAction SilentlyContinue |
                Where-Object { $_.Message -match [regex]::Escape($ServiceName) }
        }

        foreach ($ev in $appByProvider) {
            $state = Get-StateFromMessage -Message $ev.Message
            if (-not $state) { continue }

            $tier3Events += [PSCustomObject]@{
                Time     = $ev.TimeCreated
                EventID  = $ev.Id
                State    = $state
                ExitCode = $null
                Message  = ($ev.Message -split "`n")[0]
                Source   = "Application"
            }
        }
    } catch {}

    $tier3Events = @($tier3Events | Sort-Object Time -Descending)

    # Final merge: Tier 1 + Tier 3
    $combined = @($systemEvents) + @($tier3Events) |
        Sort-Object Time -Descending |
        Group-Object { "$($_.Time)_$($_.State)" } |
        ForEach-Object { $_.Group | Select-Object -First 1 }

    return @($combined | Sort-Object Time -Descending)
}

# ----------------------------------------------------------------
# Helper: Try to identify WHO stopped the service (Security log)
# ----------------------------------------------------------------
function Get-StopInitiator {
    param([string]$ServiceName, [datetime]$StopTime)

    $window = 120
    try {
        $secEvents = Get-WinEvent -LogName Security -MaxEvents 500 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Id -in @(4689, 4674) -and
                [Math]::Abs(($_.TimeCreated - $StopTime).TotalSeconds) -le $window
            }

        $match = $secEvents |
            Where-Object { $_.Message -match [regex]::Escape($ServiceName) } |
            Select-Object -First 1

        if ($match) {
            $userMatch = [regex]::Match($match.Message, 'Account Name:\s+(.+)')
            if ($userMatch.Success) {
                return "User: $($userMatch.Groups[1].Value.Trim()) (Security EventID $($match.Id))"
            }
        }
    } catch {}

    return "System/SCM (no user audit entry - enable Security auditing for exact identity)"
}

# ----------------------------------------------------------------
# Helper: Get service recovery/failure actions via sc.exe
# ----------------------------------------------------------------
function Get-RecoveryActions {
    param([string]$ServiceName)
    try {
        $sc = & "$env:SystemRoot\System32\sc.exe" qfailure $ServiceName 2>&1
        return ($sc -join " | ").Trim()
    } catch {
        return "Unable to read recovery config"
    }
}

# ----------------------------------------------------------------
# Helper: Get service dependency status
# ----------------------------------------------------------------
function Get-DependencyStatus {
    param([string]$ServiceName)
    try {
        $svc  = Get-Service -Name $ServiceName -ErrorAction Stop
        $deps = $svc.ServicesDependedOn
        if ($deps.Count -eq 0) { return "None" }
        return ($deps | ForEach-Object { "$($_.Name) [$($_.Status)]" }) -join ", "
    } catch {
        return "Unable to read"
    }
}

# ================================================================
#  MAIN LOOP
# ================================================================
foreach ($server in $serverList) {

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host " Server: $server  |  Mode: $mode  |  Action: $action" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    switch ($action) {

        # ==============================================================
        # SERVICES
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
        # STATUS
        # ==============================================================
        "status" {
            foreach ($serviceName in $serviceNames) {
                Write-Host "`n[STATUS] Checking: $serviceName" -ForegroundColor Yellow

                if ($mode -eq "local") {
                    try {
                        $svc = Get-Service -Name $serviceName -ErrorAction Stop
                    } catch {
                        Write-Warning "Service not found: $serviceName"
                        continue
                    }

                    $cim    = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
                    $path   = if ($path_output -eq "yes") { $cim.PathName } else { $null }
                    $events = Get-ServiceEvents -ServiceName $serviceName -MaxEvents 1000

                    $stopStates = @("stopped","crashed (unexpected stop)","stopped (recovery triggered)","stopped (exit error)","stopping")
                    $lastStop   = $events | Where-Object { $_.State -in $stopStates }         | Select-Object -First 1
                    $lastStart  = $events | Where-Object { $_.State -in @("running","starting") } | Select-Object -First 1
                    $lastCrash  = $events | Where-Object { $_.EventID -in @(7034,7031,7024,214) } | Select-Object -First 1
                    $lastError  = $events | Where-Object { $_.EventID -in @(7000,7001,7009,215) } | Select-Object -First 1

                    $recovery = Get-RecoveryActions -ServiceName $serviceName
                    $exitCode = $cim.ExitCode

                    $statusColor = if ($svc.Status -eq "Running") { "Green" } else { "Red" }
                    Write-Host "  Status     : $($svc.Status)"  -ForegroundColor $statusColor
                    Write-Host "  Start Type : $($cim.StartMode)"
                    Write-Host "  Last Start : $(if ($lastStart) { "$($lastStart.Time) [source: $($lastStart.Source)]" } else { 'N/A' })"
                    Write-Host "  Last Stop  : $(if ($lastStop)  { "$($lastStop.Time) [source: $($lastStop.Source)]"  } else { 'N/A' })"
                    if ($lastCrash) { Write-Host "  !! CRASH   : $($lastCrash.Time) - $($lastCrash.State) | $($lastCrash.ExitCode)" -ForegroundColor Red }
                    if ($lastError) { Write-Host "  !! ERROR   : $($lastError.Time) - $($lastError.State)" -ForegroundColor Red }
                    if ($exitCode -ne 0) { Write-Host "  Exit Code  : $exitCode (non-zero)" -ForegroundColor Yellow }
                    Write-Host "  Recovery   : $recovery"

                    $outputArray += [PSCustomObject]@{
                        ServerName      = $server
                        ServiceName     = $svc.Name
                        DisplayName     = $svc.DisplayName
                        Status          = $svc.Status
                        StartType       = $cim.StartMode
                        RunAs           = $cim.StartName
                        LastStarted     = if ($lastStart) { $lastStart.Time } else { "N/A" }
                        LastStartSource = if ($lastStart) { $lastStart.Source } else { "N/A" }
                        LastStopped     = if ($lastStop)  { $lastStop.Time  } else { "N/A" }
                        LastStopSource  = if ($lastStop)  { $lastStop.Source } else { "N/A" }
                        LastCrash       = if ($lastCrash) { "$($lastCrash.Time) | $($lastCrash.State) | $($lastCrash.ExitCode)" } else { "None" }
                        LastStartError  = if ($lastError) { "$($lastError.Time) | $($lastError.State)" } else { "None" }
                        ExitCode        = $exitCode
                        RecoveryActions = $recovery
                        Path            = $path
                    }
                }
            }
        }

        # ==============================================================
        # DIAGNOSTIC
        # ==============================================================
        "diagnostic" {
            foreach ($serviceName in $serviceNames) {
                Write-Host "`n[DIAGNOSTIC] ====== $serviceName ======" -ForegroundColor Magenta

                if ($mode -eq "local") {
                    try {
                        $svc = Get-Service -Name $serviceName -ErrorAction Stop
                    } catch {
                        Write-Warning "Service not found: $serviceName"
                        continue
                    }

                    $cim       = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
                    $rawPath   = $cim.PathName
                    $exePath   = (($rawPath -replace '"','') -split '\.exe')[0] + ".exe"
                    $exeExists = Test-Path $exePath

                    $events      = Get-ServiceEvents -ServiceName $serviceName -MaxEvents 2000
                    $stopStates  = @("stopped","crashed (unexpected stop)","stopped (recovery triggered)","stopped (exit error)","stopping")
                    $startStates = @("running","starting")
                    $lastStop    = $events | Where-Object { $_.State -in $stopStates }               | Select-Object -First 1
                    $lastStart   = $events | Where-Object { $_.State -in $startStates }              | Select-Object -First 1
                    $crashEvents = @($events | Where-Object { $_.EventID -in @(7034,7031,214) })
                    $errorEvents = @($events | Where-Object { $_.EventID -in @(7024,7000,7001,7009,215) })

                    $stopInitiator = "N/A"
                    $stopMethod    = "N/A"
                    $stopReason    = "N/A"

                    if ($lastStop) {
                        $stopInitiator = Get-StopInitiator -ServiceName $serviceName -StopTime $lastStop.Time
                        $stopMethod = switch ($lastStop.EventID) {
                            7036 { "Clean stop (SCM or user request)"       }
                            212  { "Clean stop (Operational log)"           }
                            7034 { "Unexpected termination / crash"         }
                            7031 { "Terminated - recovery action triggered" }
                            7024 { "Service exited with error code"         }
                            214  { "Crashed (Operational log)"              }
                            default { "Unknown (EventID $($lastStop.EventID))" }
                        }
                        $stopReason = if ($lastStop.ExitCode) {
                            "Exit Code: $($lastStop.ExitCode)"
                        } elseif ($cim.ExitCode -ne 0) {
                            "WMI Exit Code: $($cim.ExitCode)"
                        } else {
                            "Exit code 0 (clean) - may be intentional stop"
                        }
                    }

                    $depStatus = Get-DependencyStatus -ServiceName $serviceName
                    $recovery  = Get-RecoveryActions  -ServiceName $serviceName

                    # Identify which log source was used
                    $eventSource = if ($events.Count -gt 0) { $events[0].Source } else { "No events found" }

                    Write-Host "`n  --- CURRENT STATE ---" -ForegroundColor Cyan
                    $c = if ($svc.Status -eq "Running") { "Green" } else { "Red" }
                    Write-Host "  Status     : $($svc.Status)"   -ForegroundColor $c
                    Write-Host "  Start Type : $($cim.StartMode)"
                    Write-Host "  Run As     : $($cim.StartName)"
                    Write-Host "  WMI Exit   : $($cim.ExitCode)"
                    Write-Host "  Exe Exists : $exeExists  [$exePath]" -ForegroundColor $(if ($exeExists) { "Green" } else { "Red" })
                    Write-Host "  Event Src  : $eventSource" -ForegroundColor Cyan

                    Write-Host "`n  --- LAST START / STOP ---" -ForegroundColor Cyan
                    Write-Host "  Last Start : $(if ($lastStart) { "$($lastStart.Time)  [src: $($lastStart.Source)]" } else { 'N/A' })"
                    Write-Host "  Last Stop  : $(if ($lastStop)  { "$($lastStop.Time)  [src: $($lastStop.Source)]"  } else { 'N/A' })"
                    Write-Host "  Stop Method: $stopMethod"
                    Write-Host "  Stop Reason: $stopReason"
                    Write-Host "  Initiator  : $stopInitiator"

                    Write-Host "`n  --- CRASH / ERROR EVENTS (last 5) ---" -ForegroundColor Cyan
                    if ($crashEvents.Count -gt 0) {
                        $crashEvents | Select-Object -First 5 | ForEach-Object {
                            Write-Host "  [CRASH $($_.EventID)] $($_.Time) - $($_.State) | $($_.ExitCode)" -ForegroundColor Red
                        }
                    } else { Write-Host "  No crash events found." -ForegroundColor Green }

                    if ($errorEvents.Count -gt 0) {
                        $errorEvents | Select-Object -First 5 | ForEach-Object {
                            Write-Host "  [ERROR $($_.EventID)] $($_.Time) - $($_.State)" -ForegroundColor Yellow
                        }
                    } else { Write-Host "  No start/timeout errors found." -ForegroundColor Green }

                    Write-Host "`n  --- DEPENDENCIES ---"    -ForegroundColor Cyan
                    Write-Host "  $depStatus"
                    Write-Host "`n  --- RECOVERY CONFIG ---"  -ForegroundColor Cyan
                    Write-Host "  $recovery"

                    Write-Host "`n  --- RECENT EVENT TIMELINE (last 10) ---" -ForegroundColor Cyan
                    $events | Select-Object -First 10 | ForEach-Object {
                        $color = switch -Wildcard ($_.State) {
                            "*crash*"  { "Red"    }
                            "*error*"  { "Red"    }
                            "*failed*" { "Red"    }
                            "*timed*"  { "Yellow" }
                            "running"  { "Green"  }
                            "starting" { "Cyan"   }
                            "stopping" { "Yellow" }
                            default    { "White"  }
                        }
                        Write-Host "  [$($_.EventID)] $($_.Time)  $($_.State)  $(if($_.ExitCode){"| $($_.ExitCode)"})  [src:$($_.Source)]" -ForegroundColor $color
                    }

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
                        EventSource     = $eventSource
                        LastStarted     = if ($lastStart) { $lastStart.Time } else { "N/A" }
                        LastStartSource = if ($lastStart) { $lastStart.Source } else { "N/A" }
                        LastStopped     = if ($lastStop)  { $lastStop.Time  } else { "N/A" }
                        LastStopSource  = if ($lastStop)  { $lastStop.Source } else { "N/A" }
                        StopMethod      = $stopMethod
                        StopReason      = $stopReason
                        StopInitiator   = $stopInitiator
                        CrashCount      = $crashEvents.Count
                        ErrorCount      = $errorEvents.Count
                        Dependencies    = $depStatus
                        RecoveryActions = $recovery
                        FullPath        = $rawPath
                    }
                }
            }
        }

        # ==============================================================
        # HEALTH
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

                $lastRunning = $events | Where-Object { $_.State -in @("running","starting") } | Select-Object -First 1
                $uptime = if ($svc.Status -eq "Running" -and $lastRunning) {
                    $span = (Get-Date) - $lastRunning.Time
                    "{0}d {1}h {2}m" -f [int]$span.TotalDays, $span.Hours, $span.Minutes
                } else { "Not running" }

                $crashCount = @($events | Where-Object { $_.EventID -in @(7034,7031,214) }).Count
                $errorCount = @($events | Where-Object { $_.EventID -in @(7024,7000,7001,7009,215) }).Count
                $depStatus  = Get-DependencyStatus -ServiceName $serviceName
                $eventSource = if ($events.Count -gt 0) { $events[0].Source } else { "No events" }

                $healthStatus = if ($svc.Status -ne "Running") { "DEGRADED" }
                                elseif ($crashCount -gt 0 -or $errorCount -gt 0) { "WARNING" }
                                else { "HEALTHY" }

                $color = switch ($healthStatus) {
                    "HEALTHY"  { "Green"  }
                    "WARNING"  { "Yellow" }
                    "DEGRADED" { "Red"    }
                }

                Write-Host "  Health     : $healthStatus" -ForegroundColor $color
                Write-Host "  Status     : $($svc.Status)"
                Write-Host "  Start Type : $($cim.StartMode)"
                Write-Host "  Uptime     : $uptime"
                Write-Host "  Crashes    : $crashCount"
                Write-Host "  Errors     : $errorCount"
                Write-Host "  Run As     : $($cim.StartName)"
                Write-Host "  Depends On : $depStatus"
                Write-Host "  Event Src  : $eventSource" -ForegroundColor Cyan

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
                    EventSource  = $eventSource
                }
            }
        }

        # ==============================================================
        # START / STOP / RESTART
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
                        Start-Sleep -Seconds 2
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

                    $recentEv = Get-ServiceEvents -ServiceName $serviceName -MaxEvents 20 | Select-Object -First 1
                    if ($recentEv) {
                        Write-Host "  Latest Event [$($recentEv.EventID)] [src:$($recentEv.Source)]: $($recentEv.Time) - $($recentEv.State)" -ForegroundColor Cyan
                    }

                    $outputArray += [PSCustomObject]@{
                        ServerName  = $server
                        ServiceName = $serviceName
                        Action      = $action
                        Before      = $before.Status
                        After       = $after.Status
                        Result      = "SUCCESS"
                        LatestEvent = if ($recentEv) { "$($recentEv.Time) | $($recentEv.State) [src:$($recentEv.Source)]" } else { "N/A" }
                        Error       = $null
                    }

                } catch {
                    Write-Host "  FAILED: $serviceName" -ForegroundColor Red
                    Write-Host "  $($_.Exception.Message)" -ForegroundColor Yellow

                    $failEv = Get-ServiceEvents -ServiceName $serviceName -MaxEvents 50 |
                        Where-Object { $_.EventID -in @(7000,7001,7009,7024,7034,214,215) } |
                        Select-Object -First 1

                    if ($failEv) {
                        Write-Host "  Related Event [$($failEv.EventID)]: $($failEv.Time) - $($failEv.State)" -ForegroundColor Red
                    }

                    $outputArray += [PSCustomObject]@{
                        ServerName  = $server
                        ServiceName = $serviceName
                        Action      = $action
                        Before      = "Unknown"
                        After       = "Failed"
                        Result      = "FAILED"
                        LatestEvent = if ($failEv) { "[$($failEv.EventID)] $($failEv.Time) | $($failEv.State)" } else { "No event found" }
                        Error       = $_.Exception.Message
                    }
                }
            }
        }
    }

    Write-Host "`n--------------------------------------------------" -ForegroundColor DarkGray
}

# ================================================================
# OUTPUT - Self-contained HTML report
# ================================================================
if ($outputArray.Count -eq 0) {
    Write-Host "`nNo output collected." -ForegroundColor Yellow
    return
}

$columns = $outputArray[0].PSObject.Properties.Name

function Get-CellClass {
    param([string]$ColName, [string]$Value)
    $v = $Value.ToLower()
    $c = $ColName.ToLower()

    if ($c -in @("status","healthstatus","result","after","before")) {
        if ($v -match "running|healthy|success") { return "ok"   }
        if ($v -match "stopped|degraded|failed") { return "bad"  }
        if ($v -match "warning|paused|pending")  { return "warn" }
    }
    if ($c -in @("crashcount","errorcount") -and $Value -match '^\d+$' -and [int]$Value -gt 0) { return "bad" }
    if ($c -eq "exeexists") {
        if ($v -eq "false") { return "bad" }
        if ($v -eq "true")  { return "ok"  }
    }
    if ($v -match "crash|failed|error|timed out|unexpected") { return "bad"  }
    if ($v -match "warning|recovery|stopped")               { return "warn" }
    return ""
}

$rowsHtml = foreach ($obj in $outputArray) {
    $cells = foreach ($col in $columns) {
        $raw  = if ($null -ne $obj.$col) { "$($obj.$col)" } else { "" }
        $cls  = Get-CellClass -ColName $col -Value $raw
        $safe = ConvertTo-HtmlEncoded -Text $raw
        $safe = $safe -replace '(\\|/|,)', '$1<wbr>'
        "<td class=`"$cls`">$safe</td>"
    }
    "<tr>$($cells -join '')</tr>"
}

$headerHtml = ($columns | ForEach-Object { "<th>$(ConvertTo-HtmlEncoded -Text $_)</th>" }) -join ''
$timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$rowCount   = $outputArray.Count
$csvName    = "ServiceManager_$($action)_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Service Manager - $server - $timestamp</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:Consolas,'Cascadia Code','Courier New',monospace;font-size:13px;background:#0d1117;color:#c9d1d9;padding:24px}
h1{font-size:15px;font-weight:600;color:#58a6ff;margin-bottom:6px;letter-spacing:.02em}
.meta{font-size:11px;color:#8b949e;margin-bottom:14px}
.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
#search{width:300px;padding:6px 10px;background:#161b22;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:13px;outline:none}
#search:focus{border-color:#58a6ff}
.btn{display:inline-flex;align-items:center;gap:5px;padding:6px 14px;background:#21262d;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;font-size:12px;font-family:inherit;cursor:pointer;user-select:none}
.btn:hover{background:#2d333b;border-color:#58a6ff;color:#58a6ff}
.tbl-wrap{overflow-x:auto;border-radius:8px;border:1px solid #21262d}
table{width:100%;border-collapse:collapse;table-layout:auto}
thead tr{background:#161b22;position:sticky;top:0;z-index:2}
th{padding:9px 12px;text-align:left;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:#8b949e;border-bottom:1px solid #21262d;white-space:nowrap;cursor:pointer;user-select:none}
th:hover{color:#58a6ff}
th.asc::after{content:" \2191";color:#58a6ff}
th.desc::after{content:" \2193";color:#58a6ff}
td{padding:8px 12px;border-bottom:1px solid #21262d;vertical-align:top;white-space:pre-wrap;word-break:break-word;overflow-wrap:anywhere;max-width:420px;line-height:1.55}
tbody tr:nth-child(even){background:#0d1117}
tbody tr:nth-child(odd){background:#111820}
tbody tr:hover{background:#1c2128}
td.ok{color:#3fb950}
td.bad{color:#f85149;font-weight:600}
td.warn{color:#d29922}
tr.hidden{display:none}
.row-count{font-size:11px;color:#8b949e;margin-top:10px}
</style>
</head>
<body>
<h1>Service Manager &mdash; $server &mdash; $timestamp</h1>
<div class="meta">Server: <b>$server</b> &nbsp;|&nbsp; Rows: <b>$rowCount</b></div>
<div class="toolbar">
  <input id="search" type="search" placeholder="Filter rows..." oninput="filterRows(this.value)">
  <button class="btn" onclick="exportCSV()">&#128190; Export CSV</button>
</div>
<div class="tbl-wrap">
<table id="tbl">
  <thead><tr>$headerHtml</tr></thead>
  <tbody>
$($rowsHtml -join "`n")
  </tbody>
</table>
</div>
<div class="row-count" id="rowcount">Showing $rowCount of $rowCount rows</div>
<script>
function filterRows(q){
  var term=q.toLowerCase();
  var rows=document.querySelectorAll('#tbl tbody tr');
  var vis=0;
  for(var i=0;i<rows.length;i++){
    var show=rows[i].textContent.toLowerCase().indexOf(term)>=0;
    rows[i].className=show?'':'hidden';
    if(show)vis++;
  }
  document.getElementById('rowcount').textContent='Showing '+vis+' of '+rows.length+' rows';
}
(function(){
  var ths=document.querySelectorAll('#tbl thead th');
  for(var ci=0;ci<ths.length;ci++){
    (function(colIdx){
      var asc=true;
      ths[colIdx].addEventListener('click',function(){
        for(var j=0;j<ths.length;j++)ths[j].className='';
        ths[colIdx].className=asc?'asc':'desc';
        var tbody=document.querySelector('#tbl tbody');
        var rows=Array.prototype.slice.call(tbody.querySelectorAll('tr'));
        rows.sort(function(a,b){
          var av=a.cells[colIdx]?a.cells[colIdx].textContent.trim():'';
          var bv=b.cells[colIdx]?b.cells[colIdx].textContent.trim():'';
          var an=parseFloat(av),bn=parseFloat(bv);
          if(!isNaN(an)&&!isNaN(bn))return asc?an-bn:bn-an;
          return asc?av.localeCompare(bv):bv.localeCompare(av);
        });
        for(var k=0;k<rows.length;k++)tbody.appendChild(rows[k]);
        asc=!asc;
      });
    })(ci);
  }
})();
function exportCSV(){
  var rows=document.querySelectorAll('#tbl tr:not(.hidden)');
  var lines=[];
  for(var i=0;i<rows.length;i++){
    var cells=rows[i].querySelectorAll('th,td');
    var cols=[];
    for(var j=0;j<cells.length;j++){
      var t=cells[j].textContent.replace(/[\r\n]+/g,' ').trim();
      cols.push('"'+t.replace(/"/g,'""')+'"');
    }
    lines.push(cols.join(','));
  }
  var csv=lines.join('\r\n');
  var blob=new Blob([csv],{type:'text/csv;charset=utf-8;'});
  var url=URL.createObjectURL(blob);
  var a=document.createElement('a');
  a.href=url;
  a.download='$csvName';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function(){URL.revokeObjectURL(url);},1000);
}
</script>
</body>
</html>
"@

$reportPath = Join-Path $env:TEMP "ServiceManager_$($action)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
[System.IO.File]::WriteAllText($reportPath, $html, [System.Text.Encoding]::UTF8)
Write-Host "`nReport saved: $reportPath" -ForegroundColor Cyan
Start-Process $reportPath