#Requires -RunAsAdministrator
<#
.SYNOPSIS
    NPS User Authentication Log Analyzer
    Set your inputs in the CONFIGURATION block below, then press F5 in ISE.
#>

# ════════════════════════════════════════════════════════════════
#  CONFIGURATION — Edit these variables before running (F5)
# ════════════════════════════════════════════════════════════════

$Username        = "jdoe"               # Login name e.g. "jdoe" or "CORP\jdoe"

$DaysBack        = 7                    # Number of days back from today
                                        # Set to 0 to use specific dates below instead

$StartDate       = ""                   # Used only when DaysBack = 0  e.g. "2026-05-01"
$EndDate         = ""                   # Used only when DaysBack = 0  e.g. "2026-05-26"

$ShowSummaryOnly = $false               # $true  = summary tables only (no per-event blocks)
                                        # $false = full detail for every event

$MaxEvents       = 5000                 # Max events to scan from the Security log

$ExportCSV       = ""                   # Full path to save CSV  e.g. "C:\Temp\NPS_Report.csv"
                                        # Leave "" to skip

$ExportHTML      = ""                   # Full path to save HTML e.g. "C:\Temp\NPS_Report.html"
                                        # Leave "" to skip

# ════════════════════════════════════════════════════════════════
#  END OF CONFIGURATION — Do not edit below this line
# ════════════════════════════════════════════════════════════════

# ── Input Validation ────────────────────────────────────────────

if ([string]::IsNullOrWhiteSpace($Username)) {
    Write-Host "  [ERROR] Username is empty. Set the `$Username variable at the top of the script." -ForegroundColor Red
    exit 1
}

if ($DaysBack -gt 0) {
    $startDT = (Get-Date).AddDays(-$DaysBack)
    $endDT   = Get-Date
} elseif ($StartDate -and $EndDate) {
    try {
        $startDT = [datetime]::ParseExact($StartDate, "yyyy-MM-dd", $null)
        $endDT   = [datetime]::ParseExact($EndDate,   "yyyy-MM-dd", $null).AddDays(1).AddSeconds(-1)
    } catch {
        Write-Host "  [ERROR] Invalid date format. Use yyyy-MM-dd e.g. 2026-05-01" -ForegroundColor Red
        exit 1
    }
    if ($startDT -ge $endDT) {
        Write-Host "  [ERROR] StartDate must be earlier than EndDate." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  [ERROR] Set either DaysBack > 0, or both StartDate and EndDate." -ForegroundColor Red
    exit 1
}

$plainUser = ($Username -split "\\")[-1]

# ── Display Helpers ─────────────────────────────────────────────

function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host "  ── $Title" -ForegroundColor Yellow
    Write-Host ""
}

function Write-EventBlock([hashtable]$Info, [string]$Status) {
    $color = switch ($Status) {
        "GRANTED" { "Green" }
        "DENIED"  { "Red"   }
        default   { "DarkYellow" }
    }
    Write-Host ""
    Write-Host "  [$Status]  $($Info.TimeCreated)" -ForegroundColor $color
    Write-Host "  +------------------------------------------------------------" -ForegroundColor DarkGray
    foreach ($key in $Info.Keys | Where-Object { $_ -notin @("TimeCreated","Status") }) {
        if ($Info[$key]) {
            Write-Host ("  |  {0,-28}: {1}" -f $key, $Info[$key]) -ForegroundColor White
        }
    }
    Write-Host "  +------------------------------------------------------------" -ForegroundColor DarkGray
}

# ── Reason Code Lookup ───────────────────────────────────────────

function Get-ReasonText([string]$Code) {
    $map = @{
        "0"  = "IAS_SUCCESS — Authentication and authorization succeeded"
        "1"  = "IAS_INTERNAL_ERROR — Unexpected internal error on NPS"
        "2"  = "IAS_ACCESS_DENIED — Access denied by policy"
        "3"  = "IAS_MALFORMED_REQUEST — Request packet is malformed"
        "4"  = "IAS_GLOBAL_CATALOG_UNAVAILABLE — Global Catalog unreachable"
        "5"  = "IAS_DOMAIN_UNAVAILABLE — Domain controller unreachable"
        "6"  = "IAS_SERVER_UNAVAILABLE — NPS server unavailable"
        "7"  = "IAS_NO_SUCH_DOMAIN — Domain does not exist"
        "8"  = "IAS_NO_SUCH_USER — User account not found in directory"
        "16" = "IAS_AUTH_FAILURE — Generic authentication failure"
        "17" = "IAS_CHANGE_PASSWORD_FAILURE — Password change failed"
        "18" = "IAS_UNSUPPORTED_AUTH_TYPE — Authentication type not supported"
        "32" = "IAS_LOCAL_USERS_ONLY — Only local users are permitted"
        "33" = "IAS_PASSWORD_MUST_CHANGE — User must change password at next logon"
        "34" = "IAS_ACCOUNT_DISABLED — User account is disabled"
        "35" = "IAS_ACCOUNT_EXPIRED — User account has expired"
        "36" = "IAS_ACCOUNT_LOCKED_OUT — User account is locked out"
        "37" = "IAS_INVALID_LOGON_HOURS — Logon outside permitted hours"
        "38" = "IAS_ACCOUNT_RESTRICTION — Account restriction (workstation/time)"
        "48" = "IAS_NO_POLICY_MATCH — No NPS network policy matched the request"
        "49" = "IAS_DIALIN_LOCKED_OUT — Dial-in locked out for this user"
        "50" = "IAS_DIALIN_DISABLED — Dial-in permission denied on account"
        "51" = "IAS_INVALID_AUTH_TYPE — Policy does not allow this auth type"
        "52" = "IAS_INVALID_CALLING_STATION — Calling Station ID mismatch"
        "53" = "IAS_INVALID_DIALIN_HOURS — Outside allowed dial-in hours"
        "54" = "IAS_INVALID_CALLED_STATION — Called Station ID mismatch"
        "55" = "IAS_INVALID_PORT_TYPE — Port type not allowed by policy"
        "56" = "IAS_INVALID_RESTRICTION — Generic policy restriction mismatch"
        "64" = "IAS_NO_RECORD — Log record not found"
        "65" = "IAS_SESSION_TIMEOUT — Session timeout exceeded"
        "66" = "IAS_UNEXPECTED_REQUEST — Request received out of sequence"
        "80" = "IAS_EAP_NEGOTIATION_FAILED — EAP method negotiation failed"
        "96" = "IAS_INVALID_PACKET — RADIUS packet is invalid"
    }
    if ($map.ContainsKey($Code)) { return $map[$Code] }
    return "Unknown Reason Code ($Code)"
}

function Get-EventText([int]$Id) {
    switch ($Id) {
        6272 { "Access Granted — NPS granted access to the user" }
        6273 { "Access Denied  — NPS denied access to the user" }
        6274 { "Access Discarded — No matching policy found" }
        6275 { "Account Locked — Request discarded; account locked" }
        6276 { "Quarantine — User placed in quarantine state" }
        6277 { "Granted (Grace) — Access granted; certificate not yet validated" }
        6278 { "Granted (Full)  — Full access granted after health check" }
        default { "NPS Event ID $Id" }
    }
}

# ── Banner ───────────────────────────────────────────────────────

Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║       NPS User Authentication Log Analyzer                  ║" -ForegroundColor Cyan
Write-Host "  ║       Local NPS Server : $($env:COMPUTERNAME)$((' ' * [Math]::Max(0,32 - $env:COMPUTERNAME.Length)))║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host ("  {0,-22}: {1}" -f "Username",    $Username)                                                         -ForegroundColor Cyan
Write-Host ("  {0,-22}: {1}  to  {2}" -f "Date Range", $startDT.ToString("yyyy-MM-dd HH:mm"), $endDT.ToString("yyyy-MM-dd HH:mm")) -ForegroundColor Cyan
Write-Host ("  {0,-22}: {1}" -f "Max Events",  $MaxEvents)                                                        -ForegroundColor Cyan
if ($ExportCSV)  { Write-Host ("  {0,-22}: {1}" -f "Export CSV",  $ExportCSV)  -ForegroundColor Cyan }
if ($ExportHTML) { Write-Host ("  {0,-22}: {1}" -f "Export HTML", $ExportHTML) -ForegroundColor Cyan }
Write-Host ""

# ── Query Local Security Event Log ───────────────────────────────

Write-Host "  [*] Querying local Security Event Log ..." -ForegroundColor DarkCyan

try {
    $allEvents = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = @(6272, 6273, 6274, 6275, 6276, 6277, 6278)
        StartTime = $startDT
        EndTime   = $endDT
    } -MaxEvents $MaxEvents -ErrorAction Stop 2>$null
}
catch {
    if ($_.Exception.Message -match "No events were found") {
        Write-Host ""
        Write-Host "  [!] No NPS events found in the Security log for this date range." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Check the following:" -ForegroundColor DarkYellow
        Write-Host "   1. NPS Console > Accounting > Configure Accounting" -ForegroundColor DarkGray
        Write-Host "      Ensure 'Log Authentication Requests' is ticked" -ForegroundColor DarkGray
        Write-Host "   2. The Security log may have been cleared or archived" -ForegroundColor DarkGray
        Write-Host "   3. Try increasing DaysBack or adjusting the date range" -ForegroundColor DarkGray
        exit 0
    }
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "  [*] Total NPS events in range : $($allEvents.Count) — filtering for '$Username' ..." -ForegroundColor DarkCyan

# ── Parse & Filter by Username ────────────────────────────────────

$results = [System.Collections.Generic.List[hashtable]]::new()

foreach ($ev in $allEvents) {
    $xml = [xml]$ev.ToXml()
    $dm  = @{}
    foreach ($d in $xml.Event.EventData.Data) { $dm[$d.Name] = $d.'#text' }

    $evUser = $dm["SubjectUserName"] ?? $dm["FullyQualifiedSubjectUserName"] ?? ""
    if ($evUser -notlike "*$plainUser*" -and $evUser -ne $Username) { continue }

    $rc     = $dm["ReasonCode"] ?? $dm["Reason"] ?? ""
    $status = switch ($ev.Id) {
        6272 { "GRANTED" }
        6273 { "DENIED"  }
        6276 { "QUARANTINE" }
        6277 { "GRANTED (Grace)" }
        6278 { "GRANTED (Full)"  }
        default { "OTHER" }
    }

    $results.Add([ordered]@{
        "TimeCreated"       = $ev.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        "Status"            = $status
        "EventID"           = $ev.Id
        "EventDescription"  = Get-EventText $ev.Id
        "Username"          = $evUser
        "Domain"            = $dm["SubjectDomainName"]   ?? ""
        "ClientIP"          = $dm["CallingStationID"]    ?? $dm["ClientIPAddress"] ?? ""
        "NASIPAddress"      = $dm["NASIPAddress"]        ?? ""
        "NASPortType"       = $dm["NASPortType"]         ?? ""
        "NASPort"           = $dm["NASPort"]             ?? ""
        "CalledStationID"   = $dm["CalledStationID"]     ?? ""
        "AuthType"          = $dm["AuthenticationType"]  ?? $dm["EAPType"] ?? ""
        "PolicyName"        = $dm["NPSPolicyName"]       ?? $dm["NetworkPolicyName"] ?? ""
        "ReasonCode"        = $rc
        "ReasonDescription" = if ($rc) { Get-ReasonText $rc } else { "" }
        "ProxyPolicyName"   = $dm["ProxyPolicyName"]     ?? ""
        "FramedIPAddress"   = $dm["FramedIPAddress"]     ?? ""
        "SessionID"         = $dm["UniqueId"]            ?? $dm["SessionID"] ?? ""
    })
}

# ── Summary ───────────────────────────────────────────────────────

$granted    = $results | Where-Object { $_["Status"] -like "GRANTED*" }
$denied     = $results | Where-Object { $_["Status"] -eq "DENIED" }
$quarantine = $results | Where-Object { $_["Status"] -eq "QUARANTINE" }
$other      = $results | Where-Object { $_["Status"] -eq "OTHER" }

Write-Section "Results for User : $Username"
Write-Host ("  {0,-30}: {1}" -f "Total Events Matched", $results.Count) -ForegroundColor White
Write-Host ("  {0,-30}: {1}" -f "  Granted",            $granted.Count)    -ForegroundColor Green
Write-Host ("  {0,-30}: {1}" -f "  Denied",             $denied.Count)     -ForegroundColor Red
Write-Host ("  {0,-30}: {1}" -f "  Quarantine",         $quarantine.Count) -ForegroundColor DarkYellow
Write-Host ("  {0,-30}: {1}" -f "  Other",              $other.Count)      -ForegroundColor Gray

if ($results.Count -eq 0) {
    Write-Host ""
    Write-Host "  No events found for '$Username' in this date range." -ForegroundColor Yellow
    Write-Host "  - Check username spelling (try without domain prefix)" -ForegroundColor DarkGray
    Write-Host "  - Verify NPS authentication logging is enabled" -ForegroundColor DarkGray
    Write-Host "  - Try increasing DaysBack" -ForegroundColor DarkGray
    exit 0
}

if ($denied.Count -gt 0) {
    Write-Section "Top Denial Reasons  (Troubleshooting Guide)"
    $denied | Group-Object { $_["ReasonDescription"] } | Sort-Object Count -Descending | ForEach-Object {
        Write-Host ("  [{0,3}x]  {1}" -f $_.Count, $_.Name) -ForegroundColor Red
    }
}

$policies = $results | Where-Object { $_["PolicyName"] } | Group-Object { $_["PolicyName"] } | Sort-Object Count -Descending
if ($policies) {
    Write-Section "NPS Policies Matched"
    foreach ($p in $policies) {
        Write-Host ("  [{0,3}x]  {1}" -f $p.Count, $p.Name) -ForegroundColor Cyan
    }
}

$ips = $results | Where-Object { $_["ClientIP"] } | Group-Object { $_["ClientIP"] } | Sort-Object Count -Descending
if ($ips) {
    Write-Section "Client IP / Calling Stations"
    foreach ($ip in $ips | Select-Object -First 10) {
        Write-Host ("  [{0,3}x]  {1}" -f $ip.Count, $ip.Name) -ForegroundColor White
    }
}

$auths = $results | Where-Object { $_["AuthType"] } | Group-Object { $_["AuthType"] } | Sort-Object Count -Descending
if ($auths) {
    Write-Section "Authentication Types Used"
    foreach ($a in $auths) {
        Write-Host ("  [{0,3}x]  {1}" -f $a.Count, $a.Name) -ForegroundColor White
    }
}

# ── Per-Event Detail Blocks ───────────────────────────────────────

if (-not $ShowSummaryOnly) {

    if ($granted.Count -gt 0) {
        Write-Section "GRANTED Events — Full Detail"
        foreach ($g in $granted) { Write-EventBlock $g "GRANTED" }
    }

    if ($denied.Count -gt 0) {
        Write-Section "DENIED Events — Full Detail"
        foreach ($d in $denied) { Write-EventBlock $d "DENIED" }
    }

    if ($quarantine.Count -gt 0) {
        Write-Section "QUARANTINE Events — Full Detail"
        foreach ($q in $quarantine) { Write-EventBlock $q "QUARANTINE" }
    }

    if ($other.Count -gt 0) {
        Write-Section "OTHER Events — Full Detail"
        foreach ($o in $other) { Write-EventBlock $o "OTHER" }
    }
}

# ── CSV Export ────────────────────────────────────────────────────

if ($ExportCSV) {
    try {
        $csvDir = Split-Path $ExportCSV
        if ($csvDir -and -not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }
        $results | ForEach-Object { [PSCustomObject]$_ } | Export-Csv -Path $ExportCSV -NoTypeInformation -Encoding UTF8
        Write-Host "  [OK] CSV saved  : $ExportCSV" -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] CSV export failed : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ── HTML Export ───────────────────────────────────────────────────

if ($ExportHTML) {
    try {
        $htmlDir = Split-Path $ExportHTML
        if ($htmlDir -and -not (Test-Path $htmlDir)) { New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null }

        $rows = $results | ForEach-Object {
            $r  = $_
            $bg = switch -Wildcard ($r["Status"]) {
                "GRANTED*"   { "#d4edda" }
                "DENIED"     { "#f8d7da" }
                "QUARANTINE" { "#fff3cd" }
                default      { "#f2f2f2" }
            }
            $cells = $r.Keys | ForEach-Object { "<td>$([System.Web.HttpUtility]::HtmlEncode($r[$_]))</td>" }
            "<tr style='background:$bg'>$($cells -join '')</tr>"
        }
        $headers = ($results[0].Keys | ForEach-Object { "<th>$_</th>" }) -join ""

        @"
<!DOCTYPE html>
<html><head><meta charset='UTF-8'>
<title>NPS Report — $Username</title>
<style>
  body  { font-family: Segoe UI, Arial, sans-serif; font-size: 13px; margin: 20px; }
  h1    { color: #222; }
  .info { background:#f0f4f8; border:1px solid #c8d8e8; padding:12px 18px;
          border-radius:6px; margin-bottom:18px; line-height:1.9; }
  table { border-collapse: collapse; width: 100%; }
  th    { background: #2c3e50; color: #fff; padding: 7px 10px;
          text-align: left; white-space: nowrap; }
  td    { padding: 5px 8px; border: 1px solid #ddd; white-space: nowrap; }
  tr:hover td { filter: brightness(0.96); }
</style>
</head><body>
<h1>NPS Authentication Report</h1>
<div class='info'>
  <b>User:</b> $Username &nbsp;&nbsp;
  <b>Server:</b> $($env:COMPUTERNAME) (local) &nbsp;&nbsp;
  <b>Range:</b> $($startDT.ToString('yyyy-MM-dd')) to $($endDT.ToString('yyyy-MM-dd')) &nbsp;&nbsp;
  <b>Total:</b> $($results.Count) &nbsp;&nbsp;
  <b style='color:green'>Granted: $($granted.Count)</b> &nbsp;&nbsp;
  <b style='color:red'>Denied: $($denied.Count)</b> &nbsp;&nbsp;
  <b style='color:#856404'>Quarantine: $($quarantine.Count)</b>
</div>
<table>
  <thead><tr>$headers</tr></thead>
  <tbody>$($rows -join "`n")</tbody>
</table>
</body></html>
"@ | Out-File -FilePath $ExportHTML -Encoding UTF8

        Write-Host "  [OK] HTML saved : $ExportHTML" -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] HTML export failed : $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ── Footer ────────────────────────────────────────────────────────

Write-Host ""
Write-Host "  ────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Done.  $($results.Count) event(s) found for '$Username'." -ForegroundColor Cyan
Write-Host "  Edit the CONFIGURATION block at the top and press F5 to rerun." -ForegroundColor DarkGray
Write-Host ""
