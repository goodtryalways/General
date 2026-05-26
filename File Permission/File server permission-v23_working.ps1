# ==========================================
# ACL MANAGER
# Version : 6.0
# Author  : Sai
# Actions : Check | DryRun | Backup | Remove | Restore
# ==========================================
#
# FOLDER STRATEGY:
# -------------------------------------------------------
# Check   -> Single shared folder (overwritten each run)
#            No timestamp -- reports are informational only
#            Path: <BackupRootPath>\<Source>\Check_Reports\
#
# DryRun  -> Single shared folder (overwritten each run)
#            No timestamp -- simulation only, nothing destructive
#            Path: <BackupRootPath>\<Source>\DryRun_Reports\
#
# Backup  -> Timestamped folder (preserved per run)
#            Path: <BackupRootPath>\<Source>\Backup_<timestamp>\
#
# Remove  -> Timestamped folder (preserved per run)
#            Pre-removal backup saved here -- never overwrite
#            Path: <BackupRootPath>\<Source>\Remove_<timestamp>\
#
# Restore -> Points to an existing Backup_ or Remove_ folder
#            Post-restore snapshot saved inside that same folder
#            Set $RestoreFolderPath to the exact folder to restore from
# -------------------------------------------------------
#
# HOW REMOVE WORKS -- EXPLICIT vs INHERITED:
# -------------------------------------------------------
#   Remove uses a streaming pipeline so that explicit ACEs
#   on the root folder AND any subfolders/files are all
#   cleaned in a single pass without loading the entire
#   tree into memory at once.
#
#   Inherited ACEs are always SKIPPED -- they do not need to
#   be touched directly. Once the explicit ACE is removed from
#   whichever ancestor introduced it, inheritance propagation
#   stops automatically and the inherited copies disappear on
#   their own.
#
#   Example -- mixed explicit + inherited tree:
#
#   E:\ConvertedVideos          Explicit  -> REMOVED by script
#     mgr\                      Inherited -> skipped, auto-cleans
#       *.mp4                   Inherited -> skipped, auto-cleans
#     ar-rahman\                Explicit  -> REMOVED by script
#       *.mp4                   Inherited -> skipped, auto-cleans
#     ilaiyaraaja\              Inherited -> skipped, auto-cleans
#       special.mp4             Explicit  -> REMOVED by script
#
#   Result: ALL unwanted ACEs gone, no inheritance chain broken,
#           no other principals touched.
# -------------------------------------------------------
#
# HOW TO RESTORE:
#   1. Set $Action = "Restore"
#   2. Set $RestoreFolderPath to a Backup_ or Remove_ timestamped folder
#      Example: "E:\Sai-Work\ACL_Backup\D_Testing_Testing1\Backup_20260510_224644"
#   3. Run the script -- it reads SourcePath.txt and ACL_Backup.txt automatically
# -------------------------------------------------------
#
# FEATURES (v6.0):
# -------------------------------------------------------
#   1.  Admin privilege check      -- exits immediately if not running as Administrator
#   2.  WhatIf confirmation prompt -- Remove shows a summary and asks Y/N before acting
#   3.  SourcePath depth guard     -- warns if SourcePath is only 1 level deep
#   4.  Retry logic on Set-Acl     -- 3 attempts with short sleep on transient failures
#   5.  Orphaned SID detection     -- Check/DryRun flag raw SIDs (deleted accounts)
#                                     Well-known SIDs excluded from false positives
#   6.  RunHistory.csv             -- one row per run appended at $SourceBase level
#                                     Lock-file guard prevents concurrent write corruption
#   7.  Runner identity in log     -- hostname + Windows account stamped at startup
#   8.  Restore DryRun mode        -- previews what would be restored without touching anything
#                                     Set $RestoreDryRun = $true to use
#   9.  Streaming pipeline         -- Check, DryRun, Remove process items one at a time
#                                     No full tree loaded into memory
#  10.  Single-pass Remove         -- WhatIf scan and actual removal share one pipeline pass
#                                     No double scan, no double Get-Acl calls over SMB
#  11.  Suppressed per-file output -- Remove progress counter updates every 500 items
#                                     Full detail goes to Operations.log only
#  12.  Snapshot output separated  -- Before/After icacls snapshot output written to its
#                                     own file only. Operations.log stays clean.
#  13.  Long path warning          -- Checks LongPathsEnabled registry key at startup
#  14.  Pipe-char safe item typing -- File vs Folder detection uses regex instead of
#                                     [System.IO.Path]::GetExtension() which crashes on
#                                     paths containing pipe characters (|) in file names
# -------------------------------------------------------
#
# IMPORTANT -- icacls /save vs /restore syntax difference:
#   /save    -> icacls <LeafName> /save <file> /t /c
#               LeafName tells icacls what to save.
#               Paths in file are relative to ParentPath.
#   /restore -> icacls . /restore <file> /c   (NO LeafName argument)
#               "." = current dir after Push-Location to ParentPath.
#               LeafName is already inside the backup file.
#               Passing it again causes path doubling:
#               ConvertedVideos\ConvertedVideos\mgr\... (WRONG)
#   Both must Push-Location to the same ParentPath.
# -------------------------------------------------------

# ==========================================
# CONFIGURATION
# ==========================================

$Action = "Restore"
# Valid values: Check | DryRun | Backup | Remove | Restore

$SourcePath = "E:\ConvertedVideos"

$BackupRootPath = "E:\Sai-Work\ACL_Backup"

# Required ONLY when Action = "Restore"
# Must point to a Backup_ or Remove_ timestamped folder
$RestoreFolderPath = "E:\Sai-Work\ACL_Backup\E_ConvertedVideos\Remove_20260512_195122"

# Set to $true to preview what Restore would do without touching any ACLs
$RestoreDryRun = $false

$TranscriptMode = "Off"
# On | Off

# Groups whose explicit ACEs will be removed by the Remove action
# Note: PowerShell -contains is case-insensitive.
# Verify exact identity strings match your environment (they can vary by OS locale).
$RemoveGroups = @(
    "Everyone"
    #"NT AUTHORITY\Authenticated Users",
    #"Authenticated Users",
    #"BUILTIN\Users",
    #"Users"
)

# DFS roots -- these paths are never allowed as $SourcePath
$ProtectedPaths = @(
    "D:\Testing",
    "D:\Department",
    "D:\Finance",
    "D:\HR"
)

# Well-known SIDs -- these are valid built-in accounts, never orphaned.
# Used by the orphaned SID detection logic to prevent false positives.
$WellKnownSIDs = @(
    "S-1-0-0",      # Null Authority
    "S-1-1-0",      # Everyone
    "S-1-2-0",      # Local
    "S-1-3-0",      # Creator Owner
    "S-1-3-1",      # Creator Group
    "S-1-5-6",      # Service
    "S-1-5-7",      # Anonymous Logon
    "S-1-5-11",     # Authenticated Users
    "S-1-5-12",     # Restricted Code
    "S-1-5-18",     # Local System
    "S-1-5-19",     # Local Service
    "S-1-5-20",     # Network Service
    "S-1-5-32-544", # BUILTIN\Administrators
    "S-1-5-32-545", # BUILTIN\Users
    "S-1-5-32-546", # BUILTIN\Guests
    "S-1-5-32-547", # Power Users
    "S-1-5-32-548", # Account Operators
    "S-1-5-32-549", # Server Operators
    "S-1-5-32-550", # Print Operators
    "S-1-5-32-551", # Backup Operators
    "S-1-5-32-552"  # Replicators
)

# ==========================================
# ADMIN PRIVILEGE CHECK
# ==========================================

$CurrentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$IsAdmin = $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host ""
    Write-Host "==============================="
    Write-Host " ERROR: Administrator required"
    Write-Host "==============================="
    Write-Host " This script must be run as Administrator."
    Write-Host " Right-click PowerShell and choose 'Run as Administrator',"
    Write-Host " then run the script again."
    Write-Host "==============================="
    return
}

# ==========================================
# VALIDATION
# ==========================================

$ValidActions = @("Check", "DryRun", "Backup", "Remove", "Restore")
if ($Action -notin $ValidActions) {
    Write-Host "ERROR: Invalid Action '$Action'."
    Write-Host "Valid options: $($ValidActions -join ' | ')"
    return
}

if ($SourcePath -match "^[A-Za-z]:\\?$") {
    Write-Host "ERROR: Drive root path not allowed as SourcePath."
    return
}

if ($ProtectedPaths -contains $SourcePath) {
    Write-Host "ERROR: '$SourcePath' is a protected DFS root. Operation not allowed."
    return
}

if ($Action -ne "Restore") {
    if (!(Test-Path $SourcePath)) {
        Write-Host "ERROR: Source path not found: $SourcePath"
        return
    }
}

if ($Action -eq "Restore") {
    if ([string]::IsNullOrWhiteSpace($RestoreFolderPath)) {
        Write-Host "ERROR: RestoreFolderPath is not set. Please set it to a Backup_ or Remove_ folder."
        return
    }
    if (!(Test-Path $RestoreFolderPath)) {
        Write-Host "ERROR: RestoreFolderPath not found: $RestoreFolderPath"
        return
    }
}

# -------------------------------------------------------
# SOURCEPATH DEPTH GUARD
# -------------------------------------------------------
$PathDepth = ($SourcePath.TrimEnd('\') -split '\\').Count
if ($Action -in @("Remove","Backup") -and $PathDepth -le 2) {
    Write-Host ""
    Write-Host "==============================="
    Write-Host " WARNING: Shallow SourcePath"
    Write-Host "==============================="
    Write-Host " SourcePath '$SourcePath' is only 1 level deep."
    Write-Host " Modifying ACEs this close to the drive root can affect"
    Write-Host " a very large number of files and folders."
    Write-Host " Verify this is the intended target before continuing."
    Write-Host "==============================="
    Write-Host ""
}

# -------------------------------------------------------
# LONG PATH SUPPORT CHECK
# -------------------------------------------------------
if ($Action -in @("Check","DryRun","Remove")) {
    try {
        $LongPathKey = Get-ItemProperty `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
            -Name "LongPathsEnabled" -ErrorAction SilentlyContinue
        if ($null -eq $LongPathKey -or $LongPathKey.LongPathsEnabled -ne 1) {
            Write-Host ""
            Write-Host "==============================="
            Write-Host " WARNING: Long path support is disabled"
            Write-Host "==============================="
            Write-Host " Paths longer than 260 characters may cause Get-Acl"
            Write-Host " or Set-Acl to fail with misleading errors."
            Write-Host " To enable: Set HKLM:\SYSTEM\CurrentControlSet\Control\"
            Write-Host "            FileSystem\LongPathsEnabled = 1"
            Write-Host " and reboot, or use Group Policy."
            Write-Host "==============================="
            Write-Host ""
        }
    }
    catch { }
}

# ==========================================
# PATH SETUP
# ==========================================

$TimeStamp      = Get-Date -Format "yyyyMMdd_HHmmss"
$SafeSourceName = $SourcePath.Replace(":","").Replace("\","_").Trim("_")
$SourceBase     = Join-Path $BackupRootPath $SafeSourceName

$RunHistoryFile = Join-Path $SourceBase "RunHistory.csv"

switch ($Action) {
    "Check"   { $RunFolder = Join-Path $SourceBase "Check_Reports" }
    "DryRun"  { $RunFolder = Join-Path $SourceBase "DryRun_Reports" }
    "Backup"  { $RunFolder = Join-Path $SourceBase "Backup_$TimeStamp" }
    "Remove"  { $RunFolder = Join-Path $SourceBase "Remove_$TimeStamp" }
    "Restore" { $RunFolder = $RestoreFolderPath }
}

$BackupICACLSFolder  = Join-Path $RunFolder "Backup_ICACLS"
$RestoreICACLSFolder = Join-Path $RunFolder "Restore_ICACLS"
$ReportsFolder       = Join-Path $RunFolder "Reports"
$LogsFolder          = Join-Path $RunFolder "Logs"
$MetadataFolder      = Join-Path $RunFolder "Metadata"

$BackupFile                = Join-Path $BackupICACLSFolder  "ACL_Backup.txt"
$RestoreSnapshotFile       = Join-Path $RestoreICACLSFolder "ACL_Restore_After.txt"
$ErrorFile                 = Join-Path $LogsFolder          "Operations.log"
$TranscriptFile            = Join-Path $LogsFolder          "Transcript.txt"
$MetadataFile              = Join-Path $MetadataFolder      "SourcePath.txt"
$CheckReport               = Join-Path $ReportsFolder       "CheckACL_$TimeStamp.csv"
$DryRunReport              = Join-Path $ReportsFolder       "DryRun_Report_$TimeStamp.csv"
$RemoveReportCSV           = Join-Path $ReportsFolder       "Remove_Report_$TimeStamp.csv"
$RemoveReportTXT           = Join-Path $ReportsFolder       "Remove_Report_$TimeStamp.txt"
$RemoveBeforeSnapshotFile  = Join-Path $BackupICACLSFolder  "ACL_Before_Remove.txt"
$RemoveAfterSnapshotFile   = Join-Path $BackupICACLSFolder  "ACL_After_Remove.txt"
$RestoreReportCSV          = Join-Path $ReportsFolder       "Restore_Report_$TimeStamp.csv"
$RestoreReportTXT          = Join-Path $ReportsFolder       "Restore_Report_$TimeStamp.txt"
$RestoreBeforeSnapshotFile = Join-Path $RestoreICACLSFolder "ACL_Before_Restore.txt"
$RestoreAfterSnapshotFile  = Join-Path $RestoreICACLSFolder "ACL_After_Restore.txt"

if (!(Test-Path $SourceBase)) { New-Item -Path $SourceBase -ItemType Directory -Force | Out-Null }

switch ($Action) {
    "Check" {
        @($RunFolder, $ReportsFolder, $LogsFolder) | ForEach-Object {
            if (!(Test-Path $_)) { New-Item -Path $_ -ItemType Directory -Force | Out-Null }
        }
    }
    "DryRun" {
        @($RunFolder, $ReportsFolder, $LogsFolder) | ForEach-Object {
            if (!(Test-Path $_)) { New-Item -Path $_ -ItemType Directory -Force | Out-Null }
        }
    }
    "Backup" {
        @($RunFolder, $BackupICACLSFolder, $LogsFolder, $MetadataFolder) | ForEach-Object {
            if (!(Test-Path $_)) { New-Item -Path $_ -ItemType Directory -Force | Out-Null }
        }
    }
    "Remove" {
        @($RunFolder, $BackupICACLSFolder, $LogsFolder, $MetadataFolder, $ReportsFolder) | ForEach-Object {
            if (!(Test-Path $_)) { New-Item -Path $_ -ItemType Directory -Force | Out-Null }
        }
    }
    "Restore" {
        @($LogsFolder, $RestoreICACLSFolder, $ReportsFolder) | ForEach-Object {
            if (!(Test-Path $_)) { New-Item -Path $_ -ItemType Directory -Force | Out-Null }
        }
        $ErrorFile = Join-Path $LogsFolder "Restore_Operations_$TimeStamp.log"
    }
}

# ==========================================
# TRANSCRIPT
# ==========================================

if ($TranscriptMode -eq "On") {
    try { Start-Transcript -Path $TranscriptFile -Force }
    catch { Write-Host "Warning: Could not start transcript. $_" }
}

# ==========================================
# STARTUP SUMMARY
# ==========================================

$RunnerHost    = $env:COMPUTERNAME
$RunnerAccount = [Security.Principal.WindowsIdentity]::GetCurrent().Name

Write-Host ""
Write-Host "==============================="
Write-Host " ACL Manager v6.0"
Write-Host "==============================="
Write-Host " Action      : $Action"
Write-Host " Source      : $SourcePath"
Write-Host " Run Folder  : $RunFolder"
Write-Host " Timestamp   : $TimeStamp"
Write-Host " Host        : $RunnerHost"
Write-Host " Run As      : $RunnerAccount"
Write-Host "==============================="
Write-Host ""

# ==========================================
# FUNCTIONS
# ==========================================

# -------------------------------------------------------
# Get-RootItem
# Returns only the root item (the SourcePath folder itself).
# -------------------------------------------------------
function Get-RootItem {
    param ([string]$Path)
    try   { return Get-Item $Path -ErrorAction Stop }
    catch {
        "Get-RootItem error for '$Path': $_" | Out-File $ErrorFile -Append
        return $null
    }
}

# -------------------------------------------------------
# Get-ItemKind
# Determines whether a path line from an icacls backup file
# represents a File or a Folder using a regex extension check.
#
# WHY NOT [System.IO.Path]::GetExtension()?
#   That method calls Windows path APIs internally and throws:
#   "Illegal characters in path" when the string contains
#   pipe characters (|) -- which are common in media file
#   names like "001 - Song | Artist | Film.mp4".
#   The regex approach is pure string matching with no API call.
# -------------------------------------------------------
function Get-ItemKind {
    param ([string]$PathString)
    # Match a dot followed by 2-5 alphanumeric characters at end of string.
    # Covers all common extensions: .mp4 .mkv .mp3 .txt .docx .xlsx etc.
    if ($PathString -match '\.[a-zA-Z0-9]{2,5}$') { return "File" }
    return "Folder"
}

# -------------------------------------------------------
# Take-Backup
# Saves the full recursive ACL of $SourcePath using
# icacls /save into Backup_ICACLS\ACL_Backup.txt.
# Also writes $SourcePath to Metadata\SourcePath.txt.
# Returns: 0 = success, 1 = failure
# -------------------------------------------------------
function Take-Backup {
    try {
        $ParentPath = Split-Path $SourcePath -Parent
        $LeafName   = Split-Path $SourcePath -Leaf

        Write-Host "Taking backup..."
        Write-Host "  Source      : $SourcePath"
        Write-Host "  Parent      : $ParentPath"
        Write-Host "  Leaf        : $LeafName"
        Write-Host "  Backup file : $BackupFile"

        $SourcePath | Out-File $MetadataFile -Force -Encoding UTF8

        "=== icacls backup run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File $ErrorFile -Append
        "Source: $SourcePath | Backup: $BackupFile"                            | Out-File $ErrorFile -Append

        Push-Location $ParentPath
        try {
            $Output   = & icacls $LeafName /save $BackupFile /t /c 2>&1
            $ExitCode = $LASTEXITCODE
        }
        finally { Pop-Location }

        # Log exit code only -- snapshot output goes to its own file
        "icacls /save exit code: $ExitCode" | Out-File $ErrorFile -Append
        if ($ExitCode -ne 0) { $Output | Out-File $ErrorFile -Append }

        return $ExitCode
    }
    catch {
        "Take-Backup error: $_" | Out-File $ErrorFile -Append
        return 1
    }
}

# -------------------------------------------------------
# Set-AclWithRetry
# Wraps Set-Acl with up to $MaxAttempts retries.
# Returns: $true = success, $false = all attempts failed
# -------------------------------------------------------
function Set-AclWithRetry {
    param (
        [string]$Path,
        [System.Security.AccessControl.FileSystemSecurity]$AclObject,
        [int]$MaxAttempts  = 3,
        [int]$SleepSeconds = 2
    )
    for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
        try {
            Set-Acl -Path $Path -AclObject $AclObject -ErrorAction Stop
            return $true
        }
        catch {
            if ($Attempt -lt $MaxAttempts) {
                "Set-Acl attempt $Attempt failed for '$Path' -- retrying in ${SleepSeconds}s. Error: $_" |
                    Out-File $ErrorFile -Append
                Start-Sleep -Seconds $SleepSeconds
            }
            else {
                "Set-Acl FAILED after $MaxAttempts attempts for '$Path'. Error: $_" |
                    Out-File $ErrorFile -Append
                return $false
            }
        }
    }
    return $false
}

# -------------------------------------------------------
# Test-IsOrphanedSID
# Returns $true if the identity is a raw SID that is NOT
# in the $WellKnownSIDs list (i.e. a truly unknown/deleted account).
# -------------------------------------------------------
function Test-IsOrphanedSID {
    param ([string]$Identity)
    if ($Identity -match "^S-\d-\d+(-\d+)*$") {
        if ($WellKnownSIDs -contains $Identity) { return $false }
        return $true
    }
    return $false
}

# -------------------------------------------------------
# Write-RunHistory
# Appends one row to RunHistory.csv at SourceBase level.
# Uses a lock-file guard to prevent concurrent write corruption.
# -------------------------------------------------------
function Write-RunHistory {
    param (
        [string]$ActionName,
        [string]$Status,
        [int]   $ItemsModified = 0,
        [int]   $ACEsChanged   = 0,
        [int]   $Errors        = 0,
        [string]$Notes         = ""
    )

    $Row = [PSCustomObject]@{
        Timestamp     = $TimeStamp
        Host          = $RunnerHost
        RunAs         = $RunnerAccount
        Action        = $ActionName
        SourcePath    = $SourcePath
        Status        = $Status
        ItemsModified = $ItemsModified
        ACEsChanged   = $ACEsChanged
        Errors        = $Errors
        RunFolder     = $RunFolder
        Notes         = $Notes
    }

    $LockFile    = "$RunHistoryFile.lock"
    $MaxWaitSecs = 15
    $Waited      = 0

    while ((Test-Path $LockFile) -and $Waited -lt $MaxWaitSecs) {
        Start-Sleep -Milliseconds 500
        $Waited++
    }

    try {
        New-Item -Path $LockFile -ItemType File -Force | Out-Null
        $Row | Export-Csv $RunHistoryFile -NoTypeInformation -Encoding UTF8 -Append
    }
    catch {
        "Write-RunHistory error: $_" | Out-File $ErrorFile -Append
    }
    finally {
        Remove-Item $LockFile -Force -ErrorAction SilentlyContinue
    }
}

# ==========================================
# STARTUP LOG
# ==========================================

"=== ACL Manager v6.0 -- Run started ===" | Out-File $ErrorFile -Append
"Timestamp : $TimeStamp"                  | Out-File $ErrorFile -Append
"Action    : $Action"                     | Out-File $ErrorFile -Append
"Source    : $SourcePath"                 | Out-File $ErrorFile -Append
"Host      : $RunnerHost"                 | Out-File $ErrorFile -Append
"Run As    : $RunnerAccount"              | Out-File $ErrorFile -Append
"=======================================" | Out-File $ErrorFile -Append

# ==========================================
# ACTIONS
# ==========================================

# --------------------------------------------------
# CHECK
# Reads current ACL of all items (root + children).
# Streaming pipeline -- no full tree in memory.
# CSV rows written incrementally.
# --------------------------------------------------
if ($Action -eq "Check") {

    Write-Host "Starting Check..."
    Write-Host "No changes will be made."
    Write-Host ""

    $CheckCount  = 0
    $OrphanCount = 0
    $FirstRow    = $true

    & {
        $RootItem = Get-RootItem -Path $SourcePath
        if ($null -ne $RootItem) { $RootItem }
        Get-ChildItem $SourcePath -Recurse -Force -ErrorAction SilentlyContinue
    } | ForEach-Object {

        $Item = $_
        $CheckCount++

        if ($CheckCount % 500 -eq 0) {
            Write-Progress -Activity "Check" -Status "Items scanned: $CheckCount" `
                -CurrentOperation $Item.FullName
        }

        try {
            $Acl = Get-Acl $Item.FullName

            foreach ($Entry in $Acl.Access) {

                $InRemoveGroups = $RemoveGroups -contains $Entry.IdentityReference.Value
                $IsOrphanedSID  = Test-IsOrphanedSID -Identity $Entry.IdentityReference.Value
                if ($IsOrphanedSID) { $OrphanCount++ }

                if ($IsOrphanedSID) {
                    $Reason = "ORPHANED SID detected: '$($Entry.IdentityReference.Value)' appears to be a raw SID with no known account. The account may have been deleted. Review and clean up manually."
                }
                elseif ($InRemoveGroups -and (-not $Entry.IsInherited)) {
                    $Reason = "Explicit ACE for '$($Entry.IdentityReference.Value)' matches RemoveGroups. This $(if ($Item.PSIsContainer) { 'folder' } else { 'file' }) has a direct (non-inherited) permission entry that CAN be removed by the Remove action."
                }
                elseif ($InRemoveGroups -and $Entry.IsInherited) {
                    $Reason = "ACE for '$($Entry.IdentityReference.Value)' matches RemoveGroups but is INHERITED -- cannot remove directly. It will auto-clean once the explicit ACE on the ancestor folder is removed by the Remove action."
                }
                else {
                    $Reason = "Identity '$($Entry.IdentityReference.Value)' is NOT in RemoveGroups -- this ACE will NOT be touched by the Remove action."
                }

                $Row = [PSCustomObject]@{
                    Path              = $Item.FullName
                    Identity          = $Entry.IdentityReference.Value
                    Rights            = $Entry.FileSystemRights
                    IsInherited       = $Entry.IsInherited
                    AccessControlType = $Entry.AccessControlType
                    ItemType          = if ($Item.PSIsContainer) { "Folder" } else { "File" }
                    OrphanedSID       = $IsOrphanedSID
                    Reason            = $Reason
                }

                if ($FirstRow) {
                    $Row | Export-Csv $CheckReport -NoTypeInformation -Encoding UTF8
                    $FirstRow = $false
                }
                else {
                    $Row | Export-Csv $CheckReport -NoTypeInformation -Encoding UTF8 -Append
                }
            }
        }
        catch {
            "Check error on '$($Item.FullName)': $_" | Out-File $ErrorFile -Append
        }
    }

    Write-Progress -Activity "Check" -Completed

    Write-Host "Check completed."
    Write-Host " Items scanned : $CheckCount"
    if (Test-Path $CheckReport) {
        Write-Host " Report        : $CheckReport"
    }
    else {
        Write-Host " No ACL entries found under: $SourcePath"
    }
    if ($OrphanCount -gt 0) {
        Write-Host ""
        Write-Host "  *** WARNING: $OrphanCount orphaned SID(s) detected. ***"
        Write-Host "  *** Review the OrphanedSID=True rows in the report.  ***"
    }

    Write-RunHistory -ActionName "Check" -Status "Completed" `
        -Notes "ItemsScanned: $CheckCount | OrphanedSIDs: $OrphanCount"
}

# --------------------------------------------------
# DRYRUN
# Simulates the Remove action. No changes made.
# Streaming pipeline -- no full tree in memory.
# --------------------------------------------------
elseif ($Action -eq "DryRun") {

    Write-Host "Starting DryRun..."
    Write-Host "No changes will be made."
    Write-Host ""

    $WouldRemoveCount   = 0
    $InheritedSkipCount = 0
    $OrphanDryRunCount  = 0
    $ScannedCount       = 0
    $FirstRow           = $true

    & {
        $RootItem = Get-RootItem -Path $SourcePath
        if ($null -ne $RootItem) { $RootItem }
        Get-ChildItem $SourcePath -Recurse -Force -ErrorAction SilentlyContinue
    } | ForEach-Object {

        $Item = $_
        $ScannedCount++

        if ($ScannedCount % 500 -eq 0) {
            Write-Progress -Activity "DryRun" `
                -Status "Items scanned: $ScannedCount | Would remove: $WouldRemoveCount ACE(s)" `
                -CurrentOperation $Item.FullName
        }

        try {
            $Acl = Get-Acl $Item.FullName

            $ToRemove = $Acl.Access | Where-Object {
                ($RemoveGroups -contains $_.IdentityReference.Value) -and (-not $_.IsInherited)
            }

            $ToSkip = $Acl.Access | Where-Object {
                ($RemoveGroups -contains $_.IdentityReference.Value) -and $_.IsInherited
            }

            foreach ($Skipped in $ToSkip) {
                $InheritedSkipCount++
                $IsOrphanedSID = Test-IsOrphanedSID -Identity $Skipped.IdentityReference.Value
                if ($IsOrphanedSID) { $OrphanDryRunCount++ }

                $Row = [PSCustomObject]@{
                    Path        = $Item.FullName
                    Identity    = $Skipped.IdentityReference.Value
                    Rights      = $Skipped.FileSystemRights
                    IsInherited = $Skipped.IsInherited
                    ItemType    = if ($Item.PSIsContainer) { "Folder" } else { "File" }
                    Action      = "Inherited - Cannot Remove"
                    OrphanedSID = $IsOrphanedSID
                    Reason      = "ACE for '$($Skipped.IdentityReference.Value)' is inherited from an ancestor. Cannot remove directly -- it will auto-clean once the explicit ACE on the ancestor folder is removed by the Remove action."
                }
                if ($FirstRow) { $Row | Export-Csv $DryRunReport -NoTypeInformation -Encoding UTF8; $FirstRow = $false }
                else           { $Row | Export-Csv $DryRunReport -NoTypeInformation -Encoding UTF8 -Append }
            }

            foreach ($Rule in $ToRemove) {
                $WouldRemoveCount++
                $IsOrphanedSID = Test-IsOrphanedSID -Identity $Rule.IdentityReference.Value
                if ($IsOrphanedSID) { $OrphanDryRunCount++ }

                $Row = [PSCustomObject]@{
                    Path        = $Item.FullName
                    Identity    = $Rule.IdentityReference.Value
                    Rights      = $Rule.FileSystemRights
                    IsInherited = $Rule.IsInherited
                    ItemType    = if ($Item.PSIsContainer) { "Folder" } else { "File" }
                    Action      = "Would Be Removed"
                    OrphanedSID = $IsOrphanedSID
                    Reason      = "Explicit ACE for '$($Rule.IdentityReference.Value)' matches the RemoveGroups list. This $(if ($Item.PSIsContainer) { 'folder' } else { 'file' }) has a direct (non-inherited) permission entry that will be removed by the Remove action."
                }
                if ($FirstRow) { $Row | Export-Csv $DryRunReport -NoTypeInformation -Encoding UTF8; $FirstRow = $false }
                else           { $Row | Export-Csv $DryRunReport -NoTypeInformation -Encoding UTF8 -Append }
            }
        }
        catch {
            "DryRun error on '$($Item.FullName)': $_" | Out-File $ErrorFile -Append
        }
    }

    Write-Progress -Activity "DryRun" -Completed

    Write-Host ""
    Write-Host "==============================="
    Write-Host " DryRun Summary"
    Write-Host "==============================="
    Write-Host " Items scanned      : $ScannedCount"
    Write-Host " Would remove       : $WouldRemoveCount explicit ACE(s)"
    Write-Host " Inherited (skipped): $InheritedSkipCount ACE(s) -- auto-clean when ancestor explicit ACE is removed"
    if ($OrphanDryRunCount -gt 0) {
        Write-Host " Orphaned SIDs      : $OrphanDryRunCount -- review OrphanedSID=True rows in report"
    }
    Write-Host "==============================="

    if (Test-Path $DryRunReport) {
        Write-Host ""
        Write-Host "DryRun completed."
        Write-Host "Report : $DryRunReport"
        Write-Host "         (includes both 'Would Be Removed' and 'Inherited - Cannot Remove' rows)"
        Write-Host "         (Reason column explains why each ACE can or cannot be removed)"
        if ($OrphanDryRunCount -gt 0) {
            Write-Host ""
            Write-Host "  *** WARNING: $OrphanDryRunCount orphaned SID(s) detected. ***"
            Write-Host "  *** Review the OrphanedSID=True rows in the report.        ***"
        }
    }
    else {
        Write-Host ""
        Write-Host "DryRun completed. No matching ACL entries found."
    }

    Write-RunHistory -ActionName "DryRun" -Status "Completed" `
        -Notes "Scanned: $ScannedCount | WouldRemove: $WouldRemoveCount | InheritedSkipped: $InheritedSkipCount | OrphanedSIDs: $OrphanDryRunCount"
}

# --------------------------------------------------
# BACKUP
# Saves current ACL using icacls /save.
# --------------------------------------------------
elseif ($Action -eq "Backup") {

    $Result = Take-Backup

    "Backup result: $(if ($Result -eq 0) { 'SUCCESS' } else { 'FAILED' }) | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" |
        Out-File $ErrorFile -Append

    Write-Host ""
    if ($Result -eq 0) {
        Write-Host "==============================="
        Write-Host " Backup completed successfully"
        Write-Host "==============================="
        Write-Host " Backup file  : $BackupFile"
        Write-Host " Metadata     : $MetadataFile"
        Write-Host " Log          : $ErrorFile"
        Write-Host ""
        Write-Host " To restore from this backup, set:"
        Write-Host "   `$Action            = `"Restore`""
        Write-Host "   `$RestoreFolderPath = `"$RunFolder`""
        Write-Host "==============================="
        Write-RunHistory -ActionName "Backup" -Status "Success" -Notes "Backup: $BackupFile"
    }
    else {
        Write-Host "==============================="
        Write-Host " Backup FAILED"
        Write-Host " Review log: $ErrorFile"
        Write-Host "==============================="
        Write-RunHistory -ActionName "Backup" -Status "FAILED" -Notes "Review: $ErrorFile"
    }
}

# --------------------------------------------------
# REMOVE
# Step 1: Takes a backup (aborts if backup fails).
# Step 2: SINGLE-PASS scan -- streams the tree once.
#         Collects matching ACEs. No second scan.
# Step 3: WhatIf summary + Y/N confirmation.
# Step 4: Removal loop using already-collected data.
# Step 5: Before/After icacls snapshots.
# Step 6: Removal report -- CSV + TXT.
# --------------------------------------------------
elseif ($Action -eq "Remove") {

    Write-Host "Starting pre-removal backup..."

    $Result = Take-Backup

    if ($Result -ne 0) {
        Write-Host ""
        Write-Host "ERROR: Backup failed. Remove aborted for safety."
        Write-Host "Review log: $ErrorFile"
        Write-RunHistory -ActionName "Remove" -Status "ABORTED -- Backup failed" -Notes "Review: $ErrorFile"
        return
    }

    # Before snapshot -- captured right after backup, before any ACE is touched
    Write-Host ""
    Write-Host "Capturing Before snapshot..."
    $BeforeParent = Split-Path $SourcePath -Parent
    $BeforeLeaf   = Split-Path $SourcePath -Leaf
    Push-Location $BeforeParent
    try {
        $BeforeOutput = & icacls $BeforeLeaf /save $RemoveBeforeSnapshotFile /t /c 2>&1
        $BeforeExit   = $LASTEXITCODE
        $BeforeOutput | Out-File "$RemoveBeforeSnapshotFile.log" -Append -Encoding UTF8
        "Before-Remove snapshot exit code: $BeforeExit" | Out-File $ErrorFile -Append
        if ($BeforeExit -ne 0) { $BeforeOutput | Out-File $ErrorFile -Append }
    }
    finally { Pop-Location }
    Write-Host "Before snapshot saved: $RemoveBeforeSnapshotFile"
    Write-Host ""

    # Single-pass scan
    Write-Host "Scanning ACLs..."

    $MatchList             = [System.Collections.Generic.List[PSCustomObject]]::new()
    $ScanCount             = 0
    $WhatIfTotal           = 0
    $TotalInheritedSkipped = 0
    $WhatIfFolderPaths     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $WhatIfFilePaths       = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    & {
        $RootItem = Get-RootItem -Path $SourcePath
        if ($null -ne $RootItem) { $RootItem }
        Get-ChildItem $SourcePath -Recurse -Force -ErrorAction SilentlyContinue
    } | ForEach-Object {

        $Item = $_
        $ScanCount++

        if ($ScanCount % 500 -eq 0) {
            Write-Progress -Activity "Scanning" `
                -Status "Items scanned: $ScanCount | Matching ACEs found: $WhatIfTotal" `
                -CurrentOperation $Item.FullName
        }

        try {
            $Acl = Get-Acl $Item.FullName

            $InheritedSkipped      = $Acl.Access | Where-Object {
                ($RemoveGroups -contains $_.IdentityReference.Value) -and $_.IsInherited
            }
            $TotalInheritedSkipped += @($InheritedSkipped).Count

            $RulesToRemove = $Acl.Access | Where-Object {
                ($RemoveGroups -contains $_.IdentityReference.Value) -and (-not $_.IsInherited)
            }

            if (@($RulesToRemove).Count -gt 0) {
                $WhatIfTotal += @($RulesToRemove).Count
                if ($Item.PSIsContainer) { $WhatIfFolderPaths.Add($Item.FullName) | Out-Null }
                else                     { $WhatIfFilePaths.Add($Item.FullName)   | Out-Null }

                $MatchList.Add([PSCustomObject]@{
                    FullName      = $Item.FullName
                    IsContainer   = $Item.PSIsContainer
                    AclObject     = $Acl
                    RulesToRemove = @($RulesToRemove)
                })
            }
        }
        catch {
            "Scan error on '$($Item.FullName)': $_" | Out-File $ErrorFile -Append
        }
    }

    Write-Progress -Activity "Scanning" -Completed

    $WhatIfFolders = $WhatIfFolderPaths.Count
    $WhatIfFiles   = $WhatIfFilePaths.Count

    Write-Host ""
    Write-Host "==============================="
    Write-Host " Remove -- WhatIf Preview"
    Write-Host "==============================="
    Write-Host " Source          : $SourcePath"
    Write-Host " Items scanned   : $ScanCount"
    Write-Host " Folders affected: $WhatIfFolders"
    Write-Host " Files affected  : $WhatIfFiles"
    Write-Host " Total ACEs      : $WhatIfTotal explicit ACE(s) will be removed"
    Write-Host " Groups targeted : $($RemoveGroups -join ', ')"
    Write-Host "==============================="

    if ($WhatIfTotal -eq 0) {
        Write-Host ""
        Write-Host "No explicit ACEs matching RemoveGroups found. Nothing to remove."
        Write-RunHistory -ActionName "Remove" -Status "Completed -- Nothing to remove" `
            -Notes "Scanned: $ScanCount | No matching explicit ACEs found"
        return
    }

    Write-Host ""
    $Confirm = Read-Host "Proceed with removal? Type Y to confirm, N to cancel"
    if ($Confirm -notmatch "^[Yy]$") {
        Write-Host ""
        Write-Host "Remove cancelled by user."
        Write-RunHistory -ActionName "Remove" -Status "Cancelled by user" `
            -Notes "WhatIf: $WhatIfTotal ACEs | Folders: $WhatIfFolders | Files: $WhatIfFiles"
        return
    }

    Write-Host ""
    Write-Host "Confirmed. Proceeding with Remove..."
    Write-Host ""

    # Removal loop
    $RemovedCount      = 0
    $ErrorCount        = 0
    $ModifiedItemCount = 0
    $ProcessedCount    = 0
    $RemovedACERecords = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($Match in $MatchList) {

        $ProcessedCount++

        if ($ProcessedCount % 500 -eq 0) {
            Write-Progress -Activity "Removing ACEs" `
                -Status "Items processed: $ProcessedCount of $($MatchList.Count) | ACEs removed: $RemovedCount" `
                -PercentComplete ([math]::Min(100,[int](($ProcessedCount / $MatchList.Count) * 100)))
        }

        try {
            $Acl      = $Match.AclObject
            $Modified = $false

            foreach ($Rule in $Match.RulesToRemove) {
                "  Removing '$($Rule.IdentityReference.Value)' from '$($Match.FullName)'" |
                    Out-File $ErrorFile -Append
                $Acl.RemoveAccessRule($Rule) | Out-Null
                $Modified = $true
                $RemovedCount++

                $RemovedACERecords.Add([PSCustomObject]@{
                    RemovedAt         = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    Path              = $Match.FullName
                    ItemType          = if ($Match.IsContainer) { "Folder" } else { "File" }
                    Identity          = $Rule.IdentityReference.Value
                    Rights            = $Rule.FileSystemRights
                    AccessControlType = $Rule.AccessControlType
                    IsInherited       = $Rule.IsInherited
                    Note              = "Explicit ACE removed. Restore using: $RunFolder"
                })
            }

            if ($Modified) {
                $SetAclOk = Set-AclWithRetry -Path $Match.FullName -AclObject $Acl
                if ($SetAclOk) { $ModifiedItemCount++ } else { $ErrorCount++ }
            }
        }
        catch {
            $ErrorCount++
            "Remove error on '$($Match.FullName)': $_" | Out-File $ErrorFile -Append
        }
    }

    Write-Progress -Activity "Removing ACEs" -Completed
    Write-Host "Removal complete. ACEs removed: $RemovedCount across $ModifiedItemCount item(s)."

    # After snapshot
    Write-Host ""
    Write-Host "Capturing After snapshot..."
    Push-Location $BeforeParent
    try {
        $AfterOutput = & icacls $BeforeLeaf /save $RemoveAfterSnapshotFile /t /c 2>&1
        $AfterExit   = $LASTEXITCODE
        $AfterOutput | Out-File "$RemoveAfterSnapshotFile.log" -Append -Encoding UTF8
        "After-Remove snapshot exit code: $AfterExit" | Out-File $ErrorFile -Append
        if ($AfterExit -ne 0) { $AfterOutput | Out-File $ErrorFile -Append }
    }
    finally { Pop-Location }
    Write-Host "After snapshot saved: $RemoveAfterSnapshotFile"

    # Post-removal report
    $RemovedFolderCount = ($RemovedACERecords | Where-Object { $_.ItemType -eq "Folder" } |
        Select-Object -ExpandProperty Path -Unique).Count
    $RemovedFileCount   = ($RemovedACERecords | Where-Object { $_.ItemType -eq "File" } |
        Select-Object -ExpandProperty Path -Unique).Count

    if ($RemovedACERecords.Count -gt 0) {

        $FirstRow = $true
        foreach ($Rec in $RemovedACERecords) {
            if ($FirstRow) { $Rec | Export-Csv $RemoveReportCSV -NoTypeInformation -Encoding UTF8; $FirstRow = $false }
            else           { $Rec | Export-Csv $RemoveReportCSV -NoTypeInformation -Encoding UTF8 -Append }
        }

        @(
            [PSCustomObject]@{ RemovedAt=""; Path=""; ItemType="SUMMARY"; Identity="Folders rectified";    Rights=$RemovedFolderCount; AccessControlType=""; IsInherited=""; Note="" },
            [PSCustomObject]@{ RemovedAt=""; Path=""; ItemType="SUMMARY"; Identity="Files rectified";      Rights=$RemovedFileCount;   AccessControlType=""; IsInherited=""; Note="" },
            [PSCustomObject]@{ RemovedAt=""; Path=""; ItemType="SUMMARY"; Identity="Total ACEs removed";   Rights=$RemovedCount;       AccessControlType=""; IsInherited=""; Note="" },
            [PSCustomObject]@{ RemovedAt=""; Path=""; ItemType="SUMMARY"; Identity="Total items modified"; Rights=$ModifiedItemCount;  AccessControlType=""; IsInherited=""; Note="" }
        ) | Export-Csv $RemoveReportCSV -NoTypeInformation -Encoding UTF8 -Append

        $TxtLines = [System.Collections.Generic.List[string]]::new()
        $TxtLines.Add("=============================================================")
        $TxtLines.Add(" ACL Manager v6.0 -- Post-Removal Report")
        $TxtLines.Add(" Generated  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        $TxtLines.Add(" Host       : $RunnerHost")
        $TxtLines.Add(" Run As     : $RunnerAccount")
        $TxtLines.Add(" Source     : $SourcePath")
        $TxtLines.Add(" Run Folder : $RunFolder")
        $TxtLines.Add("=============================================================")
        $TxtLines.Add(" SNAPSHOT FILES")
        $TxtLines.Add("   Before removal : $RemoveBeforeSnapshotFile")
        $TxtLines.Add("   After removal  : $RemoveAfterSnapshotFile")
        $TxtLines.Add("=============================================================")
        $TxtLines.Add(" SUMMARY")
        $TxtLines.Add("   Folders rectified      : $RemovedFolderCount")
        $TxtLines.Add("   Files rectified        : $RemovedFileCount")
        $TxtLines.Add("   Total ACEs removed     : $RemovedCount")
        $TxtLines.Add("   Total items modified   : $ModifiedItemCount")
        $TxtLines.Add("   Inherited ACEs skipped : $TotalInheritedSkipped (auto-cleaned by inheritance)")
        $TxtLines.Add("   Errors                 : $ErrorCount")
        $TxtLines.Add("=============================================================")
        $TxtLines.Add(" NOTE: To restore, set:")
        $TxtLines.Add("   `$Action            = `"Restore`"")
        $TxtLines.Add("   `$RestoreFolderPath = `"$RunFolder`"")
        $TxtLines.Add("=============================================================")
        $TxtLines.Add("")
        $TxtLines.Add(" DETAIL -- All removed ACEs")
        $TxtLines.Add("=============================================================")
        $TxtLines.Add("")
        $Idx = 1
        foreach ($Rec in $RemovedACERecords) {
            $TxtLines.Add("--- Entry $Idx ---")
            $TxtLines.Add("  Removed At   : $($Rec.RemovedAt)")
            $TxtLines.Add("  Path         : $($Rec.Path)")
            $TxtLines.Add("  Item Type    : $($Rec.ItemType)")
            $TxtLines.Add("  Identity     : $($Rec.Identity)")
            $TxtLines.Add("  Rights       : $($Rec.Rights)")
            $TxtLines.Add("  ACE Type     : $($Rec.AccessControlType)")
            $TxtLines.Add("  Was Inherited: $($Rec.IsInherited)")
            $TxtLines.Add("")
            $Idx++
        }
        $TxtLines.Add("=============================================================")
        $TxtLines.Add(" End of Report")
        $TxtLines.Add("=============================================================")
        $TxtLines | Out-File $RemoveReportTXT -Force -Encoding UTF8
    }

    Write-Host ""
    Write-Host "==============================="
    Write-Host " Remove Summary"
    Write-Host "==============================="
    Write-Host " Items scanned          : $ScanCount"
    Write-Host " Folders rectified      : $RemovedFolderCount"
    Write-Host " Files rectified        : $RemovedFileCount"
    Write-Host " Total items modified   : $ModifiedItemCount"
    Write-Host " Total ACEs removed     : $RemovedCount"
    Write-Host " Inherited ACEs skipped : $TotalInheritedSkipped (auto-cleaned by inheritance)"
    Write-Host " Errors                 : $ErrorCount"
    Write-Host "==============================="
    Write-Host " Backup file          : $BackupFile"
    Write-Host " Before snapshot      : $RemoveBeforeSnapshotFile"
    Write-Host " After snapshot       : $RemoveAfterSnapshotFile"
    Write-Host " Log                  : $ErrorFile"
    if ($RemovedACERecords.Count -gt 0) {
        Write-Host " Removal report (CSV) : $RemoveReportCSV"
        Write-Host " Removal report (TXT) : $RemoveReportTXT"
    }
    Write-Host ""
    Write-Host " To restore from this backup, set:"
    Write-Host "   `$Action            = `"Restore`""
    Write-Host "   `$RestoreFolderPath = `"$RunFolder`""
    Write-Host "==============================="

    $RemoveStatus = if ($ErrorCount -eq 0) { "Success" } else { "Completed with $ErrorCount error(s)" }
    Write-RunHistory -ActionName "Remove" -Status $RemoveStatus `
        -ItemsModified $ModifiedItemCount -ACEsChanged $RemovedCount -Errors $ErrorCount `
        -Notes "Scanned: $ScanCount | Folders: $RemovedFolderCount | Files: $RemovedFileCount | InheritedSkipped: $TotalInheritedSkipped"

    if ($ErrorCount -eq 0) { Write-Host ""; Write-Host "Remove completed successfully." }
    else                   { Write-Host ""; Write-Host "Remove completed WITH ERRORS. Please review: $ErrorFile" }
}

# --------------------------------------------------
# RESTORE
# Restores ACL from a Backup_ or Remove_ folder.
#
# RestoreDryRun mode ($RestoreDryRun = $true):
#   Reads backup file, lists what would be restored.
#   No changes made.
#
# Normal mode:
#   Step 1: Before snapshot.
#   Step 2: icacls . /restore <file> /c
#   Step 3: After snapshot.
#   Step 4: Restore report -- CSV + TXT.
#
# KEY FIX -- pipe-char safe file/folder detection:
#   Uses Get-ItemKind (regex) instead of GetExtension()
#   which crashes on filenames containing | characters.
#
# KEY FIX -- icacls /restore syntax:
#   Uses "." as the path argument (current dir = ParentPath).
#   Does NOT pass $LeafName -- it is already inside the
#   backup file. Passing it again causes path doubling.
# --------------------------------------------------
elseif ($Action -eq "Restore") {

    $RestoreBackupFile   = Join-Path $RestoreFolderPath "Backup_ICACLS\ACL_Backup.txt"
    $RestoreMetadataFile = Join-Path $RestoreFolderPath "Metadata\SourcePath.txt"

    if (!(Test-Path $RestoreBackupFile)) {
        Write-Host "ERROR: Backup file not found: $RestoreBackupFile"
        Write-Host "Make sure RestoreFolderPath points to a Backup_ or Remove_ folder."
        return
    }
    if (!(Test-Path $RestoreMetadataFile)) {
        Write-Host "ERROR: Metadata file not found: $RestoreMetadataFile"
        Write-Host "Make sure RestoreFolderPath points to a Backup_ or Remove_ folder."
        return
    }

    try {
        $OriginalSourcePath = (Get-Content $RestoreMetadataFile -Encoding UTF8).Trim()

        Write-Host "Restore target    : $OriginalSourcePath"
        Write-Host "Restoring from    : $RestoreBackupFile"
        if ($RestoreDryRun) {
            Write-Host ""
            Write-Host "  *** RESTORE DRYRUN MODE -- no changes will be made ***"
        }
        Write-Host ""

        if (!(Test-Path $OriginalSourcePath)) {
            Write-Host "ERROR: Original source path no longer exists: $OriginalSourcePath"
            return
        }

        $ParentPath = Split-Path $OriginalSourcePath -Parent
        $LeafName   = Split-Path $OriginalSourcePath -Leaf

        Write-Host "Working directory : $ParentPath"
        Write-Host "Leaf name         : $LeafName"
        Write-Host ""

        $BackupFileInfo = Get-Item $RestoreBackupFile -ErrorAction SilentlyContinue
        if ($null -eq $BackupFileInfo -or $BackupFileInfo.Length -eq 0) {
            Write-Host "ERROR: Backup file is missing or empty: $RestoreBackupFile"
            "ERROR: Backup file missing or empty." | Out-File $ErrorFile -Append
            return
        }

        # --------------------------------------------------
        # RESTORE DRYRUN MODE
        # --------------------------------------------------
        if ($RestoreDryRun) {

            Write-Host "Reading backup file to preview restore targets..."
            try {
                $BackupLines = Get-Content $RestoreBackupFile -Encoding OEM -ErrorAction Stop
            }
            catch {
                Write-Host "ERROR: Could not read backup file: $_"
                return
            }

            $PreviewRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
            foreach ($BLine in $BackupLines) {
                $BLine = $BLine.TrimEnd()
                if ($BLine -ne "" -and $BLine -notmatch "^\s") {
                    $AbsPath  = Join-Path $ParentPath $BLine
                    # Get-ItemKind uses regex -- safe for pipe chars in filenames
                    $ItemKind = Get-ItemKind -PathString $BLine
                    $PreviewRecords.Add([PSCustomObject]@{
                        Path     = $AbsPath
                        ItemType = $ItemKind
                        Status   = "Would Be Restored"
                        Note     = "RestoreDryRun=True -- no changes made"
                    })
                }
            }

            $PreviewFolders = ($PreviewRecords | Where-Object { $_.ItemType -eq "Folder" }).Count
            $PreviewFiles   = ($PreviewRecords | Where-Object { $_.ItemType -eq "File"   }).Count

            Write-Host ""
            Write-Host "==============================="
            Write-Host " Restore DryRun Preview"
            Write-Host "==============================="
            Write-Host " Folders that would be restored : $PreviewFolders"
            Write-Host " Files that would be restored   : $PreviewFiles"
            Write-Host " Total items                    : $($PreviewRecords.Count)"
            Write-Host "==============================="
            Write-Host " Backup file : $RestoreBackupFile"
            Write-Host " Source      : $OriginalSourcePath"
            Write-Host "==============================="
            Write-Host ""
            Write-Host " To perform the actual restore, set:"
            Write-Host "   `$RestoreDryRun = `$false"
            Write-Host "==============================="

            if ($PreviewRecords.Count -gt 0) {
                $FirstRow = $true
                foreach ($PR in $PreviewRecords) {
                    if ($FirstRow) { $PR | Export-Csv $RestoreReportCSV -NoTypeInformation -Encoding UTF8; $FirstRow = $false }
                    else           { $PR | Export-Csv $RestoreReportCSV -NoTypeInformation -Encoding UTF8 -Append }
                }
                Write-Host ""
                Write-Host " DryRun preview report : $RestoreReportCSV"
            }

            Write-RunHistory -ActionName "Restore-DryRun" -Status "Completed" `
                -Notes "WouldRestore: $($PreviewRecords.Count) | Folders: $PreviewFolders | Files: $PreviewFiles"
            return
        }

        # Before snapshot
        Write-Host "Capturing Before snapshot..."
        Push-Location $ParentPath
        try {
            $RestBeforeOut  = & icacls $LeafName /save $RestoreBeforeSnapshotFile /t /c 2>&1
            $RestBeforeExit = $LASTEXITCODE
            $RestBeforeOut | Out-File "$RestoreBeforeSnapshotFile.log" -Append -Encoding UTF8
            "Before-Restore snapshot exit code: $RestBeforeExit" | Out-File $ErrorFile -Append
            if ($RestBeforeExit -ne 0) { $RestBeforeOut | Out-File $ErrorFile -Append }
        }
        finally { Pop-Location }
        Write-Host "Before snapshot saved: $RestoreBeforeSnapshotFile"
        Write-Host ""

        "=== Restore started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ===" | Out-File $ErrorFile -Append
        "=== Original source : $OriginalSourcePath ==="                        | Out-File $ErrorFile -Append
        "=== Parent path     : $ParentPath ==="                                | Out-File $ErrorFile -Append
        "=== Leaf name       : $LeafName ==="                                  | Out-File $ErrorFile -Append
        "=== Backup file     : $RestoreBackupFile ==="                         | Out-File $ErrorFile -Append
        "=== Backup size     : $($BackupFileInfo.Length) bytes ==="            | Out-File $ErrorFile -Append

        "=== Backup preview (first 5 lines) ===" | Out-File $ErrorFile -Append
        try {
            Get-Content $RestoreBackupFile -Encoding OEM -TotalCount 5 -ErrorAction Stop |
    ForEach-Object { "  $_" } | Out-File $ErrorFile -Append
        }
        catch { "  (Could not read preview: $_)" | Out-File $ErrorFile -Append }

        Push-Location $ParentPath
        try {
            # "." = current directory = ParentPath after Push-Location.
            # LeafName is embedded in the backup file -- do NOT pass it here.
            "=== icacls restore command ===" | Out-File $ErrorFile -Append
            "  icacls . /restore `"$RestoreBackupFile`" /c  (working dir: $ParentPath)" |
                Out-File $ErrorFile -Append

            $IcaclsArgs = @(".", "/restore", $RestoreBackupFile, "/c")
            $Output     = & icacls @IcaclsArgs 2>&1
            $ExitCode   = $LASTEXITCODE
        }
        finally { Pop-Location }

        "=== icacls restore exit code: $ExitCode ===" | Out-File $ErrorFile -Append
        if ($ExitCode -ne 0) { $Output | Out-File $ErrorFile -Append }

        if ($ExitCode -eq 0) {

            Write-Host "Restore successful."
            Write-Host "Creating post-restore ACL snapshot..."

            Push-Location $ParentPath
            try {
                $SnapshotArgs  = @($LeafName, "/save", $RestoreAfterSnapshotFile, "/t", "/c")
                $AfterSnapOut  = & icacls @SnapshotArgs 2>&1
                $AfterSnapExit = $LASTEXITCODE
                $AfterSnapOut | Out-File "$RestoreAfterSnapshotFile.log" -Append -Encoding UTF8
                "After-Restore snapshot exit code: $AfterSnapExit" | Out-File $ErrorFile -Append
                if ($AfterSnapExit -ne 0) { $AfterSnapOut | Out-File $ErrorFile -Append }
                Copy-Item $RestoreAfterSnapshotFile $RestoreSnapshotFile -Force -ErrorAction SilentlyContinue
            }
            finally { Pop-Location }

            # Build restore records from icacls output
            # Uses Get-ItemKind (regex) -- safe for pipe chars in filenames
            $RestoreRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
            $RestoredAt     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

            foreach ($Line in $Output) {
                if ($Line -match "^processed file:\s+(.+)$") {
                    $RawPath  = $Matches[1].Trim()
                    $AbsPath  = Join-Path $ParentPath $RawPath
                    $ItemKind = Get-ItemKind -PathString $RawPath
                    $RestoreRecords.Add([PSCustomObject]@{
                        RestoredAt = $RestoredAt
                        Path       = $AbsPath
                        ItemType   = $ItemKind
                        Status     = "Rectified"
                        Note       = "ACL restored from: $RestoreBackupFile"
                    })
                }
            }

            $RestoreFolderCount = ($RestoreRecords | Where-Object { $_.ItemType -eq "Folder" }).Count
            $RestoreFileCount   = ($RestoreRecords | Where-Object { $_.ItemType -eq "File"   }).Count
            $RestoreTotalCount  = $RestoreRecords.Count

            if ($RestoreRecords.Count -gt 0) {

                $FirstRow = $true
                foreach ($RRec in $RestoreRecords) {
                    if ($FirstRow) { $RRec | Export-Csv $RestoreReportCSV -NoTypeInformation -Encoding UTF8; $FirstRow = $false }
                    else           { $RRec | Export-Csv $RestoreReportCSV -NoTypeInformation -Encoding UTF8 -Append }
                }

                @(
                    [PSCustomObject]@{ RestoredAt=""; Path=""; ItemType="SUMMARY"; Status="Folders rectified";    Note=$RestoreFolderCount },
                    [PSCustomObject]@{ RestoredAt=""; Path=""; ItemType="SUMMARY"; Status="Files rectified";      Note=$RestoreFileCount   },
                    [PSCustomObject]@{ RestoredAt=""; Path=""; ItemType="SUMMARY"; Status="Total items rectified";Note=$RestoreTotalCount  }
                ) | Export-Csv $RestoreReportCSV -NoTypeInformation -Encoding UTF8 -Append

                $RTxt = [System.Collections.Generic.List[string]]::new()
                $RTxt.Add("=============================================================")
                $RTxt.Add(" ACL Manager v6.0 -- Post-Restore Report")
                $RTxt.Add(" Generated    : $RestoredAt")
                $RTxt.Add(" Host         : $RunnerHost")
                $RTxt.Add(" Run As       : $RunnerAccount")
                $RTxt.Add(" Restored To  : $OriginalSourcePath")
                $RTxt.Add(" Backup Used  : $RestoreBackupFile")
                $RTxt.Add(" Run Folder   : $RunFolder")
                $RTxt.Add("=============================================================")
                $RTxt.Add(" SNAPSHOT FILES")
                $RTxt.Add("   Before restore : $RestoreBeforeSnapshotFile")
                $RTxt.Add("   After restore  : $RestoreAfterSnapshotFile")
                $RTxt.Add("=============================================================")
                $RTxt.Add(" SUMMARY")
                $RTxt.Add("   Folders rectified : $RestoreFolderCount")
                $RTxt.Add("   Files rectified   : $RestoreFileCount")
                $RTxt.Add("   Total rectified   : $RestoreTotalCount")
                $RTxt.Add("=============================================================")
                $RTxt.Add("")
                $RTxt.Add(" DETAIL -- All rectified items")
                $RTxt.Add("=============================================================")
                $RTxt.Add("")
                $RIdx = 1
                foreach ($RRec in $RestoreRecords) {
                    $RTxt.Add("--- Entry $RIdx ---")
                    $RTxt.Add("  Restored At : $($RRec.RestoredAt)")
                    $RTxt.Add("  Path        : $($RRec.Path)")
                    $RTxt.Add("  Item Type   : $($RRec.ItemType)")
                    $RTxt.Add("  Status      : $($RRec.Status)")
                    $RTxt.Add("")
                    $RIdx++
                }
                $RTxt.Add("=============================================================")
                $RTxt.Add(" End of Report")
                $RTxt.Add("=============================================================")
                $RTxt | Out-File $RestoreReportTXT -Force -Encoding UTF8
            }

            Write-Host ""
            Write-Host "==============================="
            Write-Host " Restore completed successfully"
            Write-Host "==============================="
            Write-Host " Restored to           : $OriginalSourcePath"
            Write-Host " Folders rectified     : $RestoreFolderCount"
            Write-Host " Files rectified       : $RestoreFileCount"
            Write-Host " Total items rectified : $RestoreTotalCount"
            Write-Host "==============================="
            Write-Host " Backup used           : $RestoreBackupFile"
            Write-Host " Before snapshot       : $RestoreBeforeSnapshotFile"
            Write-Host " After snapshot        : $RestoreAfterSnapshotFile"
            Write-Host " Log                   : $ErrorFile"
            if ($RestoreRecords.Count -gt 0) {
                Write-Host " Restore report (CSV)  : $RestoreReportCSV"
                Write-Host " Restore report (TXT)  : $RestoreReportTXT"
            }
            Write-Host "==============================="

            Write-RunHistory -ActionName "Restore" -Status "Success" `
                -ItemsModified $RestoreTotalCount `
                -Notes "Folders: $RestoreFolderCount | Files: $RestoreFileCount | Backup: $RestoreBackupFile"
        }
        else {
            Write-Host ""
            Write-Host "==============================="
            Write-Host " Restore FAILED (exit code: $ExitCode)"
            Write-Host " Review log: $ErrorFile"
            Write-Host "==============================="
            Write-RunHistory -ActionName "Restore" -Status "FAILED (exit $ExitCode)" -Notes "Review: $ErrorFile"
        }
    }
    catch {
        "Restore unexpected error: $_" | Out-File $ErrorFile -Append
        Write-Host ""
        Write-Host "ERROR: Restore failed unexpectedly."
        Write-Host "Review log: $ErrorFile"
        Write-RunHistory -ActionName "Restore" -Status "FAILED -- unexpected error" -Notes "Review: $ErrorFile"
    }
}

# ==========================================
# END
# ==========================================

Write-Host ""

if ($TranscriptMode -eq "On") {
    try { Stop-Transcript } catch {}
}