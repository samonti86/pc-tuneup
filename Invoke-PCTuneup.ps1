#Requires -Version 5.1

<#
.SYNOPSIS
    Routine maintenance for Windows 10 (1809+) and Windows 11.

.DESCRIPTION
    Runs a safe-by-default monthly maintenance routine: third-party app updates,
    OS updates, system-integrity repair (DISM -> SFC), disk health + optimization,
    cleanup, an event-log/health report, and a Defender pass.

    Design rules (see research/win-maintenance-script-spec.md in command-center):
      - Self-elevates via UAC, re-passing -ExecutionPolicy Bypass and original args.
      - Targets Windows PowerShell 5.1 (in-box on Win10 & Win11). No PS7-only syntax.
      - Feature-detects winget / Defender / battery instead of assuming they exist.
      - Every Get-WinEvent uses -ErrorAction SilentlyContinue (zero-match is a
        TERMINATING error otherwise and would abort the script).
      - Checks $LASTEXITCODE after native EXEs (sfc/DISM/chkdsk report failure there,
        not as exceptions).
      - Destructive actions are opt-in only; -DryRun previews without changing anything.
      - Transcript-logs every run and prints a summary report at the end.

.PARAMETER DryRun
    Preview every action without executing it. Read-only reporting still runs.

.PARAMETER ReportOnly
    Run only the read-only health checks (disk, events, startup, power, Defender
    status). No maintenance actions.

.PARAMETER SkipCleanup
    Skip temp-file and WinSxS component cleanup.

.PARAMETER FullScan
    Defender FullScan instead of the default QuickScan.

.PARAMETER DeepClean
    Adds chkdsk /f /r (schedules a reboot-time check) and DISM /ResetBase.
    /ResetBase blocks uninstalling already-installed updates -- use deliberately.

.PARAMETER FlushUpdateCache
    Stop wuauserv/bits, wipe SoftwareDistribution\Download, restart them.
    Use only when Windows Update is misbehaving.

.PARAMETER NetworkReset
    netsh winsock reset + netsh int ip reset. REQUIRES A REBOOT and can disrupt
    VPN/proxy config. Use only when the socket layer is corrupted.

.PARAMETER EventDays
    How many days of Event Viewer history the health analysis covers (default 7,
    range 1-365). Lower it (e.g. -EventDays 1) to focus on only the most recent issues.
    Each issue also shows first/last-seen timestamps and a "last 24h" count, so stale,
    already-resolved problems are easy to tell apart from active ones.

.PARAMETER EmptyRecycleBin
    Empty the Recycle Bin on all drives and report space reclaimed. Opt-in because it
    deletes user-recoverable data.

.PARAMETER ResetStore
    Clear the Microsoft Store cache (wsreset). Opt-in; useful for Store/UWP update
    errors (e.g. 0x80073D02). Note: wsreset opens the Store window when it finishes.

.PARAMETER OptimizeAllDrives
    Optimize EVERY fixed drive in step 5, not just the system drive. Opt-in because a
    defrag pass on a large spinning data drive can run for HOURS and would dominate a
    routine that otherwise finishes in minutes. Non-system drives are reported as
    Skipped without this switch, never silently ignored.

.PARAMETER RepairIssues
    Attempt the SAFE auto-repairs the health analysis flags. In practice that means a
    targeted winget repair (falling back to upgrade) of crashing apps it can map to a
    single package -- the one category with a safe, generic automated fix. Skips
    anything it can't confidently map. Everything else in the analysis is recommendation
    only (by design: most event-log issues have no safe automated repair). The Event
    Viewer analysis itself is always-on and read-only; only the repair is gated by this.
    (Alias: -RepairCrashLoops, kept for compatibility.)

.PARAMETER Relaunched
    INTERNAL. Set automatically when the script relaunches itself through UAC; it only
    makes the new elevated window pause before closing so you can read the report.
    Don't pass it by hand -- an already-elevated or scheduled run must never pause.

.EXAMPLE
    .\Invoke-PCTuneup.ps1
    Run the safe monthly routine (self-elevates).

.EXAMPLE
    .\Invoke-PCTuneup.ps1 -DryRun
    Show exactly what would run, change nothing.

.EXAMPLE
    .\Invoke-PCTuneup.ps1 -ReportOnly
    Health/event/disk report only.
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$ReportOnly,
    [switch]$SkipCleanup,
    [switch]$FullScan,
    [switch]$DeepClean,
    [switch]$FlushUpdateCache,
    [switch]$NetworkReset,
    [Alias('RepairCrashLoops')]
    [switch]$RepairIssues,
    [switch]$EmptyRecycleBin,
    [switch]$ResetStore,
    [switch]$OptimizeAllDrives,
    [ValidateRange(1, 365)]
    [int]$EventDays = 7,
    # INTERNAL -- set automatically by the UAC relaunch below, not meant to be passed
    # by hand. It only makes the elevated window pause before closing so the report is
    # readable; an already-elevated or scheduled run never sets it and never pauses.
    [switch]$Relaunched
)

# ---------------------------------------------------------------------------
# 0. Self-elevation
#    UAC is the Windows analogue of `sudo`. If we're not admin, relaunch the
#    same script elevated, re-passing -ExecutionPolicy Bypass (so policy doesn't
#    block the child) and the original switches (so -DryRun/-DeepClean survive).
# ---------------------------------------------------------------------------
function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "Administrator rights required -- relaunching via UAC..." -ForegroundColor Yellow
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-Relaunched')
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        # -Relaunched is added above; never forward it twice (PowerShell rejects a
        # parameter specified more than once).
        if ($kv.Key -eq 'Relaunched') { continue }
        if ($kv.Value -is [switch]) {
            # Switches forward as a bare -Name, and only when actually present.
            if ($kv.Value.IsPresent) { $argList += "-$($kv.Key)" }
        } else {
            # VALUE-carrying params (e.g. -EventDays 1) must forward their value too.
            # Forwarding only the switches silently dropped these across the UAC hop,
            # so the elevated child quietly fell back to the default -- the worst kind
            # of bug: no error, just the wrong behaviour.
            $argList += "-$($kv.Key)"
            $val = "$($kv.Value)"
            $argList += $(if ($val -match '\s') { "`"$val`"" } else { $val })
        }
    }
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
    } catch {
        Write-Error "Elevation cancelled or failed. Re-run from an elevated PowerShell."
    }
    return
}

# ---------------------------------------------------------------------------
# 1. Setup: dry-run flag, results ledger, transcript
# ---------------------------------------------------------------------------
$script:DryRun  = [bool]$DryRun
$script:Results = New-Object System.Collections.Generic.List[object]

# Windows is NOT always installed on C: (imaged corporate builds, dual-boot layouts,
# and recovery-partition oddities all move it). Derive the system drive ONCE here and
# use it everywhere instead of hardcoding 'C'. $env:SystemDrive is authoritative and,
# unlike Get-Volume, needs no WMI -- so it still works on a box whose Storage provider
# is broken. Two forms because callers want both: 'C' for -DriveLetter params, 'C:' for
# native tools like chkdsk/chkntfs.
$script:SysDriveLetter = "$env:SystemDrive".TrimEnd(':')
$script:SysDrive       = "$($script:SysDriveLetter):"

# Did the Event Viewer sweep actually COMPLETE? Load-bearing: if Find-EventIssues throws,
# $script:Issues stays empty, and an empty issue list is indistinguishable from a genuinely
# healthy machine -- so the health report cheerfully printed "Clean". A failed scan must
# never render as a clean bill of health. Set $true only on a completed sweep.
$script:EventScanOk = $false

$script:RunStamp = Get-Date -Format 'yyyy-MM-dd-HHmmss'
$script:LogDir   = Join-Path $env:USERPROFILE 'pc-tuneup-logs'
if (-not (Test-Path $script:LogDir)) { New-Item -ItemType Directory -Path $script:LogDir -Force | Out-Null }

# Retention: keep only the most recent 30 of each artifact so the log dir doesn't
# grow without bound across monthly runs. Pruned BEFORE this run's files are created.
foreach ($pat in 'tuneup-*.log', 'energy-report-*.html', 'battery-report-*.html') {
    Get-ChildItem $script:LogDir -Filter $pat -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -Skip 30 |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

$logFile = Join-Path $script:LogDir "tuneup-$($script:RunStamp).log"
# Only stop a transcript we actually started. If the CALLER already had one running,
# Start-Transcript errors here -- and an unconditional Stop-Transcript in the finally
# block would then tear down THEIR transcript instead of ours.
$script:TranscriptStarted = $false
try {
    Start-Transcript -Path $logFile -ErrorAction Stop | Out-Null
    $script:TranscriptStarted = $true
} catch {
    Write-Warning "Could not start the transcript log ($logFile): $(($_.Exception.Message -split "`r?`n")[0])"
    Write-Warning "Continuing WITHOUT a log file -- console output only."
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Add-Result {
    param([string]$Step, [string]$Status, [string]$Detail = '')
    $script:Results.Add([pscustomobject]@{ Step = $Step; Status = $Status; Detail = $Detail })
}

function Test-CommandExists {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# Free space (GB) on a drive, or $null if it can't be read. Used to report how
# much cleanup actually reclaimed. Defaults to the SYSTEM drive, not a hardcoded 'C' --
# a stale 'C' default is exactly the trap this change exists to remove.
function Get-FreeSpaceGB {
    param([string]$Drive = $script:SysDriveLetter)
    try {
        $d = Get-PSDrive -Name $Drive -ErrorAction Stop
        return [math]::Round($d.Free / 1GB, 2)
    } catch { return $null }
}

# Gate any action behind -DryRun. Returns $true if the caller should proceed.
function Confirm-Action {
    param([string]$What)
    if ($script:DryRun) {
        Write-Host "  [DryRun] would: $What" -ForegroundColor DarkGray
        return $false
    }
    return $true
}

# Decode the common Win32/CLR exception codes a crash reports, so the report says
# WHY something died rather than just printing a raw hex code.
function Convert-ExceptionCode {
    param($Code)
    if ($null -eq $Code -or "$Code" -eq '') { return 'n/a' }
    $norm = ("$Code" -replace '^0x', '').ToUpper().Trim()
    $map = @{
        'E0434352' = '.NET/CLR exception'
        'C0000005' = 'access violation'
        'C0000409' = 'stack buffer overrun'
        'C00000FD' = 'stack overflow'
        'C0000374' = 'heap corruption'
        'C0000017' = 'out of memory'
        '80000003' = 'breakpoint'
    }
    if ($map.ContainsKey($norm)) { return "0x$norm ($($map[$norm]))" }
    return "0x$norm"
}

# Event-log insertion strings are NOT guaranteed to be short, single-line, or even an
# app name. A .NET app logging through Microsoft.Extensions.Logging writes its ENTIRE
# multi-line message -- stack traces included -- as property [0] under the shared
# '.NET Runtime' source. Collapse to one line and clip, so one noisy app can't dump 40
# lines of stack trace into the report body and the summary table.
function Format-EventToken {
    param([string]$Text, [int]$Max = 48)
    if (-not $Text) { return '' }
    $t = (($Text -replace '[\r\n\t]+', ' ') -replace '\s{2,}', ' ').Trim()
    if ($t.Length -gt $Max) { return $t.Substring(0, [Math]::Max(1, $Max - 3)) + '...' }
    return $t
}

# Guard for anything about to be treated as a FILE NAME. On Windows PowerShell 5.1
# (.NET Framework) [IO.Path]::GetFileNameWithoutExtension() THROWS "Illegal characters
# in path" on control chars / < > " |; .NET Core silently accepts them. That asymmetry
# is exactly why this class of bug survives PS7 testing and only detonates on 5.1 --
# the shipping target. GetInvalidFileNameChars() is a superset of what the API rejects,
# so this errs toward "not a file name" and the caller safely does nothing.
function Test-PlausibleFileName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name.Length -gt 128) { return $false }
    return ($Name.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -lt 0)
}

# Service Control Manager insertion strings put the service name at [0] -- EXCEPT on the
# two timeout events, where [0] is the timeout in MILLISECONDS and the service is at [1]:
#   7009  "A timeout was reached (%1 milliseconds) while waiting for the %2 service..."
#   7011  "A timeout (%1 ms) was reached while waiting for a transaction response from %2"
# Reading [0] blindly names the culprit "30000".
function Get-EventServiceName {
    param($EventRecord)
    $idx = if ($EventRecord.Id -eq 7009 -or $EventRecord.Id -eq 7011) { 1 } else { 0 }
    if ($EventRecord.Properties.Count -le $idx) { $idx = 0 }
    return [string]$EventRecord.Properties[$idx].Value
}

# Parse `winget list` text output by header-column offsets and return the single Id
# if exactly one package matched. Returns $null on zero/ambiguous/locale-mismatch --
# the caller treats $null as "don't touch anything" (safe by default).
function Get-WingetIdFromListing {
    param([string]$Raw)
    if (-not $Raw) { return $null }
    # @() is load-bearing: with a single surviving line the pipeline yields a bare
    # [string], and [array]::IndexOf() below would then choke on a non-array.
    $lines  = @($Raw -split "\r?\n" | Where-Object { $_ -and ($_ -notmatch '^[\s\-\\|/]+$') })
    $header = $lines | Where-Object { $_ -match '(^|\s)Id(\s|$)' -and $_ -match 'Version' } | Select-Object -First 1
    if (-not $header) { return $null }
    $idCol  = $header.IndexOf('Id')
    $verCol = $header.IndexOf('Version')
    if ($idCol -lt 0 -or $verCol -le $idCol) { return $null }
    $hIdx = [array]::IndexOf($lines, $header)
    if ($hIdx -lt 0 -or ($hIdx + 1) -ge $lines.Count) { return $null }
    $ids = foreach ($d in $lines[($hIdx + 1)..($lines.Count - 1)]) {
        if ($d.Length -gt $idCol) {
            $end = [Math]::Min($verCol, $d.Length)
            $field = $d.Substring($idCol, $end - $idCol).Trim()
            if ($field) { $field }
        }
    }
    $ids = @($ids | Where-Object { $_ } | Sort-Object -Unique)
    if ($ids.Count -eq 1) { return $ids[0] }
    return $null
}

# Map a faulting executable to its installed winget package Id. Prefers the
# structured Microsoft.WinGet.Client module (clean objects, locale-proof); falls
# back to parsing the winget CLI. Returns $null unless the match is unambiguous.
function Resolve-WingetId {
    param([string]$App, [string]$Path)
    $term = $null
    if ($Path -and (Test-Path $Path -ErrorAction SilentlyContinue)) {
        try { $term = (Get-Item $Path -ErrorAction Stop).VersionInfo.ProductName }
        catch { Write-Verbose "ProductName lookup failed for '$Path'; will fall back to the exe base name." }
    }
    if (-not $term) {
        # Only if $App actually looks like a file name -- see Test-PlausibleFileName.
        # A caller can hand us an arbitrary event-log string, and on 5.1 that throws.
        if (-not (Test-PlausibleFileName $App)) {
            Write-Verbose "Skipping '$(Format-EventToken $App)': not a plausible executable name."
            return $null
        }
        $term = [System.IO.Path]::GetFileNameWithoutExtension($App)
    }
    if (-not $term) { return $null }

    if (Test-CommandExists 'Get-WinGetPackage') {
        try {
            $ids = @(Get-WinGetPackage -ErrorAction Stop |
                Where-Object { $_.Name -like "*$term*" -or $_.Id -like "*$term*" } |
                ForEach-Object { $_.Id } | Sort-Object -Unique)
            if ($ids.Count -eq 1) { return $ids[0] }
            return $null
        } catch { Write-Verbose "Get-WinGetPackage query failed; falling back to the winget CLI." }
    }
    $out = (winget list --name $term --accept-source-agreements 2>$null | Out-String)
    return (Get-WingetIdFromListing -Raw $out)
}

# Translate a winget exit code that means "nothing to do here" into a human reason,
# or $null if the code is a genuine failure.
#
# Same false-failure family as DISM 3010, chkdsk exit 3, and the netsh ACL-locked key:
# a non-zero code that does NOT mean something broke. It matters most on the repair
# path, because a crashing app is very often ALREADY on the newest version -- so this
# is the COMMON outcome, not an edge case, and it was being reported as Failed.
#
# Codes measured directly (winget 1.x); the hex is the documented APPINSTALLER_CLI_ERROR:
#   0x8A15002B (-1978335189)  UPDATE_NOT_APPLICABLE  "No available upgrade found."
#   0x8A15007C (-1978335108)  "The installer technology in use does not support repair."
function Get-WingetNoOpReason {
    param([int]$Code)
    switch ($Code) {
        -1978335189 { return 'already at the latest version' }
        -1978335108 { return 'this package type does not support winget repair' }
        default     { return $null }
    }
}

# Run a native EXE and judge success by $LASTEXITCODE (these tools don't throw).
function Invoke-Native {
    param(
        [string]$Label,
        [string]$File,
        [string[]]$Arguments,
        [int[]]$SuccessCodes = @(0)
    )
    if (-not (Confirm-Action "$Label  ($File $($Arguments -join ' '))")) {
        Add-Result $Label 'DryRun'
        return
    }
    Write-Host "  > $File $($Arguments -join ' ')" -ForegroundColor DarkCyan
    & $File @Arguments
    $code = $LASTEXITCODE
    if ($SuccessCodes -contains $code) {
        # 3010 = ERROR_SUCCESS_REBOOT_REQUIRED. It means SUCCESS, pending a restart --
        # DISM returns it routinely. Callers opt into it via -SuccessCodes; label it
        # clearly so "exit 3010" never reads like a failure in the summary.
        if ($code -eq 3010) {
            Add-Result $Label 'OK' 'exit 3010 (success; reboot required to finish)'
            Write-Host "  Completed successfully, but a REBOOT is required to finish." -ForegroundColor Yellow
            return
        }
        Add-Result $Label 'OK' "exit $code"
    } else {
        Add-Result $Label 'Failed' "exit $code"
        Write-Warning "$Label returned exit code $code"
    }
}

# Run one pipeline step in isolation. A step that throws an UNHANDLED error is
# logged and recorded as Failed, but never aborts the remaining steps or the
# end-of-run summary. Without this, a single throw (e.g. Get-PhysicalDisk failing
# on odd hardware) would skip every later step AND the summary -- the worst outcome
# for a maintenance tool, since you'd lose the report of what did/didn't happen.
function Invoke-Step {
    param([string]$Name, [scriptblock]$Body)
    try {
        & $Body
    } catch {
        $msg = ($_.Exception.Message -split "`r?`n")[0]
        Write-Warning "Step '$Name' hit an unhandled error: $msg"
        Add-Result $Name 'Failed' "unhandled: $msg"
    }
}

# ===========================================================================
# ACTION STEPS  (skipped entirely when -ReportOnly)
# ===========================================================================

function New-RestoreCheckpoint {
    Write-Section "0. System Restore checkpoint"
    # Seatbelt: a rollback point that PRE-DATES every change below (app updates,
    # DISM/SFC, registry-touching cleanup). Conceptually like a ZFS/LVM snapshot
    # before a risky operation -- if something regresses, you roll back.
    #
    # Two real-world gotchas we tolerate rather than fail on:
    #   1. System Restore is OFF by default on many OEM/clean images. Checkpoint-
    #      Computer then throws -- we catch and tell the user how to enable it.
    #   2. Windows rate-limits restore points to one per 24h (governed by
    #      SystemRestorePointCreationFrequency). A second call inside that window
    #      is silently a no-op -- acceptable; the existing point still protects us.
    if (-not (Test-CommandExists 'Checkpoint-Computer')) {
        Add-Result 'Restore point' 'Skipped' 'Checkpoint-Computer unavailable'
        Write-Warning "Checkpoint-Computer not available -- skipping restore point."
        return
    }
    if (-not (Confirm-Action "create a System Restore checkpoint")) { Add-Result 'Restore point' 'DryRun'; return }
    try {
        Checkpoint-Computer -Description "pc-tuneup $(Get-Date -Format 'yyyy-MM-dd HH:mm')" `
            -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        Add-Result 'Restore point' 'OK'
        Write-Host "  Restore point created." -ForegroundColor Green
    } catch {
        Add-Result 'Restore point' 'Skipped' $_.Exception.Message
        Write-Warning "Could not create restore point: $($_.Exception.Message)"
        Write-Host "  (Enable once with: Enable-ComputerRestore -Drive '$($script:SysDrive)\')" -ForegroundColor DarkGray
    }
}

function Update-Apps {
    Write-Section "1. Third-party app updates (winget)"
    # winget is NOT guaranteed: Win10 1809+ only, absent on LTSC/debloated/pre-login.
    if (-not (Test-CommandExists 'winget')) {
        Write-Warning "winget not available on this machine -- skipping app updates."
        Add-Result 'App updates (winget)' 'Skipped' 'winget not installed'
        return
    }
    if (-not (Confirm-Action "winget upgrade --all")) { Add-Result 'App updates (winget)' 'DryRun'; return }
    # --include-unknown catches apps whose version winget can't parse (else skipped).
    # The --accept-* / --silent / --disable-interactivity flags keep it non-interactive.
    winget upgrade --all --include-unknown `
        --accept-source-agreements --accept-package-agreements `
        --silent --disable-interactivity
    # Don't claim success blindly: winget returns non-zero when some packages fail
    # to upgrade. Surface that as Partial rather than a false OK. (Exit 0 includes the
    # benign "nothing to upgrade" case, so that still reports OK.)
    $code = $LASTEXITCODE
    $noOp = Get-WingetNoOpReason $code
    if ($code -eq 0) {
        Add-Result 'App updates (winget)' 'OK'
    } elseif ($noOp) {
        # e.g. "No available upgrade found" -- nothing was pending. That is a clean run,
        # not a partial one.
        Add-Result 'App updates (winget)' 'OK' "nothing to upgrade ($noOp)"
    } else {
        Add-Result 'App updates (winget)' 'Partial' ("winget exit {0} (0x{0:X8})" -f $code)
        Write-Warning "winget upgrade --all returned exit $code -- one or more apps may not have updated."
    }
}

function Repair-Issues {
    Write-Section "1b. Safe auto-repair of detected issues"
    # Opt-in. Consumes the analysis done by Find-EventIssues (runs at startup). The ONLY
    # safe, generic automated repair is the winget app repair, so that's all this does;
    # every other issue category is recommendation-only (shown in the health report).
    if (-not $RepairIssues) {
        Write-Host "  Skipped -- opt-in. Re-run with -RepairIssues to attempt the safe auto-repairs." -ForegroundColor DarkGray
        Add-Result 'Issue repair' 'Skipped' 'not requested (-RepairIssues)'; return
    }
    $repairable = @($script:Issues | Where-Object { $_.AutoRepair -eq 'winget-app' -and $_.Apps })
    if (-not $repairable) {
        Add-Result 'Issue repair' 'Skipped' 'nothing safely auto-repairable'
        Write-Host "  Nothing safely auto-repairable -- see the health report for recommendations." -ForegroundColor DarkGray
        return
    }
    if (-not (Test-CommandExists 'winget')) {
        Add-Result 'Issue repair' 'Skipped' 'winget unavailable'
        Write-Warning "winget not available -- cannot auto-repair. See the health report for manual steps."
        return
    }
    # Several faulting exes can map to one package (e.g. a VPN client's helper +
    # notification service). Repair each package at most once per run.
    $seen = New-Object System.Collections.Generic.HashSet[string]
    foreach ($iss in $repairable) {
        foreach ($app in $iss.Apps) {
            $id = Resolve-WingetId -App $app.App -Path $app.Path
            if (-not $id) {
                Write-Host "  '$($app.App)': no confident winget match -- repair/reinstall it manually." -ForegroundColor Yellow
                Add-Result "Repair $($app.App)" 'Skipped' 'no confident winget match'
                continue
            }
            if (-not $seen.Add($id)) {
                Write-Host "  '$($app.App)' -> '$id' already handled this run; skipping duplicate." -ForegroundColor DarkGray
                continue
            }
            if (-not (Confirm-Action "winget repair --id $id  (fallback: upgrade)")) {
                Add-Result "Repair $($app.App)" 'DryRun' $id; continue
            }
            # 'repair' re-runs the installer's repair path; if the package doesn't
            # support it (non-zero exit), fall back to pulling the latest version,
            # which is the next-safest fix for an app-level bug.
            Write-Host "  Repairing $($app.App) -> winget package '$id'..." -ForegroundColor Cyan
            winget repair --id $id --silent --accept-source-agreements --disable-interactivity
            $code        = $LASTEXITCODE
            $repairNoOp  = Get-WingetNoOpReason $code
            if ($code -ne 0) {
                Write-Host "  repair unavailable/failed (exit $code); trying 'winget upgrade'..." -ForegroundColor DarkGray
                winget upgrade --id $id --include-unknown `
                    --accept-source-agreements --accept-package-agreements `
                    --silent --disable-interactivity
                $code = $LASTEXITCODE
            }
            $noOp = Get-WingetNoOpReason $code
            if ($code -eq 0) {
                Add-Result "Repair $($app.App)" 'OK' $id
            } elseif ($noOp) {
                # Nothing broke -- winget simply had nothing to apply. The usual shape is
                # "this package type can't be repaired" AND "it's already current", which
                # together mean the crash is not something winget can fix. Report that
                # plainly instead of a false Failed, and name BOTH reasons when we have them.
                $why = if ($repairNoOp -and $repairNoOp -ne $noOp) { "$repairNoOp; $noOp" } else { $noOp }
                Add-Result "Repair $($app.App)" 'Skipped' "$id -- $why"
                Write-Host "  '$id': $why -- winget has nothing to apply." -ForegroundColor Yellow
                Write-Host "    If it keeps crashing, reinstall it manually or check the app's own settings." -ForegroundColor DarkGray
            } else {
                Add-Result "Repair $($app.App)" 'Failed' "$id (exit $code)"
                Write-Warning "Repair of '$id' returned exit $code -- repair it manually."
            }
        }
    }
}

function Invoke-OSUpdate {
    Write-Section "2. Windows Update (OS patches)"
    # Reliable *scripted* install needs the PSWindowsUpdate community module.
    # Without it, we can only trigger detection and point the user at Settings.
    if (Test-CommandExists 'Get-WindowsUpdate') {
        if (-not (Confirm-Action "Install-WindowsUpdate -AcceptAll")) { Add-Result 'Windows Update' 'DryRun'; return }
        try {
            Import-Module PSWindowsUpdate -ErrorAction Stop
            # Capture the result so the summary can distinguish "nothing was available"
            # from "installed 5 updates". Previously both rendered as a bare 'OK' with an
            # empty section body -- no way to tell whether it had actually done anything.
            $wu = @(Install-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop)
            if ($wu.Count -gt 0) {
                $wu | Format-Table -AutoSize | Out-String | Write-Host
                Add-Result 'Windows Update' 'OK' "via PSWindowsUpdate; $($wu.Count) update(s)"
            } else {
                Write-Host "  No applicable updates found -- already current." -ForegroundColor Green
                Add-Result 'Windows Update' 'OK' 'via PSWindowsUpdate; none available'
            }
        } catch {
            Add-Result 'Windows Update' 'Failed' $_.Exception.Message
            Write-Warning "PSWindowsUpdate failed: $($_.Exception.Message)"
        }
    } else {
        if (-not (Confirm-Action "trigger Windows Update detection")) { Add-Result 'Windows Update' 'DryRun'; return }
        try {
            (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
            Write-Host "  Detection triggered. Install pending updates via Settings > Windows Update." -ForegroundColor Yellow
            Write-Host "  (Tip: 'Install-Module PSWindowsUpdate' once to enable fully-scripted OS patching.)" -ForegroundColor DarkGray
            Add-Result 'Windows Update' 'Partial' 'detection only; install via Settings'
        } catch {
            Add-Result 'Windows Update' 'Failed' $_.Exception.Message
        }
    }
}

function Repair-SystemIntegrity {
    Write-Section "3. System integrity (DISM -> SFC)"
    # ORDER MATTERS: SFC repairs files *from* the component store. If the store is
    # corrupt, fix it FIRST with DISM, then run SFC. RestoreHealth needs internet.
    # DISM legitimately returns 3010 (success + reboot required) after servicing the
    # component store -- accept it as success rather than crying failure.
    Invoke-Native 'DISM RestoreHealth' 'DISM.exe' @('/Online','/Cleanup-Image','/RestoreHealth') -SuccessCodes @(0, 3010)
    Invoke-Native 'SFC scannow'        'sfc.exe'  @('/scannow')
}

function Invoke-ChkdskScan {
    Write-Section "4. Filesystem check (chkdsk)"
    # /scan is online and non-destructive (no reboot). /f /r locks the volume and
    # runs at next boot -- only under -DeepClean.
    Invoke-Native 'chkdsk online scan' 'chkdsk.exe' @($script:SysDrive,'/scan')
    if ($DeepClean) {
        Write-Host "  -DeepClean: scheduling full chkdsk /f /r at next reboot..." -ForegroundColor Yellow
        if (Confirm-Action "chkdsk $($script:SysDrive) /f /r (reboot-time)") {
            # Let CMD do the piping -- NOT PowerShell. chkdsk's "schedule at next restart?
            # (Y/N)" prompt is not satisfied by a PowerShell pipeline: `'Y' | chkdsk.exe`
            # leaves it unanswered, so chkdsk re-prompts three times and schedules NOTHING.
            # `cmd /c "echo y|chkdsk ..."` answers it correctly. Verified on Win11 26200:
            # PS pipe -> "C: is not dirty" (nothing scheduled); cmd echo -> "Chkdsk has been
            # scheduled manually to run on next reboot". Do not "simplify" this back to a
            # native PowerShell pipe.
            cmd.exe /c "echo y|chkdsk $($script:SysDrive) /f /r"
            $code = $LASTEXITCODE

            # IGNORE THE EXIT CODE -- it is genuinely meaningless here. chkdsk returns 3
            # ("could not check the disk") whether scheduling SUCCEEDED or failed: measured
            # exit 3 both when nothing was scheduled and when chkntfs then confirmed
            # "scheduled manually to run on next reboot". So verify the END STATE instead.
            # chkntfs reports whether autochk will really run on this volume at next boot,
            # which is the only fact that matters. An exit code is a claim; this is reality.
            $verify = ''
            try { $verify = (& chkntfs.exe $script:SysDrive 2>&1 | Out-String) }
            catch { Write-Verbose "chkntfs query failed: $($_.Exception.Message)" }
            $scheduled = ($verify -match 'scheduled') -or
                         ($verify -match 'is dirty' -and $verify -notmatch 'not dirty')

            if ($scheduled) {
                Write-Host "  Verified: a disk check IS scheduled for the next reboot." -ForegroundColor Green
                Write-Host "  Note: /r reads every sector -- this can take a long time at boot on a large disk." -ForegroundColor Yellow
                Add-Result 'chkdsk /f /r (scheduled)' 'OK' "verified via chkntfs (chkdsk exit $code is not meaningful)"
            } elseif (-not $verify.Trim()) {
                # chkntfs itself gave us nothing, so we genuinely don't know either way.
                # Say so rather than guessing from the exit code.
                Add-Result 'chkdsk /f /r (scheduled)' 'Partial' 'could not verify with chkntfs'
                Write-Warning "Could not confirm whether the boot-time check was scheduled (chkntfs returned nothing)."
            } else {
                Add-Result 'chkdsk /f /r (scheduled)' 'Failed' 'chkntfs shows NO scheduled check'
                Write-Warning "chkntfs reports no scheduled check -- the boot-time chkdsk was NOT scheduled."
                Write-Host "  To schedule it by hand, run this in an elevated prompt and answer Y:" -ForegroundColor Yellow
                Write-Host "      chkdsk $($script:SysDrive) /f /r" -ForegroundColor Yellow
                Write-Host "  (To cancel a scheduled check later:  chkntfs /x $($script:SysDrive))" -ForegroundColor DarkGray
            }
        } else { Add-Result 'chkdsk /f /r (scheduled)' 'DryRun' }
    }
}

function Optimize-Drives {
    Write-Section "5. Drive optimization (TRIM / defrag)"
    # Optimize-Volume is media-aware: TRIM on SSD, defrag on HDD. Never hardcode
    # -Defrag (would needlessly burn SSD write cycles).
    #
    # SYSTEM DRIVE ONLY by default. A defrag pass on a large spinning data drive can run
    # for HOURS -- a real test box had 33 TB and 22 TB fixed volumes attached -- which
    # would dominate a routine that otherwise finishes in ~15 minutes, and that is not an
    # acceptable surprise on someone else's PC. The system drive is where optimization
    # actually pays off. -OptimizeAllDrives opts into the rest.
    #
    # Note the system drive comes from an env var, so the DEFAULT path needs no WMI at
    # all. That matters: Get-Volume rides the Storage WMI provider, which is not
    # dependable everywhere -- on a live Win10 22H2 box it errored with "Invalid property"
    # and returned nothing. The old loop then had nothing to iterate, added NO result, and
    # the step VANISHED from the summary. A silent no-op is the one outcome this tool must
    # never produce.
    $sysDrive = $script:SysDriveLetter
    $targets  = @($sysDrive)

    # Enumerate the other fixed drives so they can be REPORTED as skipped (and optimized
    # under -OptimizeAllDrives). Best-effort: failure here must not cost us the system drive.
    $others = @()
    try {
        $others = @(Get-Volume -ErrorAction Stop |
            Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' } |
            ForEach-Object { [string]$_.DriveLetter })
    } catch {
        $why = ($_.Exception.Message -split "`r?`n")[0]
        Write-Warning "Get-Volume failed ($why) -- falling back to Win32_LogicalDisk."
    }
    if (-not $others) {
        # DriveType=3 is a local fixed disk, the same set Get-Volume's 'Fixed' selects.
        $others = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue |
            ForEach-Object { $_.DeviceID.TrimEnd(':') })
    }
    $others = @($others | Where-Object { $_ -and $_ -ne $sysDrive })

    if ($OptimizeAllDrives) {
        Write-Host "  -OptimizeAllDrives: including non-system fixed drives (this can take hours on large HDDs)." -ForegroundColor Yellow
        $targets += $others
        $others = @()
    } elseif ($others) {
        $list = ($others | ForEach-Object { "$($_):" }) -join ', '
        Write-Host "  System drive only. Skipping $list -- use -OptimizeAllDrives to include them." -ForegroundColor DarkGray
    }

    foreach ($dl in $targets) {
        $label = "Optimize ${dl}:"
        if (-not (Confirm-Action $label)) { Add-Result $label 'DryRun'; continue }
        try {
            Optimize-Volume -DriveLetter $dl -Verbose -ErrorAction Stop
            Add-Result $label 'OK'
        } catch {
            # Optimize-Volume is backed by the same provider that just broke the
            # enumeration. defrag.exe is the in-box equivalent and does NOT go through
            # it; /O means "do the right operation for this media type" -- i.e. TRIM on
            # an SSD, defrag on an HDD, exactly what Optimize-Volume does by default.
            $why = ($_.Exception.Message -split "`r?`n")[0]
            Write-Warning "Optimize-Volume failed on ${dl}: ($why) -- retrying with defrag.exe /O."
            defrag.exe "${dl}:" /O
            if ($LASTEXITCODE -eq 0) {
                Add-Result $label 'OK' 'via defrag.exe /O (Storage provider unavailable)'
            } else {
                Add-Result $label 'Failed' "Optimize-Volume + defrag.exe (exit $LASTEXITCODE) both failed"
            }
        }
    }

    # Recorded AFTER the loop so the summary leads with the drive that was actually
    # optimized. Skipped drives still get a row -- what we did NOT touch is part of an
    # honest report, and $others is empty under -OptimizeAllDrives.
    foreach ($dl in $others) {
        Add-Result "Optimize ${dl}:" 'Skipped' 'non-system drive (-OptimizeAllDrives to include)'
    }
}

function Clear-TempFiles {
    Write-Section "6. Cleanup (temp + WinSxS component store)"
    if ($SkipCleanup) { Add-Result 'Cleanup' 'Skipped' '-SkipCleanup'; return }

    # Snapshot free space so we can report what cleanup actually reclaimed.
    $beforeGB = Get-FreeSpaceGB $script:SysDriveLetter

    # Delete only temp items NOT touched in the last 24h, and never the CDXML/CIM
    # module proxies PowerShell drops here (remoteIpMoProxy_*). Why: this script runs
    # inside a live PS session that uses $env:TEMP itself -- deleting a proxy that a
    # module first-loads LATER breaks that module (we hit exactly this: wiping TEMP in
    # this step broke Clear-DnsClientCache in the DNS report). "Locked files are
    # skipped" was the wrong assumption -- these aren't locked, just needed later.
    # Recent = possibly in use; old temp is the reclaimable junk anyway.
    $cutoff = (Get-Date).AddDays(-1)
    foreach ($root in @($env:TEMP, (Join-Path $env:WINDIR 'Temp'))) {
        if (Confirm-Action "remove items older than 24h in $root") {
            Get-ChildItem -LiteralPath $root -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -lt $cutoff -and $_.Name -notlike 'remoteIpMoProxy_*' } |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Add-Result 'Temp cleanup' ($(if ($DryRun) {'DryRun'} else {'OK'}) ) '>24h old; CIM proxies preserved'

    # Trim superseded WinSxS components. /ResetBase (under -DeepClean) also drops the
    # ability to uninstall current updates AND is ignored on recent builds -- opt-in only.
    $dismArgs = @('/Online','/Cleanup-Image','/StartComponentCleanup')
    if ($DeepClean) {
        $dismArgs += '/ResetBase'
        Write-Host "  -DeepClean: adding /ResetBase (blocks uninstalling current updates)." -ForegroundColor Yellow
    }
    # Same as RestoreHealth: component cleanup (especially with /ResetBase) commonly
    # finishes with 3010 = success, reboot required.
    Invoke-Native 'WinSxS component cleanup' 'DISM.exe' $dismArgs -SuccessCodes @(0, 3010)

    # Report reclaimed space (real runs only -- under -DryRun nothing was deleted).
    $afterGB = Get-FreeSpaceGB $script:SysDriveLetter
    if (-not $DryRun -and $null -ne $beforeGB -and $null -ne $afterGB) {
        $reclaimed = [math]::Round($afterGB - $beforeGB, 2)
        # Free space can DROP mid-run (a background process or the Defender scan writing),
        # making this negative. Label it "net change" then so the number isn't misread.
        $word = if ($reclaimed -lt 0) { 'net change' } else { 'reclaimed' }
        Write-Host ("  {0} free space  {1} GB -> {2} GB  ({3} {4} GB)" -f $script:SysDrive, $beforeGB, $afterGB, $word, $reclaimed) -ForegroundColor Green
        Add-Result 'Space reclaimed' 'OK' ("{0} {1} GB ({2} {3}->{4} GB)" -f $word, $reclaimed, $script:SysDrive, $beforeGB, $afterGB)
    }
}

function Clear-UpdateCache {
    Write-Section "7. Windows Update cache reset"
    if (-not $FlushUpdateCache) { Add-Result 'Update-cache flush' 'Skipped' 'not requested'; return }
    if (-not (Confirm-Action "stop wuauserv/bits, wipe SoftwareDistribution\Download, restart")) {
        Add-Result 'Update-cache flush' 'DryRun'; return
    }
    try {
        Stop-Service wuauserv, bits -Force -ErrorAction Stop
        Remove-Item "$env:WINDIR\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
        Start-Service wuauserv, bits -ErrorAction Stop
        Add-Result 'Update-cache flush' 'OK'
    } catch {
        Add-Result 'Update-cache flush' 'Failed' $_.Exception.Message
        # Best-effort: make sure services come back up even if the wipe errored.
        Start-Service wuauserv, bits -ErrorAction SilentlyContinue
    }
}

function Reset-NetworkStack {
    Write-Section "8. Network stack reset"
    if (-not $NetworkReset) { Add-Result 'Network reset' 'Skipped' 'not requested'; return }
    Write-Host "  WARNING: requires a reboot and may disrupt VPN/proxy config." -ForegroundColor Red
    Invoke-Native 'winsock reset' 'netsh.exe' @('winsock','reset')

    # 'netsh int ip reset' almost always returns exit 1 with "Access is denied" on ONE
    # key -- an NSI key under HKLM\SYSTEM\CurrentControlSet\Control\Nsi\... that Windows
    # ACL-locks so even an elevated admin/SYSTEM can't write it. The rest of the TCP/IP
    # stack still resets. So when it ran but only ACL-locked keys were denied, report
    # Partial (benign), not a hard Failure. We deliberately do NOT take ownership of that
    # key -- modifying a system-protected ACL is risky surgery for no real benefit.
    if (-not (Confirm-Action "int ip reset  (netsh.exe int ip reset)")) {
        Add-Result 'int ip reset' 'DryRun'; return
    }
    Write-Host "  > netsh.exe int ip reset" -ForegroundColor DarkCyan
    $out  = (& netsh.exe int ip reset 2>&1 | Out-String)
    $code = $LASTEXITCODE
    Write-Host $out
    if ($code -eq 0) {
        Add-Result 'int ip reset' 'OK' 'exit 0'
    } elseif ($out -match 'Access is denied' -and $out -match ', OK!') {
        Add-Result 'int ip reset' 'Partial' 'ran; 1 ACL-locked NSI key denied (known Windows quirk, benign)'
        Write-Host "  Note: one protected registry key couldn't be reset (Access is denied) -- a known," -ForegroundColor Yellow
        Write-Host "  harmless Windows ACL quirk. The rest of the TCP/IP stack WAS reset. Reboot to finish." -ForegroundColor Yellow
    } else {
        Add-Result 'int ip reset' 'Failed' "exit $code"
        Write-Warning "int ip reset returned exit code $code"
    }
}

function Invoke-Defender {
    Write-Section "9. Microsoft Defender (signatures + scan)"
    # Probe by actually CALLING the status cmdlet so we can tell FOUR states apart:
    #   - cmdlet genuinely absent              -> Skipped (Defender feature not installed)
    #   - present but the module fails to LOAD -> Failed  (NOT a silent skip!)
    #   - present but engine NOT RUNNING       -> Skipped (a 3rd-party AV like
    #     Malwarebytes is primary; Defender stood down -> nothing to scan with)
    #   - present and running (Normal/Passive) -> proceed
    # The old code used Test-CommandExists, which returns $false on a module-LOAD
    # error too -- so a transient CDXML/proxy fault got misreported as "third-party
    # AV?" and the scan was silently skipped. Never again: a load error is a failure,
    # and an inactive engine is a clearly-labelled skip (not a guess, not a failure).
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
    } catch [System.Management.Automation.CommandNotFoundException] {
        Add-Result 'Defender' 'Skipped' 'cmdlets not present (Defender feature absent)'
        Write-Warning "Defender cmdlets not present -- skipping (feature not installed)."
        return
    } catch {
        Add-Result 'Defender' 'Failed' "status check failed: $(($_.Exception.Message -split "`r?`n")[0])"
        Write-Warning "Defender is present but its status check FAILED -- scan NOT run. $(($_.Exception.Message -split "`r?`n")[0])"
        return
    }

    # On-demand scans need Defender's antimalware engine running. When another AV is
    # the registered primary (Malwarebytes here), Defender reports AMServiceEnabled=$false
    # / AMRunningMode='Not running' -- it CAN'T scan, so skip accurately. (Passive mode,
    # by contrast, still permits Start-MpScan, so only a stopped engine is skipped.)
    $mode = "$($status.AMRunningMode)"
    if (-not $status.AMServiceEnabled -or $mode -eq 'Not running') {
        Add-Result 'Defender' 'Skipped' "engine inactive (mode: $mode); another AV is primary"
        Write-Host "  Defender engine inactive (AMRunningMode: $mode) -- another AV owns protection. Skipping scan." -ForegroundColor Yellow
        return
    }
    if ($mode -and $mode -ne 'Normal') {
        Write-Host "  Defender running mode: $mode (a 3rd-party AV may be primary; on-demand scan still supported)." -ForegroundColor DarkGray
    }

    if (-not (Confirm-Action "update signatures + $($(if($FullScan){'Full'}else{'Quick'}))Scan")) {
        Add-Result 'Defender' 'DryRun'; return
    }
    try {
        Update-MpSignature -ErrorAction Stop
        $scanType = if ($FullScan) { 'FullScan' } else { 'QuickScan' }
        Start-MpScan -ScanType $scanType -ErrorAction Stop
        Add-Result 'Defender scan' 'OK' $scanType
    } catch {
        Add-Result 'Defender scan' 'Failed' $_.Exception.Message
        Write-Warning "Defender step failed: $($_.Exception.Message)"
    }
}

function Sync-SystemClock {
    Write-Section "10. System clock sync (w32tm)"
    # Clock drift silently breaks TLS/cert validation, Kerberos, and 2FA codes.
    # Resyncing against the configured time source is safe and non-destructive.
    if (-not (Test-CommandExists 'w32tm')) {
        Add-Result 'Clock sync' 'Skipped' 'w32tm unavailable'; return
    }
    if (-not (Confirm-Action "w32tm /resync (sync the system clock)")) { Add-Result 'Clock sync' 'DryRun'; return }
    # The Windows Time service must be running for a resync; it's trigger-started on
    # standalone PCs, so nudge it first.
    try {
        if ((Get-Service w32time -ErrorAction Stop).Status -ne 'Running') {
            Start-Service w32time -ErrorAction SilentlyContinue
        }
    } catch { Write-Verbose "w32time service not queryable: $($_.Exception.Message)" }
    & w32tm /resync /force | Out-Null
    $code = $LASTEXITCODE
    if ($code -eq 0) {
        Write-Host "  Clock resynced. Local time now: $(Get-Date)" -ForegroundColor Green
        Add-Result 'Clock sync' 'OK' "resynced ($(Get-Date -Format 'HH:mm:ss'))"
    } else {
        Add-Result 'Clock sync' 'Partial' "w32tm exit $code"
        Write-Warning "w32tm /resync returned $code (time service stopped or no time source configured)."
    }
}

function Clear-RecycleBinSafe {
    Write-Section "6b. Cleanup: Recycle Bin"
    # Opt-in: emptying the bin is real (recoverable) data loss, so never automatic.
    if (-not $EmptyRecycleBin) { Add-Result 'Recycle Bin' 'Skipped' 'not requested (-EmptyRecycleBin)'; return }
    if (-not (Confirm-Action "empty the Recycle Bin on all drives")) { Add-Result 'Recycle Bin' 'DryRun'; return }
    try {
        Clear-RecycleBin -Force -ErrorAction Stop
        Write-Host "  Recycle Bin emptied." -ForegroundColor Green
        Add-Result 'Recycle Bin' 'OK'
    } catch {
        # Clear-RecycleBin throws a benign error when the bin is already empty.
        $m = ($_.Exception.Message -split "`r?`n")[0]
        if ($m -match 'empty') {
            Write-Host "  Recycle Bin already empty." -ForegroundColor Green
            Add-Result 'Recycle Bin' 'OK' 'already empty'
        } else {
            Add-Result 'Recycle Bin' 'Failed' $m
            Write-Warning "Empty Recycle Bin failed: $m"
        }
    }
}

function Reset-StoreCache {
    Write-Section "11. Microsoft Store cache reset (wsreset)"
    # Opt-in. wsreset clears the Store download cache -- the standard fix for Store/UWP
    # install/update failures. It has no silent mode and opens the Store when done, so
    # it's deliberately opt-in and we don't wait on it.
    if (-not $ResetStore) { Add-Result 'Store cache reset' 'Skipped' 'not requested (-ResetStore)'; return }
    if (-not (Test-CommandExists 'wsreset.exe')) { Add-Result 'Store cache reset' 'Skipped' 'wsreset unavailable'; return }
    if (-not (Confirm-Action "wsreset.exe (clear Microsoft Store cache)")) { Add-Result 'Store cache reset' 'DryRun'; return }
    try {
        Start-Process -FilePath 'wsreset.exe' -WindowStyle Hidden -ErrorAction Stop
        Write-Host "  wsreset launched (clears the Store cache; the Store may open briefly)." -ForegroundColor DarkGray
        Add-Result 'Store cache reset' 'OK' 'wsreset launched'
    } catch {
        Add-Result 'Store cache reset' 'Failed' ($_.Exception.Message -split "`r?`n")[0]
    }
}

# ===========================================================================
# REPORT STEPS  (always run -- read-only)
# ===========================================================================

function Get-DiskHealthReport {
    Write-Section "Report: Disk health"
    # The Storage WMI provider (root\Microsoft\Windows\Storage) is NOT dependable on every
    # box. On a live Win10 22H2 machine Get-PhysicalDisk died with "Invalid property"
    # (CimException 0x80041031) -- and note the failure surfaced from the ENUMERATOR
    # ("Exception calling MoveNext"), i.e. a terminating error mid-pipeline that
    # -ErrorAction SilentlyContinue does not suppress. Unguarded, that failed the step.
    # Win32_DiskDrive lives in the classic CIMv2 provider and is unaffected, so a broken
    # storage stack now costs detail, not the report.
    $disks = $null
    try { $disks = @(Get-PhysicalDisk -ErrorAction Stop) }
    catch {
        $why = ($_.Exception.Message -split "`r?`n")[0]
        Write-Warning "Storage provider unavailable (Get-PhysicalDisk: $why) -- falling back to Win32_DiskDrive."
        $legacy = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
                Drive      = $_.Model
                'Size(GB)' = if ($_.Size) { [math]::Round($_.Size / 1GB, 1) } else { 'n/a' }
                Interface  = $_.InterfaceType
                # Win32_DiskDrive.Status is the drive's own SMART predictive-failure
                # verdict: 'OK', or 'Pred Fail' when it expects to die.
                Status     = if ($_.Status) { $_.Status } else { 'n/a' }
            }
        })
        if ($legacy) {
            $legacy | Format-Table -AutoSize
            Add-Result 'Disk health report' 'Partial' 'Storage provider broken; used Win32_DiskDrive (no wear/temp)'
            Write-Host "  Wear/temperature/read-error counters need the Storage provider. To check it:" -ForegroundColor DarkGray
            Write-Host "      winmgmt /verifyrepository        (is the WMI store intact?)" -ForegroundColor DarkGray
            Write-Host "      Get-CimInstance -Namespace root/Microsoft/Windows/Storage -ClassName MSFT_Disk" -ForegroundColor DarkGray
        } else {
            Add-Result 'Disk health report' 'Failed' "no disk info available: $why"
        }
        return
    }

    $disks | Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus | Format-Table -AutoSize
    # Reliability-counter props (Wear/Temperature) are often $null on consumer drives.
    # Render n/a rather than crashing.
    try {
        $disks | ForEach-Object {
            $c = $_ | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
            [pscustomobject]@{
                Drive          = $_.FriendlyName
                'Wear%'        = if ($null -ne $c.Wear) { $c.Wear } else { 'n/a' }
                ReadErrors     = if ($null -ne $c.ReadErrorsTotal) { $c.ReadErrorsTotal } else { 'n/a' }
                'Temp(C)'      = if ($null -ne $c.Temperature) { $c.Temperature } else { 'n/a' }
                PowerOnHours   = if ($null -ne $c.PowerOnHours) { $c.PowerOnHours } else { 'n/a' }
            }
        } | Format-Table -AutoSize
    } catch {
        Write-Host "  Reliability counters unavailable on this hardware." -ForegroundColor DarkGray
    }
    Add-Result 'Disk health report' 'OK'
}

function Get-DiskSpaceReport {
    Write-Section "Report: Disk space"
    # Win32_LogicalDisk DriveType=3 = local fixed disks. Warn before a drive fills up
    # (low free space causes update failures, paging thrash, and corruption risk).
    $rows = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue |
        ForEach-Object {
            $pct = if ($_.Size -gt 0) { [math]::Round($_.FreeSpace / $_.Size * 100, 1) } else { 0 }
            [pscustomobject]@{
                Drive      = $_.DeviceID
                'Size(GB)' = [math]::Round($_.Size / 1GB, 1)
                'Free(GB)' = [math]::Round($_.FreeSpace / 1GB, 1)
                'Free%'    = $pct
                Status     = if ($pct -lt 10) { 'LOW' } elseif ($pct -lt 15) { 'watch' } else { 'ok' }
            }
        })
    $rows | Format-Table -AutoSize
    $low = @($rows | Where-Object { $_.Status -eq 'LOW' })
    if ($low) {
        foreach ($d in $low) { Write-Host "  LOW SPACE: $($d.Drive) only $($d.'Free%')% free." -ForegroundColor Red }
        Add-Result 'Disk space' 'Warn' ('LOW: ' + (($low | ForEach-Object { "$($_.Drive) $($_.'Free%')%" }) -join ', '))
    } else {
        Write-Host "  All fixed drives have healthy free space." -ForegroundColor Green
        Add-Result 'Disk space' 'OK' 'all drives healthy'
    }
}

function Get-DirtyBitReport {
    Write-Section "Report: Filesystem dirty bit"
    # A 'dirty' volume is flagged by Windows for an automatic chkdsk at next boot
    # (suspected corruption). Surfacing it explains an upcoming boot-time chkdsk.
    $dirty = @()
    foreach ($d in @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)) {
        $out = (fsutil dirty query $d.DeviceID 2>$null | Out-String)
        if ($out -match 'is Dirty' -and $out -notmatch 'NOT Dirty') {
            $dirty += $d.DeviceID
            Write-Host "  $($d.DeviceID) is marked DIRTY -- Windows will chkdsk it at next boot." -ForegroundColor Yellow
        } else {
            Write-Host "  $($d.DeviceID) clean." -ForegroundColor Green
        }
    }
    # A dirty volume means Windows suspects corruption and will chkdsk it at next boot --
    # that is a finding, not a routine 'OK'.
    if ($dirty) { Add-Result 'Dirty bit' 'Warn' (($dirty -join ', ') + ' DIRTY -- chkdsk at next boot') }
    else        { Add-Result 'Dirty bit' 'OK' 'all clean' }
}

function Get-ComponentStoreReport {
    Write-Section "Report: WinSxS component store"
    # Read-only sizing (DISM /AnalyzeComponentStore) -- tells you the real on-disk size
    # of WinSxS and whether Windows itself recommends a component cleanup. Takes ~15s.
    $out = (DISM.exe /Online /Cleanup-Image /AnalyzeComponentStore 2>$null | Out-String)
    if ($LASTEXITCODE -ne 0 -or -not $out) {
        Write-Host "  Could not analyze the component store (DISM exit $LASTEXITCODE)." -ForegroundColor DarkGray
        Add-Result 'Component store' 'Skipped' "DISM exit $LASTEXITCODE"
        return
    }
    $actual = ([regex]::Match($out, 'Actual Size of Component Store\s*:\s*(.+)')).Groups[1].Value.Trim()
    $rec    = ([regex]::Match($out, 'Component Store Cleanup Recommended\s*:\s*(\w+)')).Groups[1].Value.Trim()
    if ($actual) { Write-Host "  Actual component store size: $actual" -ForegroundColor DarkGray }
    if ($rec)    { Write-Host "  Cleanup recommended by Windows: $rec" -ForegroundColor $(if ($rec -eq 'Yes') { 'Yellow' } else { 'Green' }) }
    Add-Result 'Component store' 'OK' ("size $actual; cleanup rec $rec")
}

function Get-ConnectivityReport {
    Write-Section "Report: Network connectivity"
    # Pure-.NET gateway discovery (no CDXML module dependency, which we've seen break).
    # ICMP can be filtered on some networks, so treat NO REPLY as a hint, not gospel.
    $results = @()
    $gateways = @()
    try {
        $gateways = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
            Where-Object { $_.OperationalStatus -eq 'Up' } |
            ForEach-Object { $_.GetIPProperties().GatewayAddresses } |
            ForEach-Object { $_.Address.IPAddressToString } |
            Where-Object { $_ -and $_ -ne '0.0.0.0' -and $_ -notmatch '^fe80' } | Sort-Object -Unique)
    } catch { Write-Verbose "Gateway enumeration failed: $($_.Exception.Message)" }

    foreach ($gw in $gateways) {
        $ok = Test-Connection -ComputerName $gw -Count 1 -Quiet -ErrorAction SilentlyContinue
        $results += [pscustomobject]@{ Check = "Gateway $gw"; Result = $(if ($ok) { 'reachable' } else { 'NO REPLY' }) }
    }
    if (-not $gateways) { $results += [pscustomobject]@{ Check = 'Gateway'; Result = 'none found' } }

    $netOk = Test-Connection -ComputerName '1.1.1.1' -Count 1 -Quiet -ErrorAction SilentlyContinue
    $results += [pscustomobject]@{ Check = 'Internet (1.1.1.1)'; Result = $(if ($netOk) { 'reachable' } else { 'NO REPLY' }) }

    try {
        $null = [System.Net.Dns]::GetHostEntry('www.microsoft.com')
        $results += [pscustomobject]@{ Check = 'DNS resolution'; Result = 'working' }
    } catch {
        $results += [pscustomobject]@{ Check = 'DNS resolution'; Result = 'FAILED' }
    }

    $results | Format-Table -AutoSize
    $bad = @($results | Where-Object { $_.Result -match 'NO REPLY|FAILED' })
    if ($bad) {
        Write-Host "  Connectivity issues (ICMP may be filtered -- verify before acting)." -ForegroundColor Yellow
        Add-Result 'Connectivity' 'Warn' ((($bad | ForEach-Object { $_.Check }) -join ', ') + ' failing (ICMP may be filtered)')
    } else {
        Write-Host "  Network connectivity looks healthy." -ForegroundColor Green
        Add-Result 'Connectivity' 'OK' 'gateway/internet/DNS ok'
    }
}

# Knowledge base of known event-log issue types. Each rule matches by provider
# (-like, case-insensitive) and optionally by event Id. Severity decides whether a
# low-volume issue is still surfaced (High always shows). AutoRepair is 'winget-app'
# ONLY for application crashes -- the one category with a safe, generic automated fix;
# everything else is 'none' (we recommend; we don't risk an unsafe auto-change).
function Get-IssueKnowledgeBase {
    @(
        @{ Name = 'App crashes'; Providers = @('Application Error', 'Application Hang'); Severity = 'Medium'; AutoRepair = 'winget-app';
           Advice = "Update or reinstall the crashing app; if it hooks into a browser or another app, disable that integration. -RepairIssues can attempt a winget repair/upgrade of packages it can map." }
        # '.NET Runtime' is TWO unrelated things wearing one source name, so it needs two
        # rules and the ORDER matters (Resolve-IssueRule returns the first match):
        #   1. The CLR itself reporting a fatal/unhandled exception -- 1023/1026/1027. A
        #      real crash.
        #   2. Any ASP.NET Core app using the EventLog logging provider without setting a
        #      SourceName. It inherits '.NET Runtime' and writes its OWN ILogger EventId,
        #      so a routine "HTTP 404 from an upstream API" lands here looking identical
        #      to a crash. Those are the app's error LOGS -- not crashes, not winget-repairable.
        @{ Name = 'App crashes'; Providers = @('.NET Runtime'); Ids = @(1023, 1026, 1027); Severity = 'Medium'; AutoRepair = 'winget-app';
           Advice = "An unhandled .NET exception killed the process. Update or reinstall the app; if it persists, check the app's own logs for the failing call." }
        @{ Name = 'App error logs (.NET)'; Providers = @('.NET Runtime'); Severity = 'Low'; AutoRepair = 'none';
           Advice = "These are an application's OWN logged errors (it uses the shared '.NET Runtime' event source), not process crashes -- volume here usually means a misconfigured app: a wrong upstream URL/API key, or a retired third-party endpoint. Fix it in that app's settings; Windows repair tools will not help." }
        @{ Name = 'Service crashes'; Providers = @('Service Control Manager'); Ids = @(7000, 7001, 7009, 7011, 7022, 7023, 7024, 7031, 7034); Severity = 'Medium'; AutoRepair = 'none';
           Advice = "Windows auto-restarts these. If the service belongs to a third-party app, update/reinstall that app. Persistent crashes of a Windows service warrant SFC/DISM (this routine runs them)." }
        @{ Name = 'Disk / filesystem'; Providers = @('disk', 'Microsoft-Windows-Ntfs', 'Ntfs', 'volmgr', 'volsnap'); Severity = 'High'; AutoRepair = 'none';
           Advice = "BACK UP NOW, then run a full chkdsk (-DeepClean schedules chkdsk /f /r at reboot). Check the wear + reliability counters above and the drive cabling -- recurring disk errors can precede drive failure." }
        @{ Name = 'Hardware (WHEA)'; Providers = @('Microsoft-Windows-WHEA-Logger'); Severity = 'High'; AutoRepair = 'none';
           Advice = "Hardware-level faults (CPU/PCIe/RAM/bus). Run vendor diagnostics + a memory test (mdsched.exe), update BIOS/chipset/GPU drivers, reseat components. Not software-repairable." }
        @{ Name = 'Unexpected shutdown'; Providers = @('Microsoft-Windows-Kernel-Power', 'Microsoft-Windows-Kernel-Boot'); Severity = 'High'; AutoRepair = 'none';
           Advice = "The PC lost power or crashed without a clean shutdown. Check overheating, the PSU/battery, and recently-updated drivers; disabling Fast Startup can help if it recurs. Reliability Monitor shows the timeline." }
        @{ Name = 'Unexpected shutdown'; Providers = @('EventLog'); Ids = @(6008); Severity = 'High'; AutoRepair = 'none';
           Advice = "The previous shutdown was unexpected (power loss or a crash). Check overheating, the PSU/battery, and recently-updated drivers; review Reliability Monitor." }
        @{ Name = 'Backup / shadow copy'; Providers = @('VSS', 'Microsoft-Windows-Backup'); Severity = 'Medium'; AutoRepair = 'none';
           Advice = "Volume Shadow Copy errors can break backups AND System Restore. Many are transient (raised during shutdown). If persistent, run 'vssadmin list writers' (look for failed writers) and free disk for shadow storage." }
        @{ Name = 'Windows Update'; Providers = @('Microsoft-Windows-WindowsUpdateClient'); Severity = 'Medium'; AutoRepair = 'none';
           Advice = "Update failures are often transient and retry automatically. If one is stuck, run with -FlushUpdateCache. Store/UWP errors (e.g. 0x80073D02 = packages in use) usually clear after a reboot or 'wsreset'." }
        @{ Name = 'Windows Search'; Providers = @('Microsoft-Windows-Search'); Severity = 'Low'; AutoRepair = 'none';
           Advice = "Rebuild the search index: Settings > Privacy & security > Searching Windows > Advanced indexing options > Rebuild. Safe but I/O-heavy, so left manual." }
        @{ Name = 'DCOM (usually benign)'; Providers = @('Microsoft-Windows-DistributedCOM'); Severity = 'Low'; AutoRepair = 'none';
           Advice = "DCOM 10010/10016 timeout/permission entries are extremely common and almost always harmless. Only chase if tied to a concrete symptom; editing DCOM permissions is risky, so no auto-fix." }
        @{ Name = 'TPM (usually benign)'; Providers = @('Microsoft-Windows-TPM-WMI'); Severity = 'Low'; AutoRepair = 'none';
           Advice = "Usually benign. If BitLocker or Windows Hello misbehave, inspect tpm.msc; only clear/re-own the TPM deliberately (it can invalidate BitLocker keys)." }
        @{ Name = 'Certificate enrollment'; Providers = @('Microsoft-Windows-CertificateServicesClient*'); Severity = 'Low'; AutoRepair = 'none';
           Advice = "Typically benign on a non-domain PC -- only relevant with enterprise/AD certificate services. Safe to ignore otherwise." }
        @{ Name = 'Hyper-V / WSL networking'; Providers = @('Microsoft-Windows-Hyper-V-*', 'vmms'); Severity = 'Low'; AutoRepair = 'none';
           Advice = "Usually WSL2/containers (podman)/VM virtual-switch churn. 'wsl --shutdown' or disabling/re-enabling the vEthernet adapter often clears it; generally transient." }
        @{ Name = 'TCP/IP'; Providers = @('Tcpip', 'Microsoft-Windows-Tcpip'); Severity = 'Low'; AutoRepair = 'none';
           Advice = "Duplicate-IP or adapter-disconnect warnings. Check for IP conflicts (DHCP reservations) and update the NIC driver; -NetworkReset is a last resort (needs a reboot, can disrupt VPN/proxy)." }
        @{ Name = 'DNS client'; Providers = @('Microsoft-Windows-DNS-Client'); Severity = 'Low'; AutoRepair = 'none';
           Advice = "Name-resolution timeouts. The routine already flushes the DNS cache; verify the DNS servers listed above are reachable." }
    )
}

# Find the first knowledge-base rule matching a provider (+ optional id constraint).
function Resolve-IssueRule {
    param([string]$Provider, [int[]]$Ids)
    foreach ($rule in Get-IssueKnowledgeBase) {
        $hit = $false
        foreach ($p in $rule.Providers) { if ($Provider -like $p) { $hit = $true; break } }
        if (-not $hit) { continue }
        if ($rule.ContainsKey('Ids') -and $rule.Ids) {
            $idHit = $false
            foreach ($i in $Ids) { if ($rule.Ids -contains $i) { $idHit = $true; break } }
            if (-not $idHit) { continue }
        }
        return $rule
    }
    return $null
}

function Find-EventIssues {
    # READ-ONLY. ONE sweep of System + Application (Critical+Error, last $EventDays days).
    # Groups by source, classifies against the knowledge base, merges by category, and
    # populates $script:Issues. High-severity issues surface even at low counts; lower
    # ones need volume ($noiseFloor) first. Each issue carries first/last-seen + a 24h
    # count so stale (likely-resolved) problems are distinguishable from active ones.
    $since = (Get-Date).AddDays(-$EventDays)
    $recentCutoff = (Get-Date).AddHours(-24)
    $noiseFloor = 5
    $script:Issues = @()
    $script:EventTotals = [ordered]@{}
    $script:EventScanOk = $false

    $all = @()
    foreach ($logName in 'System', 'Application') {
        # -EA SilentlyContinue is MANDATORY: a zero-match Get-WinEvent throws.
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = $logName; Level = 1, 2; StartTime = $since } -ErrorAction SilentlyContinue)
        $script:EventTotals[$logName] = $ev.Count
        $all += $ev
    }
    # Zero critical/error events in the window is a REAL result (a genuinely quiet
    # machine), not a failure -- so the scan counts as completed before returning.
    if (-not $all) { $script:EventScanOk = $true; return }

    # Merge provider groups into categories ('Application Error' + '.NET Runtime' both
    # fold into 'App crashes', so the report shows one entry, not two).
    $cats = @{}
    foreach ($g in ($all | Group-Object ProviderName)) {
        $ids  = @($g.Group | ForEach-Object { $_.Id } | Sort-Object -Unique)
        $rule = Resolve-IssueRule -Provider $g.Name -Ids $ids
        $cat  = if ($rule) { $rule.Name } else { "$($g.Name) (unclassified)" }
        if (-not $cats.ContainsKey($cat)) {
            $cats[$cat] = [pscustomobject]@{
                Category   = $cat
                Severity   = if ($rule) { $rule.Severity } else { 'Low' }
                Advice     = if ($rule) { $rule.Advice } else { "Recurring errors from '$($g.Name)'. Look up the Event ID; the usual safe fix is to update the owning app or device driver." }
                AutoRepair = if ($rule) { $rule.AutoRepair } else { 'none' }
                Count      = 0
                Events     = @()
                Detail     = ''
                Apps       = @()
                First      = $null
                Last       = $null
                Recent24h  = 0
            }
        }
        $cats[$cat].Count  += $g.Count
        $cats[$cat].Events += $g.Group
    }

    foreach ($entry in $cats.Values) {
        # Surface High always; otherwise require the noise floor.
        if ($entry.Severity -ne 'High' -and $entry.Count -lt $noiseFloor) { continue }

        # Recency: first/last-seen + how many landed in the last 24h. This is what tells
        # an ACTIVE problem apart from a stale one (e.g. crashes from an app you've since
        # uninstalled still sit in the 7-day window but have 0 recent events).
        $sorted = @($entry.Events | Sort-Object TimeCreated)
        $entry.First     = $sorted[0].TimeCreated
        $entry.Last      = $sorted[-1].TimeCreated
        $entry.Recent24h = @($entry.Events | Where-Object { $_.TimeCreated -ge $recentCutoff }).Count

        if ($entry.AutoRepair -eq 'winget-app') {
            # Per-exe crash counts from Application Error (1000) for targeted repair.
            # Layout: [0]=app [6]=exception code [10]=full app path.
            #
            # PROVIDER-SCOPED deliberately: event id 1000 is not unique, and only THIS
            # provider has that property layout. A .NET app logging via the EventLog
            # provider also writes 1000 under '.NET Runtime', where property [0] is the
            # whole log message -- which then flowed into Resolve-WingetId and threw on
            # 5.1. Same Event-ID-collision trap as podman, one layer deeper.
            $appErr = $entry.Events | Where-Object {
                $_.ProviderName -eq 'Application Error' -and $_.Id -eq 1000 -and $_.Properties.Count -gt 0
            }
            $list = foreach ($ag in ($appErr | Group-Object { $_.Properties[0].Value })) {
                $s = $ag.Group | Select-Object -First 1
                [pscustomobject]@{
                    App   = $ag.Name; Count = $ag.Count
                    Path  = $(if ($s.Properties.Count -gt 10) { $s.Properties[10].Value } else { '' })
                    Exc   = $(if ($s.Properties.Count -gt 6) { $s.Properties[6].Value } else { '' })
                }
            }
            $entry.Apps = @($list | Sort-Object Count -Descending)
            if ($entry.Apps) {
                $entry.Detail = (($entry.Apps | Select-Object -First 5 | ForEach-Object { "{0} x{1}" -f (Format-EventToken $_.App), $_.Count }) -join ', ')
                $exc = Convert-ExceptionCode $entry.Apps[0].Exc
                if ($exc -ne 'n/a') { $entry.Detail += "  [$exc]" }
            }
        }
        elseif ($entry.Category -eq 'Service crashes') {
            # SCM property [0] is the service name on every id EXCEPT the two timeout
            # events -- see Get-EventServiceName. Reading [0] blindly reported the top
            # culprit as "30000" (a timeout value) alongside the same service counted twice.
            $svcs = $entry.Events | Where-Object { $_.Properties.Count -gt 0 } |
                Group-Object { Get-EventServiceName $_ } | Sort-Object Count -Descending
            $entry.Detail = (($svcs | Select-Object -First 6 | ForEach-Object { "{0} x{1}" -f (Format-EventToken $_.Name 40), $_.Count }) -join ', ')
        }
        else {
            $entry.Detail = "event IDs: $(@($entry.Events | ForEach-Object { $_.Id } | Sort-Object -Unique) -join ', ')"
        }
        # Fallback so an issue NEVER renders a blank detail line. The app-crash branch
        # above only names culprits from Application Error (id 1000); a category built
        # purely from hangs (1002) or .NET Runtime events would otherwise show nothing.
        if (-not $entry.Detail) {
            $entry.Detail = "event IDs: $(@($entry.Events | ForEach-Object { $_.Id } | Sort-Object -Unique) -join ', ')"
        }
        $script:Issues += $entry
    }

    # Sort by severity, then ACTIVE-first (recent activity), then volume -- so live
    # issues bubble above stale ones within each severity band.
    $rank = @{ High = 0; Medium = 1; Low = 2 }
    $script:Issues = @($script:Issues | Sort-Object `
            @{ Expression = { $rank[$_.Severity] } }, `
            @{ Expression = 'Recent24h'; Descending = $true }, `
            @{ Expression = 'Count'; Descending = $true })

    # Reached the end with everything classified: the analysis is trustworthy. Only now
    # may the report claim a clean bill of health.
    $script:EventScanOk = $true
}

function Get-HealthReport {
    $span = "last $EventDays day$(if ($EventDays -ne 1) { 's' })"
    Write-Section "Report: System health (Event Viewer analysis, $span)"

    # An empty issue list has TWO very different causes: a healthy machine, or a scan that
    # died before classifying anything. Those must never render the same way. Without this
    # guard a crashed sweep printed "No notable issues classified. Clean." -- the single
    # most dangerous sentence this tool could produce, because it is maximally reassuring
    # and completely unfounded.
    if (-not $script:EventScanOk) {
        Write-Host "  EVENT SCAN DID NOT COMPLETE -- no health analysis was performed." -ForegroundColor Red
        Write-Host "  Do NOT read this as 'clean': nothing was analysed. See the 'Event analysis'" -ForegroundColor Yellow
        Write-Host "  row in the summary for the underlying error." -ForegroundColor Yellow
        Add-Result 'Health analysis' 'Failed' 'scan did not complete -- NOT a clean result'
        return
    }

    foreach ($k in $script:EventTotals.Keys) {
        Write-Host ("  {0,-12}: {1} critical/error events" -f $k, $script:EventTotals[$k]) -ForegroundColor DarkGray
    }
    if (-not $script:Issues -or $script:Issues.Count -eq 0) {
        Write-Host "  No notable issues classified. Clean." -ForegroundColor Green
        Add-Result 'Health analysis' 'OK' '0 issues'
        return
    }
    Write-Host ""
    $color = @{ High = 'Red'; Medium = 'Yellow'; Low = 'DarkGray' }
    foreach ($i in $script:Issues) {
        $recentTxt = if ($i.Recent24h -gt 0) { "$($i.Recent24h) in last 24h" } else { 'none in last 24h' }
        Write-Host ("  [{0}] {1}  --  {2} event(s), {3}" -f $i.Severity.ToUpper(), $i.Category, $i.Count, $recentTxt) -ForegroundColor $color[$i.Severity]
        if ($i.Detail) { Write-Host "      $($i.Detail)" -ForegroundColor DarkGray }
        Write-Host ("      first: {0:g}   last: {1:g}" -f $i.First, $i.Last) -ForegroundColor DarkGray
        # The staleness cue the user asked for: no recent events => probably already fixed.
        if ($i.Recent24h -eq 0) {
            Write-Host "      (no activity in the last 24h -- may already be resolved)" -ForegroundColor DarkGreen
        }
        Write-Host "      -> $($i.Advice)" -ForegroundColor Gray
        if ($i.AutoRepair -eq 'winget-app' -and $i.Apps) {
            $hint = if ($RepairIssues) { 'auto-repair runs in step 1b' } else { 're-run with -RepairIssues to attempt a safe winget repair' }
            Write-Host "      [safe auto-repair available -- $hint]" -ForegroundColor DarkCyan
        }
        # Status must reflect the FINDING, not merely that the scan ran. A High-severity
        # impending-disk-failure issue reading 'OK' in the summary defeats the whole point
        # of having a summary. High always warns; Medium warns only while it's still
        # ACTIVE (recent events) -- a Medium with nothing in 24h is already tagged "may
        # already be resolved", so flagging it would be noise; Low is benign by definition.
        $status = if ($i.Severity -eq 'High') { 'Warn' }
                  elseif ($i.Severity -eq 'Medium' -and $i.Recent24h -gt 0) { 'Warn' }
                  else { 'OK' }
        Add-Result "Issue: $($i.Category)" $status ("{0}; {1} events; {2}; last {3:M/d}" -f $i.Severity, $i.Count, $recentTxt, $i.Last)
    }
}

# Pull the executable path out of an autostart command line, so we can check whether the
# file it launches still exists. Autostart commands arrive in every shape Windows permits:
#   "C:\Program Files\App\app.exe" /background     <- quoted, spaces in path
#   C:\Windows\SysWOW64\OneDriveSetup.exe /thfirst <- unquoted, trailing args
#   %windir%\system32\SecurityHealthSystray.exe    <- environment variables
#   C:\PROGRA~1\SABnzbd\SABnzbd.exe -b0            <- 8.3 short path (Test-Path handles it)
#   Tautulli.lnk                                   <- Startup-folder entry: NOT a path
# Returns $null whenever nothing can be resolved CONFIDENTLY. That restraint is the whole
# point: a guess here turns into a false "this entry is broken" claim in the report, and a
# false accusation of breakage is worse than staying quiet.
function Resolve-CommandPath {
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Command.Trim())
    $path = $null
    if ($c.StartsWith('"')) {
        # Quoted: the path is exactly what sits between the first pair of quotes.
        $end = $c.IndexOf('"', 1)
        if ($end -gt 1) { $path = $c.Substring(1, $end - 1) }
    } else {
        # Unquoted: stop at the first executable extension. Non-greedy, so an UNQUOTED path
        # containing spaces still resolves correctly (Windows allows this, sloppily).
        $m = [regex]::Match($c, '^(.*?\.(exe|com|bat|cmd|scr|dll|msc))(\s|$)', 'IgnoreCase')
        if ($m.Success) { $path = $m.Groups[1].Value }
        elseif ($c -notmatch '\s') { $path = $c }
    }
    if (-not $path) { return $null }
    # Only ever judge a ROOTED path. A bare 'Tautulli.lnk' from a Startup folder is
    # unverifiable without resolving the folder, and calling it "missing" would be wrong.
    if ($path -notmatch '^[A-Za-z]:\\' -and $path -notmatch '^\\\\') { return $null }
    return $path
}

# Collect everything that starts on its own, across all THREE surfaces Windows uses.
#
# Win32_StartupCommand -- all this report used to show -- covers only the Run keys and the
# Startup folders. Measured on a live box: 12 entries there, against 22 non-Windows
# auto-start SERVICES and 5 non-Microsoft logon/boot SCHEDULED TASKS it never saw. Under a
# third of reality. That blind spot is not academic: it is precisely why a leftover Ombi
# service kept running (and logging errors) on a machine whose owner believed it was
# uninstalled, and why a pair of orphaned VPN-client drivers stayed invisible for weeks.
function Get-AutostartEntries {
    $entries = @()

    # 1. Run keys + Startup folders.
    foreach ($s in @(Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue)) {
        $loc = "$($s.Location)"
        # HKU paths embed a ~50-character raw SID. Collapse to hive + leaf key, or
        # Format-Table starves the column and wraps it one character per line.
        if ($loc -match '^(HK[A-Z_]+)\\.*\\([^\\]+)$') { $loc = "$($Matches[1])\...\$($Matches[2])" }
        $entries += [pscustomobject]@{
            Type = 'Run/Startup'; Name = "$($s.Name)"; Source = $loc; Command = "$($s.Command)"
        }
    }

    # 2. Auto-start services, minus the in-box ones. Without that filter ~200 Windows
    # services drown the signal; third-party services are what a maintenance pass is for.
    foreach ($svc in @(Get-CimInstance Win32_Service -Filter "StartMode='Auto'" -ErrorAction SilentlyContinue)) {
        $p = "$($svc.PathName)"
        if ($p -match '\\Windows\\(System32|SysWOW64|servicing)\\') { continue }
        $entries += [pscustomobject]@{
            Type = 'Service'; Name = "$($svc.Name)"; Source = "svc: $($svc.State)"; Command = $p
        }
    }

    # 3. Scheduled tasks triggered at logon or boot, excluding Microsoft's own tree.
    # ScheduledTasks is a CDXML module, so a broken CIM proxy fails during module AUTO-LOAD
    # -- before the cmdlet's own -ErrorAction can help. That is the exact trap that once
    # broke the DNS report, so import it explicitly and let our own catch handle it.
    try {
        Import-Module ScheduledTasks -ErrorAction Stop
        foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            if ($t.State -eq 'Disabled') { continue }
            if ("$($t.TaskPath)" -like '\Microsoft\*') { continue }
            $trig = @($t.Triggers | Where-Object { "$($_.CimClass.CimClassName)" -match 'LogonTrigger|BootTrigger' })
            if (-not $trig) { continue }
            # A task's Execute value is sometimes ALREADY quoted. Concatenating it raw
            # produced '""C:\path\x.exe" args', whose first quote pair encloses nothing --
            # Resolve-CommandPath then found an empty path and gave up, silently skipping
            # the existence check. Strip the quotes so the path is plain before we rebuild.
            $act  = @($t.Actions | Where-Object { $_.Execute })
            $cmd  = ''
            if ($act) {
                $exe = "$($act[0].Execute)".Trim().Trim('"')
                $cmd = ("$exe $($act[0].Arguments)").Trim()
            }
            $when = if ("$($trig[0].CimClass.CimClassName)" -match 'Boot') { 'at boot' } else { 'at logon' }
            $entries += [pscustomobject]@{
                Type = 'Task'; Name = "$($t.TaskName)"; Source = $when; Command = $cmd
            }
        }
    } catch {
        Write-Warning "Scheduled tasks could not be enumerated: $(($_.Exception.Message -split "`r?`n")[0])"
        Write-Host "  (Autostart audit below therefore covers Run keys + services only.)" -ForegroundColor DarkGray
    }
    return $entries
}

function Get-StartupAudit {
    Write-Section "Report: Autostart audit (Run keys, services, scheduled tasks)"
    $entries = @(Get-AutostartEntries)
    if (-not $entries) {
        Write-Warning "Could not enumerate any autostart entry."
        Add-Result 'Autostart audit' 'Failed' 'no entries enumerated'
        return
    }

    # Resolve each command to a real file and test it. An autostart entry pointing at a file
    # that is GONE is classic partial-uninstall residue: the app was removed, its launch
    # point survived. A $null path means "unverifiable", which is NOT the same as broken.
    foreach ($e in $entries) {
        $p = Resolve-CommandPath $e.Command
        $miss = $false
        if ($p) { $miss = -not (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue) }
        Add-Member -InputObject $e -NotePropertyName 'ExePath' -NotePropertyValue $p -Force
        Add-Member -InputObject $e -NotePropertyName 'Missing' -NotePropertyValue $miss -Force
    }

    foreach ($grp in @('Run/Startup', 'Service', 'Task')) {
        $rows = @($entries | Where-Object { $_.Type -eq $grp })
        if (-not $rows) { continue }
        $label = switch ($grp) {
            'Run/Startup' { 'Run keys + Startup folders' }
            'Service'     { 'Auto-start services (non-Windows)' }
            'Task'        { 'Scheduled tasks at logon/boot (non-Microsoft)' }
        }
        Write-Host ""
        Write-Host "  $label  [$($rows.Count)]" -ForegroundColor Cyan
        $rows | ForEach-Object {
            [pscustomobject]@{
                '!'     = $(if ($_.Missing) { 'X' } else { '' })
                Name    = Format-EventToken $_.Name 34
                Source  = Format-EventToken $_.Source 22
                Command = Format-EventToken $_.Command 58
            }
        } | Format-Table -AutoSize
    }

    $missing = @($entries | Where-Object { $_.Missing })
    Write-Host ""
    if ($missing) {
        Write-Host "  BROKEN AUTOSTART ENTRIES -- these point at files that no longer exist:" -ForegroundColor Yellow
        foreach ($m in $missing) {
            Write-Host ("    [{0}] {1}" -f $m.Type, (Format-EventToken $m.Name 40)) -ForegroundColor Yellow
            Write-Host ("        missing : {0}" -f $m.ExePath) -ForegroundColor DarkGray
            Write-Host ("        from    : {0}" -f (Format-EventToken $m.Source 60)) -ForegroundColor DarkGray
        }
        Write-Host "  Usually leftovers from an incomplete uninstall. Removal is safe but left MANUAL:" -ForegroundColor DarkGray
        Write-Host "    Run keys -> Task Manager > Startup    services -> sc.exe delete <name>" -ForegroundColor DarkGray
        Write-Host "    tasks    -> Task Scheduler (taskschd.msc)" -ForegroundColor DarkGray
        Add-Result 'Autostart audit' 'Warn' ("{0} entries; {1} point at MISSING files" -f $entries.Count, $missing.Count)
    } else {
        Write-Host "  $($entries.Count) autostart entries; every resolvable one points at a file that exists." -ForegroundColor Green
        Add-Result 'Autostart audit' 'OK' ("{0} entries; none broken" -f $entries.Count)
    }
}

# Decode Win32_PnPEntity.ConfigManagerErrorCode -- the CM_PROB_* value that Device Manager
# renders as a yellow bang. Text kept plain-English rather than echoing the raw constant.
function Convert-DeviceErrorCode {
    param([int]$Code)
    $map = @{
        1  = 'not configured correctly'
        3  = 'driver corrupted, or out of memory'
        9  = 'firmware reported the device incorrectly'
        10 = 'cannot start'
        12 = 'not enough free resources'
        14 = 'needs a restart to work'
        16 = 'resources not fully identified'
        18 = 'drivers need reinstalling'
        19 = 'registry configuration incomplete or damaged'
        21 = 'being removed'
        22 = 'disabled'
        24 = 'not present, not working, or missing drivers'
        28 = 'drivers not installed'
        31 = 'driver failed to load'
        33 = 'hardware not responding / resource conflict'
        43 = 'Windows stopped it after it reported a problem'
        45 = 'not currently connected (leftover device node)'
    }
    if ($map.ContainsKey($Code)) { return $map[$Code] }
    return "problem code $Code"
}

function Get-DeviceHealthReport {
    Write-Section "Report: Device health (Device Manager problems)"
    # A non-zero ConfigManagerErrorCode is EXACTLY what puts a yellow bang next to a device
    # in Device Manager. This reads Windows' own verdict rather than inferring one, which is
    # what keeps the check honest: it cannot false-positive any more than Device Manager can.
    # Report-only by design -- removing a device node (pnputil /remove-device) is a separate
    # decision, not something a routine maintenance pass should do behind your back.
    $all = $null
    try { $all = @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop) }
    catch {
        $why = ($_.Exception.Message -split "`r?`n")[0]
        Write-Warning "Could not enumerate PnP devices: $why"
        Add-Result 'Device health' 'Failed' $why
        return
    }
    $bad = @($all | Where-Object { $null -ne $_.ConfigManagerErrorCode -and $_.ConfigManagerErrorCode -ne 0 })
    # Code 22 = the user DISABLED this device deliberately. That is a choice, not a fault --
    # warning on it would be noise. Count it separately, never flag it.
    $disabled = @($bad | Where-Object { $_.ConfigManagerErrorCode -eq 22 })
    $faulty   = @($bad | Where-Object { $_.ConfigManagerErrorCode -ne 22 })

    if (-not $faulty) {
        Write-Host "  All $($all.Count) present devices report healthy." -ForegroundColor Green
        if ($disabled) { Write-Host "  ($($disabled.Count) device(s) deliberately disabled -- not a fault.)" -ForegroundColor DarkGray }
        Add-Result 'Device health' 'OK' "$($all.Count) devices, none faulty"
        return
    }

    $faulty | ForEach-Object {
        [pscustomobject]@{
            Device   = Format-EventToken "$($_.Name)" 42
            Code     = $_.ConfigManagerErrorCode
            Problem  = Convert-DeviceErrorCode ([int]$_.ConfigManagerErrorCode)
            DeviceID = Format-EventToken "$($_.PNPDeviceID)" 28
        }
    } | Format-Table -AutoSize

    Write-Host "  These appear as yellow warning icons in Device Manager (devmgmt.msc)." -ForegroundColor Yellow
    Write-Host "  Usual fixes: update or reinstall the driver. If the device belongs to software" -ForegroundColor DarkGray
    Write-Host "  you already uninstalled, it is a leftover node -- remove it in Device Manager" -ForegroundColor DarkGray
    Write-Host "  (View > Show hidden devices > right-click > Uninstall device)." -ForegroundColor DarkGray
    if ($disabled) { Write-Host "  ($($disabled.Count) further device(s) deliberately disabled -- not counted.)" -ForegroundColor DarkGray }
    $names = (($faulty | Select-Object -First 3) | ForEach-Object { Format-EventToken "$($_.Name)" 26 }) -join ', '
    Add-Result 'Device health' 'Warn' ("{0} device(s) in error: {1}" -f $faulty.Count, $names)
}

function Get-PowerReport {
    Write-Section "Report: Power / battery"
    # /energy works on desktops too; battery/sleepstudy need a battery. Reports land
    # in the log dir (timestamped, retention-pruned) instead of cluttering $USERPROFILE.
    # Pass the path as a bare argument -- PowerShell auto-quotes native-command args that
    # contain spaces. Wrapping it in literal quotes makes powercfg see a leading '"',
    # treat the absolute path as RELATIVE, and prepend the cwd (mangling the output path).
    $energyPath = Join-Path $script:LogDir "energy-report-$($script:RunStamp).html"
    Invoke-Native 'Power energy report' 'powercfg.exe' @('/energy','/output',$energyPath,'/duration','20')
    if (-not $script:DryRun) { Write-Host "  Energy report: $energyPath" -ForegroundColor DarkGray }
    if (Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue) {
        $battPath = Join-Path $script:LogDir "battery-report-$($script:RunStamp).html"
        Invoke-Native 'Battery report' 'powercfg.exe' @('/batteryreport','/output',$battPath)
        if (-not $script:DryRun) { Write-Host "  Battery report: $battPath" -ForegroundColor DarkGray }
    } else {
        Write-Host "  No battery detected -- skipping battery report (desktop)." -ForegroundColor DarkGray
        Add-Result 'Battery report' 'Skipped' 'no battery'
    }
}

function Get-PendingRebootReport {
    Write-Section "Report: Pending reboot"
    # Windows doesn't expose a single "reboot pending" flag -- it leaves markers in
    # several registry locations. Any one present => a reboot is owed. This matters
    # here because chkdsk /f /r, DISM, and -NetworkReset all DEFER work to next boot;
    # this is the one place that tells the user the run isn't truly finished.
    $pending = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $pending += 'Component-Based Servicing (DISM/SFC/updates)'
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $pending += 'Windows Update'
    }
    $pfro = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro) { $pending += 'Pending file-rename (locked files, incl. chkdsk /f /r)' }
    # Pending computer rename: active name differs from the staged next-boot name.
    $active = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' `
                  -Name ComputerName -ErrorAction SilentlyContinue).ComputerName
    $next   = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' `
                  -Name ComputerName -ErrorAction SilentlyContinue).ComputerName
    if ($active -and $next -and $active -ne $next) { $pending += 'Pending computer rename' }

    if ($pending.Count -gt 0) {
        Write-Host "  REBOOT PENDING -- restart to finish:" -ForegroundColor Yellow
        $pending | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
        # A pending reboot means the run is NOT actually finished -- chkdsk /f /r, DISM and
        # -NetworkReset all defer their real work to next boot. Warn so it can't be missed.
        Add-Result 'Pending reboot' 'Warn' ('YES: ' + ($pending -join '; '))
    } else {
        Write-Host "  No reboot pending." -ForegroundColor Green
        Add-Result 'Pending reboot' 'OK' 'none'
    }
}

function Get-NetworkReport {
    Write-Section "Report: DNS servers + cache flush"
    # DnsClient is a CDXML module, so a broken/missing CIM proxy is a MODULE-LOAD
    # failure that surfaces during command AUTO-LOAD -- before the cmdlet's own
    # ErrorAction (and, as we saw on a real run, even leaking past a try/catch around
    # the cmdlet call). So load the module EXPLICITLY first: the failure then happens
    # on Import-Module, a command we own, which our catch handles cleanly. If it can't
    # load, we report Skipped honestly instead of a false 'OK'.
    $dnsReady = $true
    try {
        Import-Module DnsClient -ErrorAction Stop
    } catch {
        $dnsReady = $false
        Write-Host "  DnsClient module failed to load -- skipping DNS flush + listing this run." -ForegroundColor Yellow
        Write-Host "    $(($_.Exception.Message -split "`r?`n")[0])" -ForegroundColor DarkGray
    }

    if ($dnsReady) {
        # The flush is a (benign) WRITE: skip under -ReportOnly and let Confirm-Action
        # suppress it under -DryRun, so -DryRun still changes nothing.
        if (-not $ReportOnly -and (Confirm-Action "flush DNS client cache")) {
            try {
                Clear-DnsClientCache -ErrorAction Stop
                Write-Host "  DNS client cache flushed." -ForegroundColor Green
            } catch {
                Write-Host "  DNS flush failed: $(($_.Exception.Message -split "`r?`n")[0])" -ForegroundColor DarkGray
            }
        }
        Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.ServerAddresses } |
            Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize
    }
    Add-Result 'DNS report' $(if ($dnsReady) { 'OK' } else { 'Skipped' }) $(if ($dnsReady) { '' } else { 'DnsClient load failed' })
}

# ===========================================================================
# MAIN
# ===========================================================================
$startTime = Get-Date
# Time the run with a MONOTONIC stopwatch rather than subtracting Get-Date values. This
# script resyncs the system clock itself (step 10), and NTP/DST corrections can move
# wall-clock time mid-run -- which would silently corrupt the elapsed figure. Same
# distinction as CLOCK_MONOTONIC vs CLOCK_REALTIME on Linux.
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
Write-Host ""
Write-Host "PC Tuneup -- $(if($DryRun){'[DRY RUN] '})$(if($ReportOnly){'[REPORT ONLY] '})starting $startTime" -ForegroundColor Magenta
Write-Host "Log: $logFile" -ForegroundColor DarkGray

try {
    # Detect crash loops up front (read-only) so the opt-in repair step below can
    # act on the same scan the report renders later. Every step runs via Invoke-Step
    # so one unhandled throw can't sink the rest of the run or the summary.
    Invoke-Step 'Event analysis' { Find-EventIssues }

    if (-not $ReportOnly) {
        Invoke-Step 'Restore point'      { New-RestoreCheckpoint }
        Invoke-Step 'App updates'        { Update-Apps }
        Invoke-Step 'Issue repair'       { Repair-Issues }
        Invoke-Step 'Windows Update'     { Invoke-OSUpdate }
        Invoke-Step 'System integrity'   { Repair-SystemIntegrity }
        Invoke-Step 'Filesystem check'   { Invoke-ChkdskScan }
        Invoke-Step 'Drive optimization' { Optimize-Drives }
        Invoke-Step 'Cleanup'            { Clear-TempFiles }
        Invoke-Step 'Recycle Bin'        { Clear-RecycleBinSafe }
        Invoke-Step 'Update-cache flush' { Clear-UpdateCache }
        Invoke-Step 'Network reset'      { Reset-NetworkStack }
        Invoke-Step 'Defender'           { Invoke-Defender }
        Invoke-Step 'Clock sync'         { Sync-SystemClock }
        Invoke-Step 'Store cache reset'  { Reset-StoreCache }
    }

    # Read-only reporting always runs.
    Invoke-Step 'Disk health'       { Get-DiskHealthReport }
    Invoke-Step 'Disk space'        { Get-DiskSpaceReport }
    Invoke-Step 'Dirty bit'         { Get-DirtyBitReport }
    Invoke-Step 'Component store'   { Get-ComponentStoreReport }
    Invoke-Step 'DNS report'        { Get-NetworkReport }
    Invoke-Step 'Connectivity'      { Get-ConnectivityReport }
    Invoke-Step 'Health report'     { Get-HealthReport }
    Invoke-Step 'Autostart audit'   { Get-StartupAudit }
    Invoke-Step 'Device health'     { Get-DeviceHealthReport }
    Invoke-Step 'Power report'      { Get-PowerReport }
    Invoke-Step 'Pending reboot'    { Get-PendingRebootReport }

    # ----- Summary -----
    Write-Section "Summary"
    # -Wrap: the Detail column carries the actionable text (exit codes, skip reasons).
    # Without it Format-Table truncates mid-sentence on a narrow console.
    $script:Results | Format-Table -AutoSize -Wrap
    # Two INDEPENDENT questions, and the summary must answer both:
    #   Failed = a step did not do its job (a tool problem).
    #   Warn   = a step worked fine and FOUND something wrong with the machine.
    # A run can be entirely Failed-free and still have a failing disk. @() guards the
    # .Count on a single result.
    $failed = @($script:Results | Where-Object { $_.Status -eq 'Failed' })
    $warned = @($script:Results | Where-Object { $_.Status -eq 'Warn' })
    if ($failed.Count -gt 0) {
        Write-Host "$($failed.Count) step(s) FAILED -- review above and the transcript." -ForegroundColor Red
    }
    if ($warned.Count -gt 0) {
        Write-Host "$($warned.Count) finding(s) NEED ATTENTION (status 'Warn'):" -ForegroundColor Yellow
        foreach ($w in $warned) { Write-Host "    - $($w.Step): $($w.Detail)" -ForegroundColor Yellow }
    }
    if ($failed.Count -eq 0 -and $warned.Count -eq 0) {
        Write-Host "All steps completed, and nothing needs your attention." -ForegroundColor Green
    }
    # Format hours EXPLICITLY. '{0:mm}' is the minutes-within-the-hour component, so it
    # silently drops whole hours: a real 1h01m59s run printed as "01m 59s". A -DeepClean
    # pass (DISM /ResetBase + SFC + a full Windows Update scan) genuinely can exceed an hour.
    $elapsed = $stopwatch.Elapsed
    $elapsedTxt = '{0:00}h {1:00}m {2:00}s' -f [math]::Floor($elapsed.TotalHours), $elapsed.Minutes, $elapsed.Seconds
    Write-Host ("Elapsed: $elapsedTxt   Log: $logFile") -ForegroundColor DarkGray
}
finally {
    # Always stop the transcript, even on Ctrl-C / unhandled error -- but only if WE
    # started it (see the Start-Transcript guard above).
    if ($script:TranscriptStarted) { Stop-Transcript | Out-Null }
}

# When we self-elevated, this is a BRAND-NEW console window that closes the instant the
# script ends -- taking the entire summary and health report with it. Hold it open until
# the user has read it. Gated on -Relaunched so an already-elevated or scheduled-task run
# never blocks waiting on input.
if ($Relaunched) {
    Write-Host ""
    Write-Host "Full log: $logFile" -ForegroundColor DarkGray
    Read-Host "Press Enter to close this window"
}
