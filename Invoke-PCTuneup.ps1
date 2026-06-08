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

.PARAMETER RepairCrashLoops
    For each app the crash-loop report flags (>=10 native crashes in 7 days), attempt
    a TARGETED winget repair (falling back to upgrade) of just that package. Opt-in:
    skips any app it can't confidently map to a single winget package. Detection of
    crash loops is always-on and read-only; only the repair action is gated by this.

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
    [switch]$RepairCrashLoops
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
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        # All our params are switches; only forward the ones actually present.
        if ($kv.Value -is [switch] -and $kv.Value.IsPresent) {
            $argList += "-$($kv.Key)"
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

$logDir = Join-Path $env:USERPROFILE 'pc-tuneup-logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$logFile = Join-Path $logDir ("tuneup-" + (Get-Date -Format 'yyyy-MM-dd-HHmmss') + ".log")
Start-Transcript -Path $logFile | Out-Null

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
# much cleanup actually reclaimed.
function Get-FreeSpaceGB {
    param([string]$Drive = 'C')
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

# Parse `winget list` text output by header-column offsets and return the single Id
# if exactly one package matched. Returns $null on zero/ambiguous/locale-mismatch --
# the caller treats $null as "don't touch anything" (safe by default).
function Get-WingetIdFromListing {
    param([string]$Raw)
    if (-not $Raw) { return $null }
    $lines  = $Raw -split "\r?\n" | Where-Object { $_ -and ($_ -notmatch '^[\s\-\\|/]+$') }
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
        try { $term = (Get-Item $Path -ErrorAction Stop).VersionInfo.ProductName } catch { }
    }
    if (-not $term) { $term = [System.IO.Path]::GetFileNameWithoutExtension($App) }
    if (-not $term) { return $null }

    if (Test-CommandExists 'Get-WinGetPackage') {
        try {
            $ids = @(Get-WinGetPackage -ErrorAction Stop |
                Where-Object { $_.Name -like "*$term*" -or $_.Id -like "*$term*" } |
                ForEach-Object { $_.Id } | Sort-Object -Unique)
            if ($ids.Count -eq 1) { return $ids[0] }
            return $null
        } catch { }
    }
    $out = (winget list --name $term --accept-source-agreements 2>$null | Out-String)
    return (Get-WingetIdFromListing -Raw $out)
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
        Add-Result $Label 'OK' "exit $code"
    } else {
        Add-Result $Label 'Failed' "exit $code"
        Write-Warning "$Label returned exit code $code"
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
        Write-Host "  (Enable once with: Enable-ComputerRestore -Drive 'C:\')" -ForegroundColor DarkGray
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
    Add-Result 'App updates (winget)' 'OK'
}

function Repair-CrashLoops {
    Write-Section "1b. Targeted repair of crash-looping apps (winget)"
    # Opt-in. Consumes the detection done by Find-CrashLoops (runs at startup).
    if (-not $RepairCrashLoops) {
        Write-Host "  Skipped -- opt-in. Re-run with -RepairCrashLoops to act on detected crash loops." -ForegroundColor DarkGray
        Add-Result 'Crash-loop repair' 'Skipped' 'not requested (-RepairCrashLoops)'; return
    }
    if (-not $script:CrashLoops -or $script:CrashLoops.Count -eq 0) {
        Add-Result 'Crash-loop repair' 'Skipped' 'no crash loops detected'; return
    }
    if (-not (Test-CommandExists 'winget')) {
        Add-Result 'Crash-loop repair' 'Skipped' 'winget unavailable'
        Write-Warning "winget not available -- cannot auto-repair. See the crash-loop report for manual steps."
        return
    }
    foreach ($c in $script:CrashLoops) {
        $id = Resolve-WingetId -App $c.App -Path $c.Path
        if (-not $id) {
            Write-Host "  '$($c.App)': no confident winget match -- skipping (repair/reinstall it manually)." -ForegroundColor Yellow
            Add-Result "Repair $($c.App)" 'Skipped' 'no confident winget match'
            continue
        }
        if (-not (Confirm-Action "winget repair --id $id  (fallback: upgrade)")) {
            Add-Result "Repair $($c.App)" 'DryRun' $id; continue
        }
        # 'repair' re-runs the installer's repair path; if the package doesn't
        # support it (non-zero exit), fall back to pulling the latest version,
        # which is the next-safest fix for an app-level bug.
        Write-Host "  Repairing $($c.App) -> winget package '$id'..." -ForegroundColor Cyan
        winget repair --id $id --silent --accept-source-agreements --disable-interactivity
        $code = $LASTEXITCODE
        if ($code -ne 0) {
            Write-Host "  repair unavailable/failed (exit $code); trying 'winget upgrade'..." -ForegroundColor DarkGray
            winget upgrade --id $id --include-unknown `
                --accept-source-agreements --accept-package-agreements `
                --silent --disable-interactivity
            $code = $LASTEXITCODE
        }
        if ($code -eq 0) {
            Add-Result "Repair $($c.App)" 'OK' $id
        } else {
            Add-Result "Repair $($c.App)" 'Failed' "$id (exit $code)"
            Write-Warning "Repair of '$id' returned exit $code -- repair it manually."
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
            Install-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
            Add-Result 'Windows Update' 'OK' 'via PSWindowsUpdate'
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
    Invoke-Native 'DISM RestoreHealth' 'DISM.exe' @('/Online','/Cleanup-Image','/RestoreHealth')
    Invoke-Native 'SFC scannow'        'sfc.exe'  @('/scannow')
}

function Invoke-ChkdskScan {
    Write-Section "4. Filesystem check (chkdsk)"
    # /scan is online and non-destructive (no reboot). /f /r locks the volume and
    # runs at next boot -- only under -DeepClean.
    Invoke-Native 'chkdsk online scan' 'chkdsk.exe' @('C:','/scan')
    if ($DeepClean) {
        Write-Host "  -DeepClean: scheduling full chkdsk /f /r at next reboot..." -ForegroundColor Yellow
        if (Confirm-Action "chkdsk C: /f /r (reboot-time)") {
            # 'Y' auto-answers the 'schedule at next restart?' prompt.
            'Y' | chkdsk.exe C: /f /r | Out-Null
            Add-Result 'chkdsk /f /r (scheduled)' 'OK' 'runs at next reboot'
        } else { Add-Result 'chkdsk /f /r (scheduled)' 'DryRun' }
    }
}

function Optimize-Drives {
    Write-Section "5. Drive optimization (TRIM / defrag)"
    # Optimize-Volume is media-aware: TRIM on SSD, defrag on HDD. Never hardcode
    # -Defrag (would needlessly burn SSD write cycles).
    $volumes = Get-Volume | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' }
    foreach ($v in $volumes) {
        $label = "Optimize $($v.DriveLetter):"
        if (-not (Confirm-Action $label)) { Add-Result $label 'DryRun'; continue }
        try {
            Optimize-Volume -DriveLetter $v.DriveLetter -Verbose -ErrorAction Stop
            Add-Result $label 'OK'
        } catch {
            Add-Result $label 'Failed' $_.Exception.Message
        }
    }
}

function Clear-TempFiles {
    Write-Section "6. Cleanup (temp + WinSxS component store)"
    if ($SkipCleanup) { Add-Result 'Cleanup' 'Skipped' '-SkipCleanup'; return }

    # Snapshot free space so we can report what cleanup actually reclaimed.
    $beforeGB = Get-FreeSpaceGB 'C'

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
    Invoke-Native 'WinSxS component cleanup' 'DISM.exe' $dismArgs

    # Report reclaimed space (real runs only -- under -DryRun nothing was deleted).
    $afterGB = Get-FreeSpaceGB 'C'
    if (-not $DryRun -and $null -ne $beforeGB -and $null -ne $afterGB) {
        $reclaimed = [math]::Round($afterGB - $beforeGB, 2)
        Write-Host ("  C: free space  {0} GB -> {1} GB  (reclaimed {2} GB)" -f $beforeGB, $afterGB, $reclaimed) -ForegroundColor Green
        Add-Result 'Space reclaimed' 'OK' ("{0} GB (C: {1}->{2} GB)" -f $reclaimed, $beforeGB, $afterGB)
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
    Invoke-Native 'int ip reset'  'netsh.exe' @('int','ip','reset')
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

# ===========================================================================
# REPORT STEPS  (always run -- read-only)
# ===========================================================================

function Get-DiskHealthReport {
    Write-Section "Report: Disk health"
    Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus | Format-Table -AutoSize
    # Reliability-counter props (Wear/Temperature) are often $null on consumer drives.
    # Render n/a rather than crashing.
    try {
        Get-PhysicalDisk | ForEach-Object {
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

function Get-EventSummary {
    Write-Section "Report: Critical/Error events (last 7 days)"
    # -ErrorAction SilentlyContinue is MANDATORY: zero matches is a terminating
    # error that would otherwise abort the whole script.
    foreach ($log in @('System','Application')) {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $log
            Level     = 1, 2          # 1 = Critical, 2 = Error
            StartTime = (Get-Date).AddDays(-7)
        } -ErrorAction SilentlyContinue

        if (-not $events) {
            Write-Host "  $log : no critical/error events. Clean." -ForegroundColor Green
            Add-Result "Event sweep ($log)" 'OK' '0 events'
            continue
        }
        Write-Host "  $log : $($events.Count) critical/error events. Top sources:" -ForegroundColor Yellow
        $events | Group-Object ProviderName |
            Sort-Object Count -Descending | Select-Object -First 5 Count, Name |
            Format-Table -AutoSize
        Add-Result "Event sweep ($log)" 'OK' "$($events.Count) events"
    }
}

function Find-CrashLoops {
    # READ-ONLY detection. Populates $script:CrashLoops with one entry per faulting
    # executable that crashed >= $threshold times in the last 7 days. Split from the
    # rendering (Get-CrashLoopReport) and the repair (Repair-CrashLoops) so all three
    # share one scan and the repair step can run *before* the report block.
    $threshold = 10
    $since = (Get-Date).AddDays(-7)
    $script:CrashLoops = @()

    # Filter on the 'Application Error' PROVIDER, not just Event ID 1000 -- other
    # providers (e.g. podman) reuse ID 1000 and would otherwise pollute the count.
    $crashes = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = 'Application Error'
        Id           = 1000
        StartTime    = $since
    } -ErrorAction SilentlyContinue
    if (-not $crashes) { return }

    $byApp = $crashes | Group-Object { $_.Properties[0].Value } | Where-Object { $_.Count -ge $threshold }
    foreach ($g in $byApp) {
        # Application Error (1000) property layout: [0]=app [3]=module [6]=exception
        # code [10]=full app path. Bounds-check in case a malformed event is short.
        $s = $g.Group | Select-Object -First 1
        $sorted = $g.Group | Sort-Object TimeCreated
        $script:CrashLoops += [pscustomobject]@{
            App           = $g.Name
            Path          = $(if ($s.Properties.Count -gt 10) { $s.Properties[10].Value } else { '' })
            Count         = $g.Count
            Module        = $(if ($s.Properties.Count -gt 3)  { $s.Properties[3].Value }  else { '' })
            ExceptionCode = $(if ($s.Properties.Count -gt 6)  { $s.Properties[6].Value }  else { '' })
            FirstSeen     = ($sorted | Select-Object -First 1).TimeCreated
            LastSeen      = ($sorted | Select-Object -Last 1).TimeCreated
        }
    }
}

function Get-CrashLoopReport {
    Write-Section "Report: Application crash loops (last 7 days)"
    if (-not $script:CrashLoops -or $script:CrashLoops.Count -eq 0) {
        Write-Host "  No app exceeded the crash-loop threshold (>=10 in 7d). Clean." -ForegroundColor Green
        Add-Result 'Crash-loop scan' 'OK' '0 crash loops'
        return
    }
    foreach ($c in $script:CrashLoops) {
        $exc = Convert-ExceptionCode $c.ExceptionCode
        Write-Host ("  {0}  --  {1} crashes" -f $c.App, $c.Count) -ForegroundColor Yellow
        Write-Host ("     module: {0}   exception: {1}" -f $c.Module, $exc) -ForegroundColor DarkGray
        Write-Host ("     first: {0}   last: {1}" -f $c.FirstSeen, $c.LastSeen) -ForegroundColor DarkGray
        if ($c.Path) { Write-Host ("     path: {0}" -f $c.Path) -ForegroundColor DarkGray }
        Add-Result "Crash loop: $($c.App)" 'OK' ("{0} crashes; {1}" -f $c.Count, $exc)
    }
    if (-not $RepairCrashLoops) {
        Write-Host "  Tip: re-run with -RepairCrashLoops for a targeted winget repair/upgrade of these." -ForegroundColor DarkGray
    }
}

function Get-StartupAudit {
    Write-Section "Report: Startup programs"
    # Get-CimInstance, not the deprecated Get-WmiObject (removed in PS7).
    Get-CimInstance Win32_StartupCommand |
        Select-Object Name, Command, Location | Format-Table -AutoSize -Wrap
    Add-Result 'Startup audit' 'OK'
}

function Get-PowerReport {
    Write-Section "Report: Power / battery"
    # /energy works on desktops too; battery/sleepstudy need a battery.
    $energyPath = Join-Path $env:USERPROFILE 'energy-report.html'
    Invoke-Native 'Power energy report' 'powercfg.exe' @('/energy','/output',"`"$energyPath`"","/duration","20")
    if (Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue) {
        $battPath = Join-Path $env:USERPROFILE 'battery-report.html'
        Invoke-Native 'Battery report' 'powercfg.exe' @('/batteryreport','/output',"`"$battPath`"")
        Write-Host "  Battery report: $battPath" -ForegroundColor DarkGray
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
        Add-Result 'Pending reboot' 'OK' ('YES: ' + ($pending -join '; '))
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
Write-Host ""
Write-Host "PC Tuneup -- $(if($DryRun){'[DRY RUN] '})$(if($ReportOnly){'[REPORT ONLY] '})starting $startTime" -ForegroundColor Magenta
Write-Host "Log: $logFile" -ForegroundColor DarkGray

try {
    # Detect crash loops up front (read-only) so the opt-in repair step below can
    # act on the same scan the report renders later.
    Find-CrashLoops

    if (-not $ReportOnly) {
        New-RestoreCheckpoint
        Update-Apps
        Repair-CrashLoops
        Invoke-OSUpdate
        Repair-SystemIntegrity
        Invoke-ChkdskScan
        Optimize-Drives
        Clear-TempFiles
        Clear-UpdateCache
        Reset-NetworkStack
        Invoke-Defender
    }

    # Read-only reporting always runs.
    Get-DiskHealthReport
    Get-NetworkReport
    Get-EventSummary
    Get-CrashLoopReport
    Get-StartupAudit
    Get-PowerReport
    Get-PendingRebootReport

    # ----- Summary -----
    Write-Section "Summary"
    $script:Results | Format-Table -AutoSize
    $failed = $script:Results | Where-Object { $_.Status -eq 'Failed' }
    if ($failed) {
        Write-Host "$($failed.Count) step(s) FAILED -- review above and the transcript." -ForegroundColor Red
    } else {
        Write-Host "All steps completed without hard failures." -ForegroundColor Green
    }
    $elapsed = (Get-Date) - $startTime
    Write-Host ("Elapsed: {0:mm}m {0:ss}s   Log: {1}" -f $elapsed, $logFile) -ForegroundColor DarkGray
}
finally {
    # Always stop the transcript, even on Ctrl-C / unhandled error.
    Stop-Transcript | Out-Null
}
