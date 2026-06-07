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
    [switch]$NetworkReset
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

# Gate any action behind -DryRun. Returns $true if the caller should proceed.
function Confirm-Action {
    param([string]$What)
    if ($script:DryRun) {
        Write-Host "  [DryRun] would: $What" -ForegroundColor DarkGray
        return $false
    }
    return $true
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

    # Direct deletion is deterministic and non-interactive. (cleanmgr /verylowdisk
    # is NOT reliably silent -- it can still demand an OK click.) In-use files are
    # locked and skipped automatically; -EA SilentlyContinue swallows those.
    foreach ($path in @("$env:TEMP\*", "$env:WINDIR\Temp\*")) {
        if (Confirm-Action "remove $path") {
            Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Add-Result 'Temp cleanup' ($(if ($DryRun) {'DryRun'} else {'OK'}))

    # Trim superseded WinSxS components. /ResetBase (under -DeepClean) also drops the
    # ability to uninstall current updates AND is ignored on recent builds -- opt-in only.
    $dismArgs = @('/Online','/Cleanup-Image','/StartComponentCleanup')
    if ($DeepClean) {
        $dismArgs += '/ResetBase'
        Write-Host "  -DeepClean: adding /ResetBase (blocks uninstalling current updates)." -ForegroundColor Yellow
    }
    Invoke-Native 'WinSxS component cleanup' 'DISM.exe' $dismArgs
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
    # Defender cmdlets fail / go passive when a 3rd-party AV owns protection.
    if (-not (Test-CommandExists 'Get-MpComputerStatus')) {
        Add-Result 'Defender' 'Skipped' 'Defender cmdlets unavailable'
        Write-Warning "Defender module not available (third-party AV?) -- skipping."
        return
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

function Get-NetworkReport {
    Write-Section "Report: DNS cache flush"
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Write-Host "  DNS client cache flushed." -ForegroundColor Green
    Get-DnsClientServerAddress -AddressFamily IPv4 |
        Where-Object { $_.ServerAddresses } |
        Select-Object InterfaceAlias, ServerAddresses | Format-Table -AutoSize
    Add-Result 'DNS flush + report' 'OK'
}

# ===========================================================================
# MAIN
# ===========================================================================
$startTime = Get-Date
Write-Host ""
Write-Host "PC Tuneup -- $(if($DryRun){'[DRY RUN] '})$(if($ReportOnly){'[REPORT ONLY] '})starting $startTime" -ForegroundColor Magenta
Write-Host "Log: $logFile" -ForegroundColor DarkGray

try {
    if (-not $ReportOnly) {
        Update-Apps
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
    Get-StartupAudit
    Get-PowerReport

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
