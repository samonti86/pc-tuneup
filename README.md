# pc-tuneup

A self-elevating Windows maintenance script for **Windows 10 (1809+) and Windows 11**.
One `.ps1`, no dependencies, written for in-box **Windows PowerShell 5.1**.

It runs a safe monthly routine and ends with a health report — and it's careful
about the things that quietly break unattended maintenance scripts (terminating
errors on empty event queries, missing `winget`, third-party AV displacing
Defender, semi-interactive `cleanmgr`, native tools that report failure only via
exit code).

## Quick start

```powershell
# Safe monthly routine (will prompt for UAC and self-elevate)
powershell -ExecutionPolicy Bypass -File .\Invoke-PCTuneup.ps1

# See exactly what it would do, change nothing
.\Invoke-PCTuneup.ps1 -DryRun

# Health/event/disk report only, no maintenance actions
.\Invoke-PCTuneup.ps1 -ReportOnly
```

> `-ExecutionPolicy Bypass` is only needed for the unsigned local script; the UAC
> relaunch re-passes it automatically.

## What the default routine does (in order)

| # | Step | Notes |
|---|------|-------|
| 0 | **System Restore checkpoint** — `Checkpoint-Computer` | Seatbelt before anything changes. Skipped with a warning if System Restore is disabled; Windows also throttles to one point per 24h. |
| 1 | **App updates** — `winget upgrade --all` | Skipped with a warning if winget isn't installed. Non-interactive flags applied. |
| 2 | **Windows Update** | Fully scripted if the optional `PSWindowsUpdate` module is present; otherwise triggers detection and points you to Settings. |
| 3 | **Integrity repair** — `DISM /RestoreHealth` → `sfc /scannow` | This order matters: SFC repairs *from* the component store, so the store is fixed first. Needs internet. |
| 4 | **Filesystem** — `chkdsk C: /scan` | Online, non-destructive. Full `/f /r` only under `-DeepClean`. |
| 5 | **Optimize** — `Optimize-Volume` per fixed drive | Media-aware: TRIM on SSD, defrag on HDD. |
| 6 | **Cleanup** — temp dirs + `DISM /StartComponentCleanup` | Skipped with `-SkipCleanup`. Direct deletion (deterministic), not `cleanmgr`. Reports GB reclaimed on `C:`. |
| 7 | **Defender** — signatures + QuickScan | Skipped if a third-party AV owns protection. |
| — | **Reports** (always) | Disk health, DNS servers, critical/error event sweep (7d), startup audit, power/battery, **pending-reboot status**. |

The highest-leverage steps are **app updates** and the **event sweep** — that's where
incidents actually get prevented. Cleanup is just hygiene.

## Parameters

| Switch | Effect |
|--------|--------|
| `-DryRun` | Preview every action; change nothing. Reports still run. |
| `-ReportOnly` | Only the read-only health checks. No maintenance actions. |
| `-SkipCleanup` | Skip temp/WinSxS cleanup. |
| `-FullScan` | Defender `FullScan` instead of `QuickScan`. |
| `-DeepClean` | **Opt-in.** Adds `chkdsk /f /r` (reboot-time) and DISM `/ResetBase`. `/ResetBase` blocks uninstalling current updates. |
| `-FlushUpdateCache` | **Opt-in.** Stop wuauserv/bits, wipe `SoftwareDistribution\Download`, restart. Use when Windows Update is stuck. |
| `-NetworkReset` | **Opt-in.** `netsh winsock reset` + `netsh int ip reset`. **Requires reboot**, may disrupt VPN/proxy. |

## Output & logging

- Every run is transcript-logged to `%USERPROFILE%\pc-tuneup-logs\tuneup-<timestamp>.log`.
- Power/battery reports are written to `%USERPROFILE%\energy-report.html` and
  `battery-report.html`.
- The run ends with a status table (OK / Skipped / DryRun / Failed) per step.

## Compatibility notes

- **Windows 10:** requires **1809+** (build 17763). `winget` is absent on LTSC,
  debloated images, and machines before first interactive login — the script detects
  this and skips app updates rather than failing.
- **PowerShell:** targets **5.1** (default on both OSes). Runs under PowerShell 7 too,
  but is written to the 5.1 baseline.
- Built and verified on Windows 11; **not yet run end-to-end on Windows 10** — see
  `CLAUDE.md` → Next Steps.

## Safety

`-DryRun` changes nothing. Everything destructive is opt-in. Read the parameter table
before using `-DeepClean`, `-FlushUpdateCache`, or `-NetworkReset`.
