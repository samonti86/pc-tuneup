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
| 6 | **Cleanup** — temp (>24h old) + `DISM /StartComponentCleanup` | Skipped with `-SkipCleanup`. Deletes temp items older than 24h and preserves the live session's in-use files (incl. CIM module proxies). Reports GB reclaimed on `C:`. Optional `-EmptyRecycleBin`. |
| 7 | **Defender** — signatures + QuickScan | Skipped if a third-party AV owns protection (or its engine is inactive). |
| 8 | **Clock sync** — `w32tm /resync` | Resyncs the system clock; drift silently breaks SSL/cert/auth. |
| — | **Reports** (always) | Disk health, **disk space (low-space warning)**, **filesystem dirty-bit**, **WinSxS store size**, DNS servers, **network connectivity (gateway/DNS/internet)**, **Event Viewer health analysis (7d)**, startup audit, power/battery, **pending-reboot status**. |

The highest-leverage output is the **Event Viewer health analysis** — that's where
real incidents surface. Cleanup is just hygiene.

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
| `-RepairIssues` | **Opt-in.** Attempt the safe auto-repairs the analysis flags — in practice a targeted `winget repair` (→ `upgrade` fallback) of crashing apps it can map to a single package. Skips what it can't map. (Alias: `-RepairCrashLoops`.) |
| `-EmptyRecycleBin` | **Opt-in.** Empty the Recycle Bin (all drives). Opt-in since it deletes user-recoverable data. |
| `-ResetStore` | **Opt-in.** Clear the Microsoft Store cache (`wsreset`) — fixes Store/UWP update errors. Opens the Store window when done. |
| `-EventDays N` | Days of Event Viewer history the health analysis covers (default 7, range 1-365). Lower it (e.g. `-EventDays 1`) to focus on only recent issues. |

## Event Viewer health analysis

This is the highest-value output. It does **one** sweep of the System + Application
logs (Critical/Error, last 7 days — adjustable with `-EventDays`), then **classifies**
each error source against a built-in knowledge base instead of just dumping raw counts.
Each issue is shown with a **severity** (High / Medium / Low), the specific culprits
(faulting apps or service names), **first/last-seen timestamps and a "last 24h" count**,
and a **safe recommendation**:

- **High** — surfaced even at low volume: disk/filesystem errors, hardware (WHEA),
  unexpected shutdowns.
- **Medium** — app crashes, service crashes, Volume Shadow Copy / backup, Windows Update.
- **Low** — usually-benign noise (DCOM timeouts, TPM, cert enrollment, Hyper-V/WSL
  networking) shown only above a volume threshold.

**Repair vs. recommend.** The honest reality is that most Event Viewer issues have *no*
safe generic automated fix — the remedy is app/driver/hardware-specific. So the analysis
**recommends** for those, and only **auto-repairs** the one category that *can* be fixed
safely and generically: a crashing app, via `winget repair`/`upgrade` of a package it can
map *unambiguously* (opt-in with `-RepairIssues`). It never kills processes, uninstalls,
restarts services, or edits the registry on a heuristic — that would be the dangerous move.

## Output & logging

- Every run is transcript-logged to `%USERPROFILE%\pc-tuneup-logs\tuneup-<timestamp>.log`.
- Power/battery reports land in the same folder, timestamped
  (`energy-report-<timestamp>.html`, `battery-report-<timestamp>.html`).
- Only the most recent **30** of each artifact are kept; older ones are pruned each run.
- The run ends with a status table (OK / Partial / Skipped / DryRun / Failed) per step.
- Each step is isolated: an unexpected error in one step is recorded and the run
  continues, so you always get the full summary.

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
