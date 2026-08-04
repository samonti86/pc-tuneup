# pc-tuneup

**A single-file, self-elevating Windows maintenance script for Windows 10 (1809+) and Windows 11.**

One `.ps1`. No dependencies. Written for in-box **Windows PowerShell 5.1**, so it runs
on a stock machine with nothing installed.

It performs a safe monthly maintenance routine and finishes with a **health report**
that classifies what's actually wrong with the machine — then tells you what to do
about it, instead of dumping raw event counts at you.

The script is deliberately careful about the things that quietly break unattended
maintenance scripts: terminating errors on empty event-log queries, a missing `winget`,
a third-party antivirus displacing Defender, semi-interactive `cleanmgr`, and native
tools (`sfc` / `DISM` / `chkdsk` / `netsh`) that report failure *only* through an exit
code that most scripts never check.

---

## Contents

- [Requirements](#requirements)
- [Get the script](#get-the-script)
- [Quick start](#quick-start)
- [What it does, step by step](#what-it-does-step-by-step)
- [The always-on reports](#the-always-on-reports)
- [The Event Viewer health analysis](#the-event-viewer-health-analysis)
- [All parameters](#all-parameters)
- [Common recipes](#common-recipes)
- [Reading the output](#reading-the-output)
- [Logs and files it writes](#logs-and-files-it-writes)
- [Safety model](#safety-model)
- [Troubleshooting / FAQ](#troubleshooting--faq)
- [Running it monthly on a schedule](#running-it-monthly-on-a-schedule)
- [Compatibility](#compatibility)
- [Development](#development)
- [License](#license)

---

## Requirements

| | |
|---|---|
| **OS** | Windows 10 build 17763 (version 1809) or newer, or Windows 11 |
| **PowerShell** | Windows PowerShell **5.1** — in-box on both. (It also runs under PowerShell 7, with one caveat noted below.) |
| **Privileges** | Administrator. The script **self-elevates** through UAC — you don't need to open an admin prompt yourself. |
| **Internet** | Recommended. `DISM /RestoreHealth`, `winget`, Windows Update and Defender signature updates all need it; each one degrades gracefully without it. |
| **Optional** | [`PSWindowsUpdate`](https://www.powershellgallery.com/packages/PSWindowsUpdate) — enables *fully scripted* OS patching. Without it the script triggers update detection and points you at Settings. |

Nothing else needs installing. There is no build step, no module to import, no config file.

## Get the script

```powershell
git clone https://github.com/samonti86/pc-tuneup.git
cd pc-tuneup
```

Or download `Invoke-PCTuneup.ps1` on its own — it is entirely self-contained and works
from any folder.

> **Downloaded as a single file from a browser?** Windows marks it as coming from the
> internet and PowerShell will refuse to run it. Clear that flag once with
> `Unblock-File .\Invoke-PCTuneup.ps1`.

## Quick start

```powershell
# 1. See exactly what it WOULD do. Changes nothing. Start here.
powershell -ExecutionPolicy Bypass -File .\Invoke-PCTuneup.ps1 -DryRun

# 2. Health report only — no maintenance actions at all.
powershell -ExecutionPolicy Bypass -File .\Invoke-PCTuneup.ps1 -ReportOnly

# 3. The real thing: the safe monthly routine.
powershell -ExecutionPolicy Bypass -File .\Invoke-PCTuneup.ps1
```

Each of these will pop a **UAC prompt** and relaunch itself elevated in a new window.
That window now **pauses at the end** so you can read the summary before it closes.

**Why `-ExecutionPolicy Bypass`?** The default Windows execution policy blocks unsigned
local scripts. The flag applies to that one invocation only — it does not change any
machine setting. If your policy already allows local scripts (`RemoteSigned`), you can
just run `.\Invoke-PCTuneup.ps1`. The UAC relaunch re-passes the flag automatically.

**How long does it take?** Typically **20–45 minutes** for the default routine. `DISM
/RestoreHealth` and `sfc /scannow` are the slow parts, and a Defender scan adds more. A
full `-DeepClean` pass (which adds DISM `/ResetBase`) has been measured at **just over an
hour** on an NVMe machine — budget accordingly. `-ReportOnly` finishes in a minute or two.

---

## What it does, step by step

Steps run in this order, and the numbers match the section headers the script prints,
so you can always tell where a run is. Steps marked **opt-in** do nothing unless you
pass their switch.

| # | Step | What and why |
|---|------|--------------|
| **0** | **System Restore checkpoint** | A rollback point created *before* anything changes. Skipped with a warning if System Restore is turned off (common on OEM images); Windows also throttles to one checkpoint per 24 h. |
| **1** | **App updates** — `winget upgrade --all` | Updates third-party apps non-interactively. `--include-unknown` catches apps whose version winget can't parse. Skipped with a warning if winget is absent. |
| **1b** | **Safe auto-repair** — *opt-in* `-RepairIssues` | Acts on the event analysis: a targeted `winget repair` (falling back to `upgrade`) of a crashing app it can map to exactly one package. Skips anything ambiguous. |
| **2** | **Windows Update** | Fully scripted when `PSWindowsUpdate` is installed; otherwise triggers detection and tells you to finish in Settings. |
| **3** | **Integrity repair** — `DISM /RestoreHealth` → `sfc /scannow` | **Order matters:** SFC repairs system files *from* the component store, so the store is repaired first. Reversing this is the classic mistake. |
| **4** | **Filesystem check** — `chkdsk C: /scan` | Online and non-destructive; no reboot. The full `/f /r` (which locks the volume and runs at boot) is opt-in via `-DeepClean`, and the script **verifies with `chkntfs` that the boot-time check was actually scheduled** rather than trusting chkdsk's exit code — which returns `3` whether scheduling succeeded or failed. |
| **5** | **Drive optimization** — `Optimize-Volume` | Media-aware: TRIM on SSDs, defrag on HDDs. Never hardcodes defrag, which would needlessly burn SSD write cycles. |
| **6** | **Cleanup** — temp + WinSxS | Deletes temp items **older than 24 h** (recent ones may be in use by the running session) and runs `DISM /StartComponentCleanup`. Reports GB reclaimed. Skip with `-SkipCleanup`. |
| **6b** | **Recycle Bin** — *opt-in* `-EmptyRecycleBin` | Opt-in because it destroys user-recoverable data. |
| **7** | **Update cache reset** — *opt-in* `-FlushUpdateCache` | Stops `wuauserv`/`bits`, wipes `SoftwareDistribution\Download`, restarts them. For when Windows Update is stuck. |
| **8** | **Network stack reset** — *opt-in* `-NetworkReset` | `netsh winsock reset` + `netsh int ip reset`. **Requires a reboot** and can disrupt VPN/proxy configuration. |
| **9** | **Microsoft Defender** | Updates signatures, then a QuickScan (`-FullScan` for a full one). Accurately skipped when another AV is primary and Defender's engine is stood down. |
| **10** | **Clock sync** — `w32tm /resync` | Clock drift silently breaks TLS/certificate validation, Kerberos, and 2FA codes. Cheap to fix, easy to overlook. |
| **11** | **Store cache reset** — *opt-in* `-ResetStore` | `wsreset` — the standard fix for Store/UWP install failures. Opens the Store window when it finishes, which is why it's opt-in. |

## The always-on reports

These are **read-only** and run on every invocation, including `-DryRun` and
`-ReportOnly`:

| Report | Tells you |
|---|---|
| **Disk health** | Per-physical-disk health/operational status, plus wear %, reboot-error counts, temperature and power-on hours where the drive exposes them. |
| **Disk space** | Free space per fixed drive, flagged `LOW` under 10 % and `watch` under 15 %. Low space causes update failures and paging thrash. |
| **Filesystem dirty bit** | Whether Windows has flagged a volume for an automatic `chkdsk` at next boot. |
| **WinSxS component store** | Real on-disk size of the component store and whether Windows itself recommends a cleanup. |
| **DNS servers + cache flush** | Configured DNS servers per interface. Also flushes the DNS client cache (suppressed under `-DryRun`/`-ReportOnly`). |
| **Network connectivity** | Reachability of your default gateway, the internet (1.1.1.1), and DNS resolution. |
| **Event Viewer health analysis** | The main event. See the next section. |
| **Startup programs** | What launches at boot, and from where. |
| **Power / battery** | Generates `powercfg /energy` and (on laptops) `/batteryreport` HTML files. |
| **Pending reboot** | Whether a restart is owed, and which subsystem is asking. Important because `chkdsk /f /r`, DISM and `-NetworkReset` all **defer work to next boot** — this is what tells you the run isn't truly finished. |

## The Event Viewer health analysis

This is the highest-value output in the tool, and the reason it exists.

It does **one** sweep of the System and Application logs (Critical + Error, last 7 days
by default — change with `-EventDays`), then **classifies** every error source against a
built-in knowledge base of ~15 known issue types rather than dumping raw counts. Each
issue is reported with a **severity**, the **specific culprits**, **recency**, and a
**safe recommendation**:

```text
  [HIGH] Disk / filesystem  --  14 event(s), 6 in last 24h
      event IDs: 7, 51
      first: 6/2/2026 3:11 PM   last: 6/8/2026 9:02 AM
      -> BACK UP NOW, then run a full chkdsk (-DeepClean schedules chkdsk /f /r at
         reboot). Check the wear + reliability counters above and the drive cabling --
         recurring disk errors can precede drive failure.

  [MEDIUM] App crashes  --  355 event(s), none in last 24h
      SomeApp.Helper.exe x340, SomeApp.Notify.exe x15  [0xE0434352 (.NET/CLR exception)]
      first: 6/1/2026 8:20 AM   last: 6/7/2026 2:41 PM
      (no activity in the last 24h -- may already be resolved)
      -> Update or reinstall the crashing app; if it hooks into a browser or another
         app, disable that integration.
      [safe auto-repair available -- re-run with -RepairIssues to attempt a winget repair]
```

**Severity bands**

- **High** — surfaced even at low volume, because one is one too many: disk/filesystem
  errors, hardware faults (WHEA), unexpected shutdowns.
- **Medium** — app crashes, service crashes, Volume Shadow Copy/backup, Windows Update.
- **Low** — usually-benign noise (DCOM timeouts, TPM, certificate enrollment,
  Hyper-V/WSL networking), shown only once it crosses a volume threshold.

**Recency matters.** Every issue carries first-seen and last-seen timestamps and a
"last 24 h" count, and issues sort by severity → recently-active → volume. That's how
you tell a live problem from a stale one: crashes from an app you uninstalled last week
still sit inside the 7-day window, but they'll show `none in last 24h` and be tagged
*may already be resolved*. Narrow the window with `-EventDays 1` to see only what's
happening now.

**Repair vs. recommend — the honest part.** Most Event Viewer issues have *no* safe,
generic, automated fix; the remedy is specific to the app, driver, or failing hardware.
So this tool **recommends** for those, and **auto-repairs** only the one category that
can be fixed safely and generically: a crashing app, via `winget repair`/`upgrade` of a
package it can map *unambiguously* — and only when you pass `-RepairIssues`. It will
never kill processes, uninstall software, restart services, or edit the registry based
on a heuristic. That restraint is the design, not a missing feature.

## All parameters

| Switch | Effect |
|--------|--------|
| `-DryRun` | Preview every action; change nothing. Read-only reports still run. |
| `-ReportOnly` | Only the read-only health checks. No maintenance actions. |
| `-SkipCleanup` | Skip the temp/WinSxS cleanup step. |
| `-FullScan` | Defender `FullScan` instead of the default `QuickScan`. Much slower. |
| `-EventDays N` | Days of Event Viewer history the analysis covers. Default `7`, range `1`–`365`. |
| `-DeepClean` | **Opt-in.** Adds `chkdsk /f /r` (scheduled for next reboot) and DISM `/ResetBase`. `/ResetBase` **blocks uninstalling currently-installed updates**. Note `/r` reads *every sector*: minutes on a small SSD, but **potentially many hours on a large spinning disk** — and the machine is unusable at the boot screen for the duration. Warn the owner before rebooting. |
| `-FlushUpdateCache` | **Opt-in.** Stop `wuauserv`/`bits`, wipe `SoftwareDistribution\Download`, restart. Use when Windows Update is stuck. |
| `-NetworkReset` | **Opt-in.** `netsh winsock reset` + `netsh int ip reset`. **Requires a reboot**; may disrupt VPN/proxy config. |
| `-RepairIssues` | **Opt-in.** Attempt the safe auto-repairs the analysis flags. Alias: `-RepairCrashLoops`. |
| `-EmptyRecycleBin` | **Opt-in.** Empty the Recycle Bin on all drives. |
| `-ResetStore` | **Opt-in.** Clear the Microsoft Store cache (`wsreset`). Opens the Store window when done. |

Standard PowerShell common parameters (`-Verbose`, `-ErrorAction`, …) work too, and are
forwarded correctly across the UAC relaunch.

Full built-in help, including examples:

```powershell
Get-Help .\Invoke-PCTuneup.ps1 -Full
```

## Common recipes

```powershell
# First time on a machine — look before you leap
.\Invoke-PCTuneup.ps1 -DryRun

# Just tell me what's wrong, don't touch anything
.\Invoke-PCTuneup.ps1 -ReportOnly

# What's broken RIGHT NOW (ignore last week's noise)
.\Invoke-PCTuneup.ps1 -ReportOnly -EventDays 1

# The standard monthly run
.\Invoke-PCTuneup.ps1

# Monthly run, and try to fix crashing apps it can identify
.\Invoke-PCTuneup.ps1 -RepairIssues

# Suspect the disk: schedule a full reboot-time chkdsk and deep-clean the component store
.\Invoke-PCTuneup.ps1 -DeepClean

# Windows Update is stuck and won't budge
.\Invoke-PCTuneup.ps1 -FlushUpdateCache

# Networking is broken at the socket layer (last resort — needs a reboot)
.\Invoke-PCTuneup.ps1 -NetworkReset

# Thorough pass: full AV scan, empty the bin, reset the Store cache
.\Invoke-PCTuneup.ps1 -FullScan -EmptyRecycleBin -ResetStore
```

## Reading the output

Every run ends with a summary table of every step and its status:

| Status | Meaning |
|--------|---------|
| **OK** | Completed successfully. |
| **Partial** | Ran, but not everything succeeded — e.g. `winget` couldn't upgrade some packages, or `netsh int ip reset` hit the one ACL-locked registry key Windows protects. Worth a look, not an emergency. |
| **Skipped** | Deliberately not run: an opt-in switch you didn't pass, or a feature that isn't present (no `winget`, no battery, Defender stood down for another AV). The reason is always in the Detail column. |
| **DryRun** | Would have run; suppressed by `-DryRun`. |
| **Failed** | Genuinely failed. Check the Detail column and the transcript. |

A step that hits an unexpected error is recorded as `Failed` and the run **continues** —
one bad step can never cost you the remaining steps or the summary.

> **Note:** `exit 3010` from DISM is *success with a reboot required*, and is reported
> as `OK`, not a failure. Likewise the single "Access is denied" key during
> `netsh int ip reset` is a known, harmless Windows ACL quirk and reports as `Partial`.

## Logs and files it writes

Everything lands in `%USERPROFILE%\pc-tuneup-logs\`:

| File | What |
|------|------|
| `tuneup-<timestamp>.log` | Full PowerShell transcript of the run. |
| `energy-report-<timestamp>.html` | `powercfg /energy` output — power/efficiency problems. |
| `battery-report-<timestamp>.html` | `powercfg /batteryreport` — battery wear over time (laptops only). |

Only the most recent **30** of each are kept; older ones are pruned at the start of each
run, so the folder can't grow without bound. The script writes nothing else outside that
folder and makes no changes to the repo directory.

> **Privacy:** those logs describe your machine — drive models, installed and crashing
> application names, startup entries, DNS servers, and event details. They stay local
> and are `.gitignore`d, but **review a log before pasting it into an issue, a forum, or
> a chat.**

## Safety model

The rules the script is built on:

1. **Safe by default.** A plain run performs only actions that are reversible or
   non-destructive. Everything with real consequences — `chkdsk /f /r`, DISM
   `/ResetBase`, wiping the update cache, resetting the network stack, emptying the
   Recycle Bin — is behind an explicit opt-in switch.
2. **`-DryRun` changes nothing.** It is a true preview, including for native tools.
3. **A restore point comes first.** Step 0, before any other change.
4. **Report honestly.** Skipped is never dressed up as success, and success is never
   dressed up as failure. Native tool exit codes are checked, not assumed.
5. **Feature-detect, never assume.** `winget`, Defender cmdlets, `w32tm`, batteries and
   restore points are all probed before use and skipped with a clear reason if absent.
6. **Never guess at a repair.** If the tool can't map a problem to one unambiguous,
   safe fix, it tells you what it found and recommends — it doesn't experiment on your
   machine.

**What this tool deliberately will not do**, because these range from useless to
actively harmful: registry "cleaning", automatic driver updates from third-party
sources, disabling Windows services to "debloat", killing processes heuristically, or
uninstalling software on your behalf.

## Troubleshooting / FAQ

**"running scripts is disabled on this system"**
Your execution policy blocks unsigned local scripts. Use the documented invocation:
`powershell -ExecutionPolicy Bypass -File .\Invoke-PCTuneup.ps1`. That affects only this
one run.

**The elevated window closes instantly / I can't read the report**
It shouldn't any more — the UAC-relaunched window pauses with *Press Enter to close*.
The full transcript is in `%USERPROFILE%\pc-tuneup-logs\` regardless.

**"winget not available on this machine"**
Expected on Windows 10 LTSC, debloated images, and before the first interactive login.
App updates are skipped; everything else still runs. Install *App Installer* from the
Microsoft Store to enable it.

**Defender was skipped — is my machine unprotected?**
No. If another antivirus (Malwarebytes, third-party suites) is registered as primary,
Windows stands Defender's engine down, and an on-demand scan genuinely cannot run. The
script detects that state and reports it accurately rather than pretending to scan.
Your other AV is doing the work.

**"Could not create restore point"**
System Restore is disabled on the system drive — common on OEM and clean images. Enable
it once:

```powershell
Enable-ComputerRestore -Drive 'C:\'
```

Note that Windows also rate-limits restore points to one per 24 hours, so a second run
the same day quietly reuses the existing one.

**Windows Update only "triggered detection"**
Install the optional module once, and future runs patch the OS end to end:

```powershell
Install-Module PSWindowsUpdate -Scope CurrentUser
```

**A step says `Failed` — did the rest of the run abort?**
No. Steps are isolated; a failure is recorded and the run continues to the summary.

**Did the boot-time `chkdsk /f /r` actually run?**
Check it, don't assume — a fast reboot usually means nothing was queued. Before rebooting,
`chkntfs C:` should say *"Chkdsk has been scheduled manually to run on next reboot."*
Afterwards, autochk writes its full output to the **Application** log as
`Microsoft-Windows-Wininit` event **1001**:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Microsoft-Windows-Wininit'} -MaxEvents 5 |
    Select-Object TimeCreated, Id
```

No 1001 event means it never ran. Cancel a pending check with `chkntfs /x C:`.

**It says a reboot is pending**
`chkdsk /f /r`, DISM servicing, and `-NetworkReset` all defer their real work to the
next boot. The pending-reboot report tells you the run isn't finished until you restart.

**Can I run it under PowerShell 7?**
Yes, it's tested there. One caveat: `Checkpoint-Computer` doesn't exist in PowerShell 7,
so the step-0 restore point is skipped with a warning. For a full-fidelity run, use
Windows PowerShell 5.1 (`powershell.exe`), which is what the documented commands invoke.

## Running it monthly on a schedule

The script doesn't install a scheduled task for you. If you want one, create it
elevated — Task Scheduler bypasses the interactive UAC prompt via *Run with highest
privileges*:

```powershell
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\path\to\Invoke-PCTuneup.ps1"'
$trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 4 -DaysOfWeek Sunday -At 3am
Register-ScheduledTask -TaskName 'pc-tuneup' -Action $action -Trigger $trigger `
    -RunLevel Highest -Description 'Monthly Windows maintenance'
```

Review `%USERPROFILE%\pc-tuneup-logs\` afterwards — an unattended run has no one to read
its console output, and **the script does not currently return a non-zero exit code when
a step fails**, so the transcript is the source of truth.

## Compatibility

- **Windows 10:** requires **1809+** (build 17763). `winget` is absent on LTSC,
  debloated images, and machines before first interactive login — detected and skipped
  rather than failing.
- **Windows 11:** fully supported; primary development target.
- **PowerShell:** written to the **5.1** baseline — no PS7-only syntax (`??`, ternary,
  `&&`/`||`, `Get-WmiObject`). Verified under both 5.1 and 7.
- **Non-English Windows:** a few checks parse English strings from native tools
  (`fsutil dirty query`, `netsh int ip reset`). They fail safe — worst case a check
  reports conservatively — but they're least accurate on localized installs.
- Built and verified on Windows 11. **Not yet run end-to-end on Windows 10.**

## Development

The whole tool is one file: `Invoke-PCTuneup.ps1`. There's no build step.

Before committing, run the sanity gate — a parse check plus PSScriptAnalyzer:

```powershell
# 1. Must print PARSE OK
$e=$null;$t=$null;[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\Invoke-PCTuneup.ps1),[ref]$t,[ref]$e)|Out-Null; if($e){$e|%{ "$($_.Extent.StartLineNumber): $($_.Message)" }}else{'PARSE OK'}

# 2. Must be CLEAN
Invoke-ScriptAnalyzer -Path .\Invoke-PCTuneup.ps1 -Settings .\PSScriptAnalyzerSettings.psd1 -Severity Warning,Error
```

`PSScriptAnalyzerSettings.psd1` excludes four rules, each a deliberate design choice
documented with its rationale in the file itself. **Any other warning is a real finding
— fix it, don't add an exclusion.**

Contributions should hold the line on the [safety model](#safety-model): cross-version
first (feature-detect and skip, never hard-fail), destructive actions opt-in only, and
`-DryRun` must change nothing.

## License

[MIT](LICENSE) — free to use, modify and redistribute, provided without warranty of any
kind. This script performs system maintenance with administrator rights; you run it at
your own risk. Read the [safety model](#safety-model) and try `-DryRun` first.
