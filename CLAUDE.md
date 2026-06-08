# Project: pc-tuneup

## Goal
A self-elevating PowerShell maintenance script for **Windows 10 (1809+) and
Windows 11**. Runs a safe-by-default monthly routine (app updates, OS updates,
integrity repair, disk health/optimization, cleanup, health report, Defender)
and prints an auditable summary. Spun out of `command-center` once the research
crystallized into actual code.

Origin research (the verified command spec this script implements) lives in
`command-center/research/win-maintenance-script-spec.md` and
`command-center/research/windows11-maintenance-commands.md`.

## Stack / Tools
- **Windows PowerShell 5.1** — in-box on both Win10 & Win11. NOT PowerShell 7.
  No PS7-only syntax (`??`, ternary, `&&`/`||`, `Get-WmiObject`).
- No external dependencies. PSWindowsUpdate is *optional* (enables fully-scripted
  OS patching; the script degrades to detection-only without it).

## Environment
- Windows 10 1809+ / Windows 11
- Path: `C:\Users\saula\repos\pc-tuneup\`
- Must run elevated — the script self-elevates via UAC.

## Key Files & Directories
- `Invoke-PCTuneup.ps1` — the whole tool. Single self-contained script.
- `README.md` — usage, parameters, what each step does.
- Logs are written at runtime to `%USERPROFILE%\pc-tuneup-logs\` (gitignored).

## Commands (build, run, test, deploy)
- **Run (safe routine):** `powershell -ExecutionPolicy Bypass -File .\Invoke-PCTuneup.ps1`
- **Preview only:** `.\Invoke-PCTuneup.ps1 -DryRun`
- **Health report only:** `.\Invoke-PCTuneup.ps1 -ReportOnly`
- **Close-out sanity gate (run before committing):**
  ```powershell
  $e=$null;$t=$null;[System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path .\Invoke-PCTuneup.ps1),[ref]$t,[ref]$e)|Out-Null; if($e){$e|%{ "$($_.Extent.StartLineNumber): $($_.Message)" }}else{'PARSE OK'}
  ```
  If PSScriptAnalyzer is installed, also run (must be CLEAN):
  `Invoke-ScriptAnalyzer -Path .\Invoke-PCTuneup.ps1 -Settings .\PSScriptAnalyzerSettings.psd1 -Severity Warning,Error`
  The settings file excludes 3 rules that are deliberate design choices here
  (Write-Host UX, custom -DryRun vs ShouldProcess, plural internal-helper nouns) —
  each with rationale in the .psd1. Any OTHER warning is a real finding; fix it.

## Constraints & Rules
- **Cross-version first.** Anything added must work on Win10 1809+ AND Win11. If a
  command is version- or edition-specific (e.g. winget on LTSC), feature-detect and
  skip-with-warning — never hard-fail.
- **Safe by default.** Destructive actions (`chkdsk /f /r`, `/ResetBase`, update-cache
  wipe, network reset) are opt-in switches only. `-DryRun` must change nothing.
- **Guard the known traps** (these are why the script exists, not incidental):
  - Every `Get-WinEvent` needs `-ErrorAction SilentlyContinue` (zero-match error).
  - Check `$LASTEXITCODE` after native EXEs (`sfc`/`DISM`/`chkdsk`/`netsh`/`powercfg`).
  - Feature-detect `winget`, Defender cmdlets, and battery before using them.
  - Tolerate `$null` storage-reliability properties.
- **Report > do.** The event sweep + disk health are the high-value output; keep the
  end-of-run summary intact.

## Current Status / Next Steps
- [x] Verified command spec written (in command-center, 2026-06-07)
- [x] Full script built: self-elevation, transcript, all guards, report, param surface (2026-06-07)
- [x] Static parse clean; Get-WinEvent + winget claims smoke-tested (2026-06-07)
- [x] Build-out: System Restore checkpoint (step 0), free-space-reclaimed reporting,
      pending-reboot report; fixed -DryRun violation (DNS flush now gated) (2026-06-07)
- [x] Integration smoke test under real Windows PowerShell 5.1 (26100): AST-loaded the
      shipped function bodies, ran all read-only reports + DryRun gating on this box.
      DryRun contract verified; pending-reboot correctly caught a live file-rename marker (2026-06-07)
- [x] Published to GitHub (private): github.com/samonti86/pc-tuneup; origin/master tracked (2026-06-07)
- [x] Crash-loop detection (always-on, read-only) + opt-in -RepairCrashLoops (targeted
      winget repair/upgrade, skip-if-ambiguous). Filters on the 'Application Error'
      PROVIDER, not just Event ID 1000 (podman et al. reuse that ID). Decodes exception
      codes. Found ExpressVPN.BrowserHelper.exe crash-looping 355x/7d, 0xE0434352/.NET (2026-06-07)
- [x] First real ELEVATED end-to-end run (2026-06-07): restore point, DISM/SFC clean,
      chkdsk clean, TRIM, 2.21 GB reclaimed, PSWindowsUpdate installed a driver. Surfaced
      a bug -> fixed: temp cleanup wiped $env:TEMP wholesale, deleting the live session's
      CDXML/CIM module proxies, which broke Clear-DnsClientCache (first-loaded post-cleanup).
      Fix: delete only >24h-old temp + preserve remoteIpMoProxy_*; harden DNS report with
      try/catch (module-LOAD errors bypass -EA SilentlyContinue). Validated under 5.1 (2026-06-07)
- [x] 2nd elevated run (under pwsh 7.6) post-mortem: Defender + DNS silently no-op'd and
      were MISREPORTED (Defender "Skipped/3rd-party AV?", DNS false "OK"). Root cause: the
      ORIGINAL pre-fix wholesale $env:TEMP wipe poisoned PowerShell's persisted
      module-analysis cache (it referenced a deleted remoteIpMoProxy_*..._94a5a24c proxy);
      that stale state carried into the next run, so CDXML modules (DnsClient, ConfigDefender)
      failed to autoload mid-run. Machine has since SELF-HEALED (fresh PS7/5.1 sessions load
      both fine). Fixes: (1) Invoke-Defender now CALLS Get-MpComputerStatus and distinguishes
      absent (Skipped) vs load-error (Failed) -- never a silent skip; (2) Get-NetworkReport
      explicitly Import-Module DnsClient first so a load failure is caught on a command we own
      and reported as Skipped, not false OK. Verified under 5.1 AND 7.6 (2026-06-07)
- [x] Defender engine-state refinement: this box runs MALWAREBYTES as the primary AV, so
      Get-MpComputerStatus reports AMServiceEnabled=$false / AMRunningMode='Not running'
      (Defender stood down -- stronger than passive). On-demand Start-MpScan can't run with
      a stopped engine, so Invoke-Defender now checks the engine state and reports an accurate
      'Skipped: engine inactive; another AV is primary' (not a guess, not a Failed). Corrects
      the earlier wrong expectation that the next run would scan. Verified 5.1+7.6 (2026-06-07)
- [x] Deep-dive QA pass (2026-06-07): added Invoke-Step so a single unhandled throw can no
      longer abort the remaining steps + summary (biggest robustness gap); winget exit code
      now captured in Update-Apps (Partial vs false OK); log retention (keep last 30 of each
      artifact); power/battery reports moved into the log dir, timestamped (declutter $USERPROFILE);
      reclaimed-space labels negative deltas as "net change"; fixed 2 empty catch blocks. Added
      PSScriptAnalyzerSettings.psd1 (3 documented rule exclusions) -> PSSA now CLEAN. Verified
      parse + PSSA-clean + Invoke-Step isolation under 5.1 AND 7.6 (2026-06-07)
- [x] Confirmed clean elevated run (tuneup-2026-06-07-202952): DNS flush EXECUTED, Defender
      correctly Skipped (engine inactive/Malwarebytes), no Failed steps -- both prior fixes
      validated in production (2026-06-07)
- [x] Generalized crash-loop -> Event Viewer HEALTH ANALYZER (2026-06-08): one sweep of
      System+Application (Crit+Error, 7d), classified against a knowledge-base of ~15 issue
      types (disk/WHEA/shutdown=High; app+service crashes/VSS/WU=Medium; DCOM/TPM/cert/Hyper-V
      =Low) with severity + named culprits + SAFE recommendation each. Only auto-repair is the
      winget app-repair (opt-in, now -RepairIssues; alias -RepairCrashLoops); everything else is
      recommend-only by design (most event issues have no safe generic fix). Replaced
      Get-EventSummary+Find-CrashLoops+Get-CrashLoopReport with Get-IssueKnowledgeBase/
      Resolve-IssueRule/Find-EventIssues/Get-HealthReport. Repair dedupes by winget id. Verified
      against live logs + parse + PSSA-clean under 5.1 AND 7.6 (2026-06-08)
- [x] Capability expansion (2026-06-08): + Sync-SystemClock (w32tm /resync, step 8 -- drift
      breaks SSL/auth); + reports Get-DiskSpaceReport (low-space warn), Get-DirtyBitReport
      (fsutil dirty query -> pending boot chkdsk), Get-ComponentStoreReport (DISM AnalyzeComponent-
      Store size + cleanup-recommended), Get-ConnectivityReport (gateway/1.1.1.1/DNS via pure
      .NET, no CDXML dep); + opt-in -EmptyRecycleBin and -ResetStore (wsreset). Deliberately
      EXCLUDED registry cleaners / auto driver updates / service-debloat (unsafe snake-oil).
      Added PSAvoidUsingComputerNameHardcoded to PSSA exclusions (1.1.1.1 probe is intentional).
      Verified on live box + parse + PSSA-clean under 5.1 AND 7.6 (2026-06-08)
- [ ] User action: fix ExpressVPN (BrowserHelper crashes 336x/7d + its 3 services crash 28x);
      reinstall/update or remove -- it dominates both event logs. winget now maps it
      (XP9M14XF781P6R), so '-RepairIssues' can attempt it; or remove ExpressVPN outright
- [ ] Test on a Windows 10 machine to confirm cross-version behavior
- [ ] Optional: add to command-center projects-index
- [ ] Optional: scheduled-task wrapper for monthly auto-run
