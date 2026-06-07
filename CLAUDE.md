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
  If PSScriptAnalyzer is installed, also run:
  `Invoke-ScriptAnalyzer -Path .\Invoke-PCTuneup.ps1 -Severity Warning,Error`

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
- [ ] Re-run elevated end-to-end to confirm the DNS step is now clean
- [ ] User action: fix ExpressVPN BrowserHelper crash loop (update/reinstall ExpressVPN
      or disable its browser integration) -- app bug, not OS corruption
- [ ] Test on a Windows 10 machine to confirm cross-version behavior
- [ ] Optional: add to command-center projects-index
- [ ] Optional: scheduled-task wrapper for monthly auto-run
