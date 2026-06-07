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
- [ ] Real end-to-end run on this Win11 box (will pop UAC; needs user present)
- [ ] Test on a Windows 10 machine to confirm cross-version behavior
- [ ] Optional: publish to GitHub + add to command-center projects-index
- [ ] Optional: scheduled-task wrapper for monthly auto-run
