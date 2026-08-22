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
- `docs/build-log.md` — **full development history**: every milestone, every defect
  found, and the reasoning behind each fix. **Not auto-loaded — read on demand.**
  Split out 2026-08-21, when this file hit 37 KB and 82% of it was completed history.

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
- **Comment-based help must still resolve** (it breaks SILENTLY — see below):
  ```powershell
  $h = Get-Help .\Invoke-PCTuneup.ps1
  if ($h -is [string] -or -not $h.parameters.parameter) { 'HELP BROKEN' }
  else { "help OK: $(@($h.parameters.parameter).Count) params, $(@($h.examples.example).Count) examples" }
  ```
  Two ways to break it, both silent (Get-Help just falls back to auto-generated syntax
  and every .PARAMETER/.EXAMPLE vanishes): (1) putting `#Requires` immediately adjacent
  to the opening `<#` with no blank line between; (2) any literal `#>` appearing in a
  `#` line comment before the help block — it terminates the block early. Both were hit
  for real on 2026-08-04.
- **Runtime smoke tests MUST run under Windows PowerShell 5.1, not pwsh.** Parse +
  PSSA are static and pass identically on both; they do NOT catch .NET Framework vs
  .NET Core *behavior* differences. Real example (2026-08-04): `[IO.Path]::
  GetFileNameWithoutExtension()` throws "Illegal characters in path" on 5.1 and
  silently accepts the same input on 7.x — the bug was invisible in pwsh and failed a
  step in production. Pattern used throughout this project: AST-load the shipped
  function bodies and exercise them, explicitly under 5.1:
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\smoke.ps1
  ```
  Shadowing a cmdlet with a same-named function is the cheap way to simulate hardware
  you don't have (e.g. a multi-drive box, or a broken Storage WMI provider) — PowerShell
  resolves functions ahead of cmdlets, so a dot-sourced function under test picks up the
  stub. Watch for stub params colliding with common parameters like `-ErrorAction`.
- **Keep `CLAUDE.md` under ~25 KB.** When work completes, move the entry into
  `docs/build-log.md` rather than leaving it here. This file reached 37 KB once
  because finished milestones never moved out; Claude Code warns above ~40 KB and
  every byte is loaded at the start of every session.

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

**Shipped and in production use.** Built 2026-06-07 and hardened across roughly
eight sessions. Last validated end-to-end **2026-08-19** (pwsh 7, `-DeepClean
-NetworkReset -FlushUpdateCache -ResetStore`, 1h05m), and separately verified on
**Windows 10 22H2** as well as Windows 11. Close-out gate green on **both**
Windows PowerShell 5.1 and pwsh 7.

📖 **Full build history — every milestone, defect and the reasoning behind
each fix — is in [`docs/build-log.md`](docs/build-log.md). Not auto-loaded; read
it on demand.** Split out 2026-08-21, when this file hit 37 KB and 82% of it was
history. **When work completes, move it there** and keep this file under ~25 KB.

### Open — script defects (deferred deliberately; the user sequenced this work)

- [ ] **(5) `Invoke-Defender` writes TWO different step names** — `Defender` on
      the skip/fail paths vs `Defender scan` on success. Inconsistent summary.
- [ ] **(6) SFC/DISM outcomes are not classified.** *"Found corrupt files and
      successfully repaired them"* — which really happened on the Win10 box and
      drove a post-reboot re-run — is indistinguishable from *"no violations
      found"*. Both render `OK exit 0`. Same shape as the Windows Update count fix.
- [ ] **(7) Three minors.** `w32tm` pipes its output to `Out-Null`, so a failure
      yields an exit code and no reason (same class as the chkdsk fix);
      `Repair-Issues` interpolates `$app.App` into a step name without
      `Format-EventToken`; temp cleanup inspects only **top-level** entries, and a
      directory's mtime updates when its children change — so an active folder
      shields arbitrarily old contents from the 24h rule, reclaiming less than it
      appears to.

### Open — machine findings (NOT script bugs)

⚠️ **Moved out of this repo on 2026-08-21. They now live in
`~/repos/command-center/research/machine-findings-2026-08.md` (private).**

**This repo is PUBLIC.** Those notes were personal machine state — installed
software by name, storage layout, filesystem corruption found by SFC — and none
of it was documentation *of the tool*. It was working notes about one person's
machines, published to the world by accident of where it was written down.

They are **not** genericized, because a generic version is a useless version:
*"a media service is still running"* does not tell you what to uninstall. Full
detail is preserved in the private file; only the location changed.

**Findings belong there. Script defects belong here.** If a future run surfaces
something about the machine rather than about the tool, write it to
`command-center`, not to this file.

### Open — optional

- [ ] Scheduled-task wrapper for a monthly auto-run.
