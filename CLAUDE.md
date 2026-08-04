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
- [x] Two bug fixes from a -DeepClean -NetworkReset run (2026-06-08): (1) 'netsh int ip reset'
      returns exit 1 + "Access is denied" on ONE ACL-locked NSI registry key (HKLM\...\Nsi\...)
      that Windows blocks even for elevated admin/SYSTEM -- the rest of the stack still resets.
      Reset-NetworkStack now captures the output and reports Partial (benign) when it ran but
      only ACL-locked keys were denied, instead of a hard Failure. Deliberately do NOT take key
      ownership (risky ACL surgery, no benefit). (2) powercfg /output path was wrapped in manual
      quotes ("`"$path`""), so the native exe saw a leading '"', treated the absolute path as
      RELATIVE, and prepended the cwd -- mislocating the energy/battery report. Fixed by passing
      the bare path (PS auto-quotes native args with spaces). Parse + PSSA-clean; netsh classifier
      verified against the real log output (2026-06-08)
- [x] Health-report RECENCY (2026-06-08, user feedback): stale events (e.g. crashes from an app
      since uninstalled) cluttered the 7d view with no way to tell active from resolved. Added
      per-issue first/last-seen timestamps + a "last 24h" count + a "(no activity in last 24h --
      may already be resolved)" tag; sort is now severity -> recent-active -> volume so live issues
      bubble up. New -EventDays N param (default 7, 1-365) narrows the window. Verified on live
      logs 5.1+7.6: App crashes (ExpressVPN, uninstalled) correctly tagged stale/0-recent; Service
      crashes 40-in-24h sorted above it; -EventDays 1 drops the stale categories (2026-06-08)
- [x] ExpressVPN post-uninstall investigation (2026-06-08): the ~40 service crashes "in last 24h"
      were REAL but PRE-uninstall -- 7031 crashes 11:40-11:55 AM, user uninstalled ~2:08 PM (7040
      events), tuneup ran 2:19 PM, so this morning's crashes were still inside the 24h window. Win32
      services genuinely gone (Get-Service none). BUT uninstall left 2 orphaned KERNEL DRIVERS still
      RUNNING: expressvpntun + tapexpressvpn (Type=1, Start=manual) -- invisible in services.msc
      (drivers, not services). No leftover Run keys / scheduled tasks / install folders. User action:
      'sc.exe stop/delete expressvpntun tapexpressvpn' then reboot (already pending from chkdsk /f /r)
- [x] End-to-end proofread + public-repo documentation pass (2026-08-03). Full read of all
      1170 lines looking for correctness bugs. Found and fixed 4 real ones + 3 hygiene:
      (1) SELF-ELEVATION DROPPED VALUE PARAMS -- the forwarding loop only re-passed
      switches (`$kv.Value -is [switch] -and .IsPresent`), so `-EventDays 1` from a
      non-elevated prompt silently reverted to the default 7 in the elevated child. No
      error, just wrong behavior. Now forwards name+value for non-switch params (quoting
      values containing whitespace) and skips a hand-passed -Relaunched to avoid a
      duplicate-parameter bind error. Verified with 4 cases incl. the exact bug.
      (2) DISM EXIT 3010 = ERROR_SUCCESS_REBOOT_REQUIRED was reported FAILED -- Invoke-Native
      only accepted 0, so a successful RestoreHealth/StartComponentCleanup needing a reboot
      looked like a hard failure (same false-failure class as the netsh fix). Both DISM call
      sites now pass -SuccessCodes @(0,3010); Invoke-Native labels 3010 'success; reboot
      required'. Verified via `cmd /c exit 3010`.
      (3) chkdsk /f /r scheduling never checked $LASTEXITCODE -- flat 'OK' even if scheduling
      failed, promising a boot-time check that would never run. Now Partial + warning on
      non-zero (pending-reboot report is the cross-check).
      (4) TRANSCRIPT HIJACK -- if the caller already had a transcript running, Start-Transcript
      errored and the unconditional Stop-Transcript in `finally` tore down THEIR transcript.
      Now tracks $script:TranscriptStarted and only stops its own; warns + continues if it
      can't log.
      Hygiene: @() guard in Get-WingetIdFromListing (single surviving line -> bare [string]
      broke [array]::IndexOf); Detail fallback so an app-crash category built only from hangs
      (1002)/.NET Runtime events can't render a blank line; summary Format-Table -Wrap so the
      Detail column stops truncating; numbered the 2 unnumbered sections (Recycle Bin -> 6b,
      Store -> 11) so printed headers run 0..11 and docs can mirror them exactly.
      UX: added internal -Relaunched switch -- the UAC-spawned window used to slam shut on
      completion, taking the whole report with it; it now pauses on Enter. Gated so an
      already-elevated/scheduled run never blocks on input.
      NOT changed (deliberate): w32tm `/resync /force` -- suspected invalid, but empirically
      w32tm ACCEPTS /force (an invalid flag like /bogusflag fails with 0x80070057, /force
      doesn't). Left as-is. Also left: script still returns exit 0 even when steps fail
      (documented as a known limitation in README rather than silently changing behavior).
      Verified: parse OK 5.1 + 7.6, PSSA clean, AST-loaded smoke test of every changed path.
- [x] README rewritten as a public-repo front door (2026-08-03): TOC, requirements, install
      (incl. Unblock-File), quick start, step-by-step table matching the script's printed
      numbering, always-on report table, health-analysis anatomy with an ILLUSTRATIVE
      (not real-machine -- repo is public) example, full param table, 9 copy-paste recipes,
      status-code glossary, logs + PRIVACY warning (logs name drives/apps/DNS/startup --
      review before pasting into an issue), safety model + explicit "will not do" list,
      11-entry FAQ, scheduled-task recipe, compatibility (incl. PS7 Checkpoint-Computer
      caveat + non-English parsing caveat), dev/sanity-gate section.
- [x] FIRST FULL ELEVATED RUN OF THE PROOFREAD BUILD (2026-08-04, tuneup-2026-08-03-160954):
      `-DeepClean -FlushUpdateCache -NetworkReset -RepairIssues -ResetStore` on Win11 26200.
      Validated in production: 6b/11 numbering, DISM 3010 handling, netsh Partial classifier,
      Defender engine-inactive skip, restore point, 10.64 GB reclaimed by /ResetBase. The new
      chkdsk exit-code check EARNED ITS KEEP -- caught `chkdsk /f /r` exiting 3 (would have
      been a silent false 'OK' before). 3 new bugs found from the real output + fixed:
      (1) ELAPSED TIME DROPPED WHOLE HOURS. '{0:mm}' is the minutes-WITHIN-HOUR component, so
      the 62-minute run printed "Elapsed: 01m 59s". Confirmed by log file span (16:09:54 ->
      17:11:54 = 62 min) and by formatting a 3719s TimeSpan. Now formats hours explicitly AND
      times with a MONOTONIC [Diagnostics.Stopwatch] instead of Get-Date subtraction -- the
      script resyncs the clock itself at step 10, so wall-clock deltas are self-corruptible
      (CLOCK_MONOTONIC vs CLOCK_REALTIME). NOTE: investigated whether the clock actually
      jumped mid-run -- it did NOT (Kernel-General id 1 shows only a 2ms delta at 17:51,
      after the run). The hypothesis was wrong; the run really did take 62 min.
      (2) chkdsk /f /r piped its output to Out-Null, discarding the ONLY evidence of why it
      exited 3. Now captures + prints it, and -- more importantly -- VERIFIES the end state
      with `chkntfs C:` instead of inferring from the exit code (an exit code is a claim;
      chkntfs is the actual scheduled state). Reports Failed + the manual command when no
      check is really scheduled.
      (3) STARTUP AUDIT WAS UNREADABLE: Win32_StartupCommand.Location embeds a ~50-char raw
      SID for HKU entries; Format-Table -AutoSize -Wrap starved the column to ~8 chars and
      wrapped it ONE CHARACTER PER LINE. Now collapses to hive+leaf ('HKU\...\Run') and clips
      the command; verified against this box's 12 startup entries.
      Also: Windows Update now reports update COUNT ('none available' vs 'N update(s)') --
      previously a no-op and a real install both rendered as a bare 'OK' with an empty body.
      README timing corrected (a -DeepClean pass measured at just over an hour, not 20-45 min).
      Machine findings (not script bugs): WSearch crash-loop is REAL and actionable --
      Microsoft-Windows-Search 3602/7042 x8 each ("Recovery phase failed", 0x80040d23,
      "please recreate the index") + WSearch 7031/7023 x12 ("A specified logon session does
      not exist") = corrupt SystemIndex catalog; the tool's own advice (rebuild the index) is
      the right fix. ESENT 902 x66 is NOT search-related (hypothesis was wrong): it's Unistore
      (Mail/Calendar/People sync DB) reporting "multiple threads illegally using the same
      database session" -- a Microsoft-internal threading defect, benign, not user-fixable.
      Verified: parse OK 5.1, PSSA clean, AST-loaded smoke test of all 3 fixes.
- [x] chkdsk /f /r SCHEDULING ACTUALLY FIXED (2026-08-04, user-driven: they want -DeepClean
      usable on OTHER people's machines -- friends' PCs, possible spinning disks where /r's
      bad-sector surface scan is the whole point -- so "fails honestly" wasn't good enough).
      Root cause, found by empirical elimination on the live box:
      (1) FIRST HYPOTHESIS WRONG: guessed the output redirection (`| Out-Null`) suppressed
      chkdsk's "schedule at next restart? (Y/N)" prompt. Removing it DID restore the prompt --
      but chkdsk then asked THREE TIMES and aborted, still scheduling nothing. So redirection
      was a red herring; the piped answer was never consumed.
      (2) ACTUAL CAUSE: a PowerShell pipeline does NOT satisfy that prompt. `'Y' | chkdsk.exe
      C: /f /r` leaves it unanswered (3 re-prompts, nothing scheduled). `cmd.exe /c
      "echo y|chkdsk C: /f /r"` answers it correctly -> "This volume will be checked the next
      time the system restarts" + chkntfs confirms "scheduled manually to run on next reboot".
      Fix = let CMD do the piping. DO NOT "simplify" it back to a native PS pipe.
      (3) BONUS TRAP: chkdsk returns EXIT 3 EVEN WHEN SCHEDULING SUCCEEDS. Measured exit 3
      both when nothing was scheduled AND when chkntfs then confirmed it was. The exit code
      carries zero signal here -- so the code now IGNORES it entirely and reports purely on
      the chkntfs-verified end state (Partial if chkntfs itself returns nothing). This is the
      strongest vindication yet of the project's verify-the-end-state-over-the-return-code rule.
      Deliberately NOT done: writing BootExecute (`autocheck autochk /r \??\C:`) directly. It
      was the fallback plan for a true /r if cmd failed, but the safe documented path works,
      so no registry surgery in the boot path -- holds the project's conservative line.
      README: step-4 row documents the chkntfs verification; new FAQ entry "Did the boot-time
      chkdsk actually run?" (chkntfs before, Wininit 1001 in the Application log after,
      `chkntfs /x C:` to cancel); -DeepClean row warns /r reads every sector and can take
      HOURS on a large spinning disk with the machine unusable at the boot screen.
- [x] Windows Search root-caused (2026-08-04): WSearch has crashed ~1x/day for the FULL 60-day
      log retention, always 21-22s after a system start, never mid-session -- a deterministic
      STARTUP RACE (7023 "A specified logon session does not exist"), not index corruption.
      That is why the user's repeated index rebuilds never stuck: a rebuild cannot fix a
      timing problem. Suggested `sc.exe config WSearch start= delayed-auto` as the reversible
      mitigation. SEPARATELY found a stale crawl scope pointing at `file:///E:\[38115ef8-...]`
      (drive absent; only C: and an empty D: exist) present in BOTH WorkingSetRules AND
      DefaultRules -- DefaultRules is the baseline re-applied on every rebuild, so it outlived
      every rebuild. User removed it via Indexing Options (it renders as a GUID folder marked
      "not available" because the volume is unmounted). NOTE: hypothesis that E:\ CAUSED the
      boot crash was DISPROVEN -- its error (id 1019) fired once in 30 days, during the
      rebuild, never at a boot crash. Two independent problems, not one.
      Also disproven this session: ESENT 902 x66 is Unistore (Mail/Calendar/People sync DB)
      reporting a Microsoft-internal threading defect -- unrelated to Search, not user-fixable.
- [x] FIRST WINDOWS 10 RUN (2026-08-04, Win10 22H2 / 19045, PS 5.1 Desktop):
      `-DeepClean -NetworkReset -RepairIssues -FlushUpdateCache`. Cross-version core all
      ported clean -- cmd-piped chkdsk /f /r scheduling + chkntfs verification, netsh
      Partial classifier, DISM 3010, elapsed formatting, update-count reporting; Defender
      actually ran a QuickScan here (Win11 box has Malwarebytes primary, so this was the
      first real exercise of that path). 2 steps FAILED + 1 silently vanished -> 5 bugs
      found and fixed:
      (1)+(2) SAME ROOT CAUSE. Ombi (ASP.NET Core) uses the EventLog logging provider
      without setting a SourceName, so it inherits the SHARED '.NET Runtime' event source
      and writes its OWN ILogger EventId -- which is 1000. The app-crash extractor filtered
      on `$_.Id -eq 1000` ALONE, so it read those as Application Error records, and
      Properties[0] (the exe name for a real crash) was instead Ombi's entire multi-line
      log message. That both dumped ~40 lines of stack trace into the report AND crashed
      step 1b when the blob reached [IO.Path]::GetFileNameWithoutExtension().
      >>> THE LESSON: that API THROWS "Illegal characters in path" on .NET Framework (5.1)
      and SILENTLY ACCEPTS the same input on .NET Core (7.x). Verifying under both 5.1 and
      7.6 does NOT protect you here -- the bug is INVISIBLE under 7 and only detonates on
      5.1, the shipping target. Treat "works in pwsh" as no evidence at all for this class.
      Fixes: $appErr now provider-scoped to 'Application Error' (Event-ID-1000 collision,
      same trap as podman one layer deeper); new Test-PlausibleFileName guard so
      Resolve-WingetId DECLINES rather than throws; new Format-EventToken collapses/clips
      any event string before it reaches the report; KB rule split so '.NET Runtime'
      1023/1026/1027 stays 'App crashes' while everything else becomes a new Low-severity
      'App error logs (.NET)' category whose advice points at app config, not Windows tools.
      (3) STEP 5 SILENTLY VANISHED FROM THE SUMMARY -- the worst failure mode this tool has.
      Get-Volume failed (broken Storage WMI provider, see below), $volumes came back empty,
      the foreach had nothing to iterate, and NO Add-Result ever ran. Not Failed, not
      Skipped: absent. Optimize-Drives now derives the system drive from $env:SystemDrive
      (so the DEFAULT path needs no WMI at all), falls back to Win32_LogicalDisk then to
      `defrag.exe /O`, and ALWAYS records an outcome.
      (4) Get-PhysicalDisk was outside any try/catch. Note its error surfaced from the
      ENUMERATOR ("Exception calling MoveNext"), i.e. terminating mid-pipeline -- so
      -ErrorAction SilentlyContinue would NOT have saved it either. Now falls back to
      Win32_DiskDrive (classic CIMv2, unaffected) and reports Partial.
      (5) Service-crash culprits read Properties[0] unconditionally, but SCM puts the
      service name at [1] on the two TIMEOUT events (7009/7011) where [0] is the timeout in
      ms -- so the top culprit rendered as "30000" and the same service was counted twice.
      New Get-EventServiceName picks the index by event id. Verified against real SCM
      events on the Win11 box.
      Verified: parse OK 5.1 + pwsh, PSSA clean, AST-loaded smoke tests of every fix under
      5.1 SPECIFICALLY (incl. shadowing Get-Volume/Get-CimInstance to simulate the Win10
      C/D/M/T layout and the broken-provider path).
- [x] Step 5 scoped to the SYSTEM DRIVE by default + new opt-in `-OptimizeAllDrives`
      (2026-08-04, user decision). The Win10 box has 33 TB and 22 TB fixed volumes attached;
      once bug (3) was fixed, step 5 would have started actually optimizing them -- a
      potentially multi-hour defrag inside a routine that otherwise takes ~15 min, which is
      unacceptable on someone else's PC. Non-system drives still get a `Skipped` summary row
      (what we did NOT touch is part of an honest report).
- [ ] Machine findings from the Win10 box (NOT script bugs, tracked so they aren't lost):
      Computer Browser service crash-looping ~267x/7d (user disabling via
      `sc.exe config Browser start= disabled`; needs `sc.exe stop Browser` to take effect
      now, revert with `start= demand`). Ombi still RUNNING despite the user believing it
      was uninstalled -- proven by recency (51 events in last 24h, last one 54 min before
      the run started); likely a leftover Windows SERVICE, which is why it's invisible in
      the startup audit (that reads Win32_StartupCommand, which does not cover services) --
      same shape as the ExpressVPN orphaned-driver finding. Its errors are a Sonarr v2 API
      path (`/api/series`, moved to `/api/v3/series` in Sonarr v3+) and a retired Plex
      endpoint returning 410 Gone. SFC found and repaired real corruption -- re-run
      `sfc /scannow` after reboot to confirm clean. Storage WMI provider broken (hypothesis,
      UNVERIFIED: third-party storage/pooling provider, given the 33/22 TB volumes report as
      local fixed disks); check `winmgmt /verifyrepository`. Box is Win10 22H2, out of
      mainstream support since 2025-10-14 -- confirm whether it's on consumer ESU.
- [x] COMMENT-BASED HELP WAS SILENTLY DEAD (2026-08-04, found incidentally while verifying
      the new -OptimizeAllDrives param during close-out). `Get-Help .\Invoke-PCTuneup.ps1`
      returned a bare auto-generated SYNTAX STRING, not help: 0 parameters, 0 examples,
      no description -- every .PARAMETER/.EXAMPLE in the 90-line help block was invisible,
      and the README explicitly promises `Get-Help -Full` works. Cause: `#Requires -Version
      5.1` sat IMMEDIATELY adjacent to the opening `<#`. PowerShell then does not associate
      the block with the script; one blank line between them fixes it. Verified pre-existing
      (HEAD had it too), and isolated with a 3-case minimal repro (no-#Requires / adjacent /
      blank-line-after) rather than guessed. Then hit a SECOND instance of the same class
      immediately: the explanatory comment written to document the fix contained a literal
      `#>`, which terminated the help block early and re-broke it -- and also corrupted the
      bisect that was hunting it. Both traps now recorded in the sanity gate above, which
      gained a Get-Help assertion, because this failure mode is 100% silent.
      Now: 13 params, 3 examples, real synopsis, on BOTH 5.1 and pwsh.
- [x] Test on a Windows 10 machine to confirm cross-version behavior (2026-08-04, above)
- [ ] Optional: add to command-center projects-index
- [ ] Optional: scheduled-task wrapper for monthly auto-run
