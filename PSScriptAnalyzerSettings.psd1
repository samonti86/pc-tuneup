@{
    # PSScriptAnalyzer config for pc-tuneup. Each excluded rule is a DELIBERATE,
    # justified exception for this script's nature -- not a blanket silencer.
    #
    #  PSAvoidUsingWriteHost
    #    This is an interactive, colorized console tool that transcript-logs every run.
    #    Write-Host (with -ForegroundColor) IS the intended output channel here. The
    #    rule exists to stop libraries/modules from polluting the pipeline; it doesn't
    #    apply to a top-level operator-facing script.
    #
    #  PSUseShouldProcessForStateChangingFunctions
    #    The script implements its OWN uniform preview gate (-DryRun -> Confirm-Action),
    #    which also covers native EXEs (sfc/DISM/chkdsk/netsh/powercfg) that the
    #    cmdlet-only -WhatIf/ShouldProcess machinery can't gate. Adopting ShouldProcess
    #    would be redundant for the cmdlet paths and impossible for the native ones.
    #
    #  PSUseSingularNouns
    #    The flagged names (Update-Apps, Optimize-Drives, Clear-TempFiles, Find-CrashLoops,
    #    Repair-CrashLoops, Test-CommandExists) are INTERNAL helpers, never exported. The
    #    singular-noun convention targets public cmdlet surfaces; renaming would only churn
    #    call sites with no caller-facing benefit.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSUseSingularNouns'
    )
}
