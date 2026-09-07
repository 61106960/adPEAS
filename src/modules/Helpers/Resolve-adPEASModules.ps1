function Resolve-adPEASModules {
    <#
    .SYNOPSIS
    Works out which check modules a run executes, from -Module and -ExcludeModule.

    .DESCRIPTION
    Resolves both parameters against the canonical list in $Script:adPEASModules rather
    than against what the caller typed. That is what makes the result normalized in three
    ways at once:

      - Casing. ValidateSet binds case-insensitively, so "-Module gpo" arrives as "gpo"
        and would be echoed that way in "Executing Modules:".
      - Order. The module blocks in Invoke-adPEAS run in a fixed sequence regardless of
        the order they were asked for, so "-Module GPO,Domain" already runs Domain first.
        Returning the list in that same order means the announced list is the run order.
      - Duplicates. "-Module Domain,Domain" is one module.

    Exclusion is applied after selection, so the two combine as "these, minus those".
    They are deliberately not mutually exclusive: -ExcludeModule alone is the case this
    exists for, but "-Module Domain,GPO,Creds -ExcludeModule Creds" is a meaningful thing
    to ask for and there is no reading of it that is ambiguous.

    Returns an empty array when nothing is left to run. That is the caller's error to
    report, not this function's - it has no opinion on whether an empty run is a mistake.

    .PARAMETER Module
    The modules to run. Empty or absent means all of them.

    .PARAMETER ExcludeModule
    Modules to drop from that selection. A name that is not in the selection anyway is
    not an error - excluding something already excluded is a no-op, not a contradiction.

    .EXAMPLE
    Resolve-adPEASModules -ExcludeModule 'Bloodhound'

    Every module except BloodHound.

    .EXAMPLE
    Resolve-adPEASModules -Module 'GPO','Domain'

    Returns Domain, GPO - canonical order, which is the order they will run in.

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Module,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ExcludeModule
    )

    $selected = if ($Module -and @($Module).Count -gt 0) {
        @($Script:adPEASModules | Where-Object { $_ -in $Module })
    } else {
        @($Script:adPEASModules)
    }

    if ($ExcludeModule -and @($ExcludeModule).Count -gt 0) {
        $selected = @($selected | Where-Object { $_ -notin $ExcludeModule })
    }

    return @($selected)
}
