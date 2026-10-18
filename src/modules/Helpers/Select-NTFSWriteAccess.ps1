<#
.SYNOPSIS
    Returns the trustees an NTFS rule list lets write a file or folder, past the two
    identity gates a GPO is judged by.

.DESCRIPTION
    Shared by the two checks that read NTFS permissions over SMB: Get-GPOPermissions for the
    policy folder in SYSVOL, and Get-GPOScheduledTasks for the program a SYSTEM or privileged
    task starts from a share. Both ask the same question - who besides the accounts expected to
    administer Group Policy can change what a policy makes every computer in scope run -
    and the evaluation used to exist only inside the first of them.

    Deny first and per trustee: a Deny rule wins the access check, so an Allow it covers
    grants nothing. Masks rather than names, because FileSystemRights is a flag field and
    the combinations that occur in practice - FullControl, Modify, Write - do not decompose
    into a fixed set of names.

    The same two gates the directory half of Get-GPOPermissions uses, so one identity is not
    expected on the object and a finding on its folder:
      Test-IsExpectedACLIdentity -Context 'GPO'   skips the default administrators
      Test-IsExpectedInScope -Scope 'GPO'         skips Expected, and Attention unless
                                                  -IncludePrivileged is set

.PARAMETER Rules
    The access rules, as Get-DirectoryAccessRules or Get-FileAccessRules return them. The
    function reads IdentityReference.Value, FileSystemRights, AccessControlType and
    IsInherited, and PropagationFlags under -SkipInheritOnly - rule-shaped objects work too.

.PARAMETER Target
    The path the rules belong to. Used in the log only.

.PARAMETER Caller
    The name the log lines carry.

.PARAMETER IncludePrivileged
    Keep the trustees Test-IsExpectedInScope rates Attention instead of skipping them.

.PARAMETER SkipInheritOnly
    Ignore rules that only reach the children of a folder. Right for a folder read for its
    own sake - who may create a file in it - and wrong for a policy folder, whose children
    are the policy: an inherit-only Modify on it reaches every file the policy consists of.

.OUTPUTS
    [PSCustomObject] per trustee, with SID, Identity, Rights, IsInherited and Row - Row
    being the "Identity (Rights)" line the reports print, with the inheritance note behind
    it. Nothing when no rule passes.

.NOTES
    Internal helper. Pure: it reads nothing but its arguments and the identity classifiers,
    so a unit test can drive it with rule-shaped objects.
#>
function Select-NTFSWriteAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rules,

        [Parameter(Mandatory = $false)]
        [string]$Target,

        [Parameter(Mandatory = $false)]
        [string]$Caller = 'Select-NTFSWriteAccess',

        [Parameter(Mandatory = $false)]
        [switch]$IncludePrivileged,

        [Parameter(Mandatory = $false)]
        [switch]$SkipInheritOnly
    )

    # The NTFS rights that let their holder rewrite the content of a file or folder.
    #
    # WriteAttributes and WriteExtendedAttributes are deliberately not in it: they change
    # timestamps and metadata, not content, and including them would put a finding on the
    # default ACL of every policy folder in the domain. On a file, CreateFiles and
    # CreateDirectories are the same bits as WriteData and AppendData.
    $writeMask = [int](
        [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor
        [System.Security.AccessControl.FileSystemRights]::CreateDirectories -bor
        [System.Security.AccessControl.FileSystemRights]::Delete -bor
        [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [System.Security.AccessControl.FileSystemRights]::TakeOwnership
    )
    $inheritOnly = [int][System.Security.AccessControl.PropagationFlags]::InheritOnly

    # The generic bits mapped to the file rights they stand for, the GenericMapping of a file
    # object. An inherit-only entry of a folder ACL keeps them as written - measured, every
    # default policy folder holds GENERIC_ALL (0x10000000) for SYSTEM, Administrators and
    # CREATOR OWNER - and such entries are exactly the rights the files of a policy folder
    # receive. Unmapped, 0x10000000 shares no bit with the write mask, and a trustee holding
    # it passed as one that cannot write.
    $mapFileRights = {
        param($Rights)
        $mask = ([long]$Rights) -band 0xFFFFFFFFL
        if ($mask -band 0x10000000L) { $mask = $mask -bor 0x1F01FFL }   # GENERIC_ALL -> FILE_ALL_ACCESS
        if ($mask -band 0x40000000L) { $mask = $mask -bor 0x120116L }   # GENERIC_WRITE -> FILE_GENERIC_WRITE
        if ($mask -band 0x80000000L) { $mask = $mask -bor 0x120089L }   # GENERIC_READ -> FILE_GENERIC_READ
        if ($mask -band 0x20000000L) { $mask = $mask -bor 0x1200A0L }   # GENERIC_EXECUTE -> FILE_GENERIC_EXECUTE
        return [int]($mask -band 0x0FFFFFFFL)
    }

    $applicable = @()
    foreach ($rule in @($Rules)) {
        if ($null -eq $rule) { continue }
        if ($SkipInheritOnly -and $rule.PSObject.Properties['PropagationFlags'] -and
            (([int]$rule.PropagationFlags) -band $inheritOnly)) {
            continue
        }
        $applicable += $rule
    }

    # Explicit and inherited Deny apart: the access check evaluates every explicit entry
    # first, so an inherited Deny takes nothing from an Allow written on the object itself.
    $deniedExplicit = @{}
    $deniedInherited = @{}
    foreach ($rule in $applicable) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Deny) { continue }
        $denySID = [string]$rule.IdentityReference.Value
        if (-not $denySID) { continue }
        if ($rule.IsInherited) { $deniedMask = $deniedInherited } else { $deniedMask = $deniedExplicit }
        if (-not $deniedMask.ContainsKey($denySID)) { $deniedMask[$denySID] = 0 }
        $deniedMask[$denySID] = $deniedMask[$denySID] -bor (& $mapFileRights $rule.FileSystemRights)
    }

    $result = @()
    foreach ($rule in $applicable) {
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

        $ruleSID = [string]$rule.IdentityReference.Value
        if (-not $ruleSID) { continue }

        $effective = & $mapFileRights $rule.FileSystemRights
        if ($deniedExplicit.ContainsKey($ruleSID)) {
            $effective = $effective -band (-bnot $deniedExplicit[$ruleSID])
        }
        if ($rule.IsInherited -and $deniedInherited.ContainsKey($ruleSID)) {
            $effective = $effective -band (-bnot $deniedInherited[$ruleSID])
        }

        $writeBits = $effective -band $writeMask
        if ($writeBits -eq 0) { continue }

        $expected = Test-IsExpectedACLIdentity -SID $ruleSID -Context 'GPO'
        if ($expected.Skip) { continue }

        $scope = Test-IsExpectedInScope -Identity $ruleSID -Scope 'GPO' -ReturnDetails
        if ($scope.Severity -eq 'Expected') { continue }
        if (-not $IncludePrivileged -and $scope.Severity -eq 'Attention') {
            Write-Log "[$Caller] Attention: $ruleSID can write $Target - $($scope.Reason) - skipped (use -IncludePrivileged to include)"
            continue
        }

        $identity = ConvertFrom-SID -SID $ruleSID
        if (-not $identity) { $identity = $ruleSID }

        # The effective rights, not the write bits of them: an admin reads "FullControl" in
        # Explorer, not the six flags it decomposes into. Where a Deny took something away
        # the name changes with it, which is the point. Synchronize sits on every rule and
        # says nothing.
        $rightsText = ([System.Security.AccessControl.FileSystemRights]$effective).ToString() -replace '(,\s*)?Synchronize', ''
        if (-not $rightsText) { $rightsText = "$writeBits" }

        $row = "$identity ($rightsText)"
        if ($rule.IsInherited) {
            $row = "$row [inherited - remove it at the parent folder]"
        }

        Write-Log "[$Caller] FINDING: $identity can write $Target ($rightsText)"
        $result += [PSCustomObject]@{
            SID         = $ruleSID
            Identity    = [string]$identity
            Rights      = $rightsText
            IsInherited = [bool]$rule.IsInherited
            Row         = $row
        }
    }

    # Unrolled into the pipeline: nothing to report arrives as nothing, and the callers
    # collect with @(). Unlike Get-DirectoryAccessRules there is no third state to keep
    # apart - an unreadable list never reaches this function.
    return $result
}
