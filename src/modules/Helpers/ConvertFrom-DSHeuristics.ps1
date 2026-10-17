<#
.SYNOPSIS
    Reads the characters of dsHeuristics that switch a protection off.

.DESCRIPTION
    dsHeuristics on CN=Directory Service,CN=Windows NT,CN=Services in the configuration
    partition is one string for the whole forest, with one heuristic per character
    (MS-ADTS 6.1.1.2.4.1.2). The order of the characters is fixed and a character can only
    be left out by truncating the string, so a character beyond the end has its default,
    "0" - the secure value of each heuristic read here.

    Character 7, fLDAPBlockAnonOps: "2" lets an anonymous client do more than bind and read
    rootDSE. Anything else blocks it.

    Character 8, fAllowAnonNSPI: anything but "0" allows anonymous calls to the bind method
    of NSPI, the address book interface over RPC.

    Character 16, dwAdminSDExMask: a hex digit, each bit of which takes a group and its
    direct and transitive members out of AdminSDHolder protection - 0x1 Account Operators,
    0x2 Server Operators, 0x4 Print Operators, 0x8 Backup Operators (3.1.1.6.1.4). The
    specification lists "0"-"9" and "a"-"f"; an upper-case letter is read as the same
    digit, since whoever wrote it meant those bits.

    Character 21, DoNotVerifyUPNAndOrSPNUniqueness: in AD DS a number whose bits switch off
    a uniqueness check on write - bit 0 userPrincipalName, bit 1 servicePrincipalName,
    bit 2 SPN alias uniqueness. "0" to "7" are the values the specification defines.

    A character outside the values its heuristic defines gets no meaning here: the
    Mask/Disabled fields stay $null and the caller says the heuristic is unknown.

.PARAMETER Value
    The attribute value. Empty or $null when the attribute is not set.

.OUTPUTS
    PSCustomObject with the character and the reading of each heuristic.
#>
function ConvertFrom-DSHeuristics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value
    )

    $text = [string]$Value

    # The effective character at each position read below: what the string holds, or the
    # default "0" beyond its end.
    $character = @{}
    foreach ($position in @(7, 8, 16, 21)) {
        $character[$position] = if ($text.Length -ge $position) { [string]$text[$position - 1] } else { '0' }
    }

    # Character 16 - the operator groups AdminSDHolder no longer protects.
    $adminSDExMask = $null
    if ($character[16] -match '^[0-9a-fA-F]$') {
        $adminSDExMask = [Convert]::ToInt32($character[16], 16)
    }
    $excludedGroups = @()
    if ($null -ne $adminSDExMask) {
        foreach ($operatorGroup in @(
            @{ Bit = 0x1; SID = 'S-1-5-32-548'; Name = 'Account Operators' }
            @{ Bit = 0x2; SID = 'S-1-5-32-549'; Name = 'Server Operators' }
            @{ Bit = 0x4; SID = 'S-1-5-32-550'; Name = 'Print Operators' }
            @{ Bit = 0x8; SID = 'S-1-5-32-551'; Name = 'Backup Operators' }
        )) {
            if ($adminSDExMask -band $operatorGroup.Bit) {
                $excludedGroups += [PSCustomObject]@{ SID = $operatorGroup.SID; Name = $operatorGroup.Name }
            }
        }
    }

    # Character 21 - the uniqueness checks the domain controllers skip.
    $uniquenessMask = $null
    if ($character[21] -match '^[0-7]$') {
        $uniquenessMask = [int]$character[21]
    }
    $uncheckedNames = @()
    if ($null -ne $uniquenessMask) {
        if ($uniquenessMask -band 0x1) { $uncheckedNames += 'UPN' }
        if ($uniquenessMask -band 0x2) { $uncheckedNames += 'SPN' }
        if ($uniquenessMask -band 0x4) { $uncheckedNames += 'SPN alias' }
    }

    [PSCustomObject]@{
        Value                  = $text
        AnonymousLDAPCharacter = $character[7]
        AnonymousLDAP          = ($character[7] -eq '2')
        AnonymousNSPICharacter = $character[8]
        AnonymousNSPI          = ($character[8] -ne '0')
        AdminSDExMaskCharacter = $character[16]
        AdminSDExMask          = $adminSDExMask
        AdminSDExcludedGroups  = $excludedGroups
        UniquenessCharacter    = $character[21]
        UniquenessMask         = $uniquenessMask
        UncheckedUniqueness    = $uncheckedNames
    }
}
