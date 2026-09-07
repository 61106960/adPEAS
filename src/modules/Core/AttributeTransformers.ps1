<#
.SYNOPSIS
    Attribute transformer functions for the RenderModel pipeline.

.DESCRIPTION
    Contains all transformer functions that convert raw AD attribute values into RenderValue arrays with severity, FindingId, and display text.
    Each transformer is registered in $Script:AttributeTransformers and called by Get-RenderModel when processing the corresponding attribute.
    Attributes without a registered transformer use Convert-DefaultToRenderValues
    (defined in Get-RenderModel.ps1).

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Requires: Get-RenderModel.ps1, adPEAS-FindingDefinitions.ps1
#>

# ============================================================================
# Helper Functions
# ============================================================================

<#
.SYNOPSIS
    Determines the severity class for an attribute value.
.DESCRIPTION
    Delegates to Get-SeverityFromTrigger which evaluates FindingDefinition triggers.
    Auto-detects computer accounts from SourceObject for context-aware classification.

    Severity Classes:
    - "Finding"  : Security vulnerability (red)
    - "Hint"     : Interesting/noteworthy (yellow)
    - "Note"     : General information (green)
    - "Secure"   : Secure configuration (special)
    - "Standard" : No special coloring (default)
.PARAMETER Name
    The attribute name (e.g., 'memberOf', 'servicePrincipalName').
.PARAMETER Value
    The attribute value (can be string, array, PSCustomObject, DateTime, etc.).
.PARAMETER IsComputer
    Set to $true if the object is a computer account (affects SPN classification).
.PARAMETER SourceObject
    Optional. The source AD object containing this attribute. Enables context-aware
    severity via Custom triggers (e.g., credential_needs_review, dangerous_rights_expected).
.RETURNS
    Severity class string: "Finding", "Hint", "Note", "Secure", or "Standard".
.EXAMPLE
    Get-AttributeSeverity -Name "servicePrincipalName" -Value "HTTP/server.domain.com"
    # Returns "Finding" for user accounts (Kerberoastable)

    Get-AttributeSeverity -Name "LDAPSigning" -Value "Required"
    # Returns "Secure"

    Get-AttributeSeverity -Name "dangerousRights" -Value "WriteDacl" -SourceObject $exchangeGroup
    # Returns "Hint" if $exchangeGroup.dangerousRightsSeverity is "Expected"
#>
function Get-AttributeSeverity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,

        [Parameter(Mandatory=$false)]
        $Value,

        [Parameter(Mandatory=$false)]
        [bool]$IsComputer = $false,

        [Parameter(Mandatory=$false)]
        $SourceObject = $null
    )

    # Auto-detect IsComputer from SourceObject if not explicitly set
    if (-not $IsComputer -and $SourceObject) {
        if ($SourceObject.objectClass) {
            $IsComputer = $SourceObject.objectClass -contains 'computer' -or
                          $SourceObject.objectClass -eq 'computer' -or
                          ($SourceObject.objectClass -is [string] -and $SourceObject.objectClass -match 'computer')
        }
        if (-not $IsComputer -and $SourceObject.sAMAccountName -and $SourceObject.sAMAccountName -match '\$$') {
            $IsComputer = $true
        }
    }

    # TemplateACL: promote to Primary (Note severity) only when a low-privileged identity
    # has write/modify rights on the template. All-privileged ACLs stay in Extended (Standard).
    if ($Name -eq 'TemplateACL' -and $Value) {
        $entries = if ($Value -is [array]) { $Value } else { @($Value) }
        foreach ($entry in $entries) {
            if (-not $entry.SID) { continue }
            $privResult = Test-IsPrivileged -Identity $entry.SID
            if (-not $privResult.IsPrivileged) {
                return 'Note'   # Non-Standard -> auto-promoted to Primary
            }
        }
        return 'Standard'   # All privileged -> stays in Extended
    }

    # Delegate to FindingDefinitions triggers (Single Source of Truth)
    $triggerSeverity = Get-SeverityFromTrigger -Name $Name -Value $Value `
        -IsComputer $IsComputer -SourceObject $SourceObject
    if ($null -ne $triggerSeverity) {
        return $triggerSeverity
    }

    # No trigger matched - default severity
    return "Standard"
}

<#
.SYNOPSIS
    Converts an array of Distinguished Names to objects with DisplayName, DN, and SID.
.DESCRIPTION
    Helper function that extracts the CN from each DN and resolves the SID using the central ConvertTo-SID helper function.
.PARAMETER DistinguishedNames
    Array of distinguished names to process.
.RETURNS
    Array of PSCustomObjects with DisplayName, DN, and SID properties.
#>
function Convert-DNsToMemberInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$DistinguishedNames
    )

    $DistinguishedNames | ForEach-Object {
        $dn = $_
        $cn = if ($dn -match '^CN=([^,]+)') { $Matches[1] } else { $dn }
        [PSCustomObject]@{
            DisplayName = $cn
            DN = $dn
            SID = ConvertTo-SID -Identity $dn
        }
    }
}

<#
.SYNOPSIS
    Classifies a member object by SID.
.DESCRIPTION
    Returns the severity class for a member based on SID-based group classification.
    Delegates to central Get-AttributeSeverity for classification.
.PARAMETER MemberInfo
    PSCustomObject with DisplayName, DN, and SID properties.
.RETURNS
    Severity class string.
#>
function Get-MemberClass {
    param($MemberInfo)
    Get-AttributeSeverity -Name 'Member' -Value $MemberInfo.SID
}

<#
.SYNOPSIS
    Classifies a member of an Exchange service group.
.DESCRIPTION
    For Exchange service groups, the classification is INVERTED from normal:
    - Low-privileged members are CRITICAL (Finding) - they shouldn't be in Exchange groups!
    - High-privileged accounts (Domain Admins, etc.) are expected (Hint)
    - Exchange service accounts (computers like EX01) are expected (Hint)
    - Other Exchange groups as members are expected (Hint)
.PARAMETER MemberInfo
    PSCustomObject with DisplayName, DN, and SID properties.
.RETURNS
    Severity class string: "Finding" for low-privileged, "Hint" for expected members.
#>
function Get-ExchangeGroupMemberClass {
    param($MemberInfo)

    $sid = $MemberInfo.SID
    $dn = $MemberInfo.DN

    # No SID available - cannot classify, treat as Hint (unknown)
    if (-not $sid) {
        return "Hint"
    }

    # Check if this is an Exchange service group itself (nested Exchange groups)
    if ($dn -and $dn -match 'OU=Microsoft Exchange Security Groups') {
        return "Hint"
    }

    # Check if this is an Exchange Server by SPN
    if ($Script:LdapConnection -and $sid) {
        try {
            $exchangeCheck = Test-IsExchangeServer -Identity $sid
            if ($exchangeCheck.IsExchangeServer) {
                return "Hint"
            }
        } catch {
            Write-Debug "[Get-ExchangeGroupMemberClass] Exchange server check failed for SID $sid - $($_.Exception.Message)"
        }
    }

    # Check if this is a computer account by querying AD for objectClass
    if ($Script:LdapConnection -and $sid) {
        try {
            $sidHex = ConvertTo-LDAPSIDHex -SID $sid
            if ($sidHex) {
                $obj = @(Get-DomainObject -LDAPFilter "(objectSid=$sidHex)" -Properties 'objectClass')[0]
                if ($obj -and $obj.objectClass) {
                    $objectClasses = @($obj.objectClass)
                    if ($objectClasses -contains 'computer') {
                        return "Hint"
                    }
                }
            }
        } catch {
            Write-Debug "[Get-ExchangeGroupMemberClass] Computer account check failed for SID $sid - $($_.Exception.Message)"
        }
    }

    # Use Test-IsPrivileged with -IncludeOperators for recursive group membership check
    $privilegeCheck = Test-IsPrivileged -Identity $sid -IncludeOperators
    if ($privilegeCheck.IsPrivileged -eq $true) {
        return "Hint"
    }

    # Fallback: Check if this is a computer account by DN pattern
    if ($dn -and ($dn -match 'CN=Computers,' -or $dn -match 'OU=.*Server')) {
        return "Hint"
    }

    # Fallback: Check if the account name ends with $ (computer account convention)
    $name = $MemberInfo.DisplayName
    if ($name -and $name -match '\$$') {
        return "Hint"
    }

    # Low-privileged account in Exchange group - CRITICAL!
    return "Finding"
}

<#
.SYNOPSIS
    Classifies a memberOf group by SID.
.PARAMETER GroupInfo
    PSCustomObject with DisplayName, DN, and SID properties.
.RETURNS
    Severity class string.
#>
function Get-MemberOfClass {
    param($GroupInfo)
    Get-AttributeSeverity -Name 'MemberOf' -Value $GroupInfo
}

<#
.SYNOPSIS
    Classifies a sIDHistory SID by security relevance.
.PARAMETER SID
    The SID string from sIDHistory.
.RETURNS
    Severity class string (Finding for privileged, Hint for non-privileged).
#>
function Get-SIDHistoryClass {
    param([string]$SID)
    Get-AttributeSeverity -Name 'sIDHistory' -Value $SID
}

# ============================================================================
# Transformer Functions
# ============================================================================

# --- memberOf Transformer ---
function Convert-MemberOfToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $memberOfArray = @($Value)
    $memberOfObjects = Convert-DNsToMemberInfo -DistinguishedNames $memberOfArray

    $renderValues = @()
    foreach ($groupInfo in $memberOfObjects) {
        $groupClass = Get-MemberOfClass -GroupInfo $groupInfo
        $findingId = switch ($groupClass) {
            'Finding' { 'PRIVILEGED_GROUP_MEMBERSHIP' }
            'Hint'    { 'OPERATOR_GROUP_MEMBERSHIP' }
            default   { $null }
        }
        $renderValues += New-RenderValue -Display $groupInfo.DisplayName `
            -Severity $groupClass -FindingId $findingId `
            -RawValue $groupInfo.DN -Metadata @{ SID = $groupInfo.SID }
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = ($maxSev -ne 'Standard')
        Values              = $renderValues
    }
}

# --- privilegedGroups Transformer ---
function Convert-PrivilegedGroupsToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $privGroupValues = @($Value)
    $firstItem = $privGroupValues | Select-Object -First 1
    $isNewFormat = $firstItem -is [PSCustomObject] -and $firstItem.PSObject.Properties['SID']

    $renderValues = @()

    if ($isNewFormat) {
        foreach ($entry in $privGroupValues) {
            $sid = $entry.SID
            $displayText = $entry.DisplayText
            $triggerResult = if ($sid) {
                Get-TriggerMatch -Name 'privilegedGroups' -Value $sid
            } else { [PSCustomObject]@{ Severity = 'Hint'; FindingId = $null } }

            $severity = if ($triggerResult.Severity -ne 'Standard') { $triggerResult.Severity } else { 'Standard' }
            $findingId = $triggerResult.FindingId
            $renderValues += New-RenderValue -Display $displayText `
                -Severity $severity -FindingId $findingId `
                -RawValue $entry -Metadata @{ SID = $sid }
        }
    } else {
        # Legacy format: plain strings
        foreach ($g in $privGroupValues) {
            $triggerResult = Get-TriggerMatch -Name 'privilegedGroups' -Value $g
            $severity = if ($triggerResult.Severity -ne 'Standard') { $triggerResult.Severity } else { 'Standard' }
            $renderValues += New-RenderValue -Display ([string]$g) -Severity $severity `
                -FindingId $triggerResult.FindingId -RawValue $g
        }
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = ($maxSev -ne 'Standard')
        Values              = $renderValues
    }
}

# --- member Transformer (with Exchange group inversion) ---
function Convert-MemberToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $memberArray = @($Value)
    $memberObjects = Convert-DNsToMemberInfo -DistinguishedNames $memberArray
    $isExchangeGroup = $Context.IsExchangeGroup

    $renderValues = @()
    foreach ($memberInfo in $memberObjects) {
        if ($isExchangeGroup) {
            $memberClass = Get-ExchangeGroupMemberClass -MemberInfo $memberInfo
            $findingId = switch ($memberClass) {
                'Finding' { 'EXCHANGE_GROUP_LOW_PRIV_MEMBER' }
                default   { $null }
            }
        } else {
            $memberClass = Get-MemberClass -MemberInfo $memberInfo
            $findingId = switch ($memberClass) {
                'Finding' { 'PRIVILEGED_GROUP_MEMBERSHIP' }
                default   { $null }
            }
        }
        $renderValues += New-RenderValue -Display $memberInfo.DisplayName `
            -Severity $memberClass -FindingId $findingId `
            -RawValue $memberInfo.DN -Metadata @{ SID = $memberInfo.SID }
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = $true
        Values              = $renderValues
    }
}

# --- userAccountControl Transformer ---
function Convert-UACToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $uacFlags = @($Value)
    $allFlagsStr = $uacFlags -join ' '
    $renderValues = @()
    foreach ($flag in $uacFlags) {
        $flagStr = [string]$flag
        # Pass allFlagsStr as SourceObject so is_dc_uac can check for SERVER_TRUST_ACCOUNT
        $match = Get-TriggerMatch -Name 'userAccountControl' -Value $flagStr -SourceObject $allFlagsStr
        $renderValues += New-RenderValue -Display $flagStr -Severity $match.Severity -FindingId $match.FindingId -RawValue $flag
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = ($maxSev -ne 'Standard')
        Values              = $renderValues
    }
}

# --- servicePrincipalName Transformer ---
function Convert-SPNToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $spnValues = @($Value)
    $renderValues = @()

    # SPNs on computers are standard (informational); on users they indicate Kerberoasting risk
    $isComputer = $Context.IsComputer

    foreach ($spn in $spnValues) {
        if ($isComputer) {
            $renderValues += New-RenderValue -Display ([string]$spn) -Severity 'Standard' -RawValue $spn
        } else {
            $match = Get-TriggerMatch -Name 'servicePrincipalName' -Value $spn -IsComputer $false
            $renderValues += New-RenderValue -Display ([string]$spn) -Severity $match.Severity -FindingId $match.FindingId -RawValue $spn
        }
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = (-not $isComputer)
        Values              = $renderValues
    }
}

# --- sIDHistory Transformer ---
function Convert-SIDHistoryToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $sidHistoryRaw = @($Value)
    $renderValues = @()

    foreach ($sidEntry in $sidHistoryRaw) {
        $sidString = $null
        if ($sidEntry -is [byte[]]) {
            try {
                $secId = New-Object System.Security.Principal.SecurityIdentifier($sidEntry, 0)
                $sidString = $secId.Value
            } catch { continue }
        } elseif ($sidEntry -is [string]) {
            $sidString = $sidEntry
        } else { continue }

        if ($sidString) {
            $sidClass = Get-SIDHistoryClass -SID $sidString
            $resolvedName = ConvertFrom-SID -SID $sidString
            # ConvertFrom-SID returns a real name (e.g. "DOMAIN\user") for resolvable SIDs, but a
            # decorated SID string for unresolvable ones ("<SID> (FOREIGN)", "<SID> (UNRESOLVABLE...)").
            # Only append "($sidString)" when we actually resolved a NAME - otherwise the SID would be
            # printed twice, e.g. "<SID> (FOREIGN) (<SID>)". Detect the decorated-SID case by checking
            # whether the returned string already contains the raw SID.
            $display = if ($resolvedName -and ($resolvedName -notlike "*$sidString*")) {
                "$resolvedName ($sidString)"     # genuine name resolved
            } elseif ($resolvedName) {
                $resolvedName                    # already the SID (optionally with a (FOREIGN)/(UNRESOLVABLE) marker)
            } else {
                $sidString
            }

            $findingId = Get-FindingIdForAttribute -Name 'sIDHistory' -Value $sidString
            $renderValues += New-RenderValue -Display $display -Severity $sidClass `
                -FindingId $findingId -RawValue $sidString -Metadata @{ ResolvedName = $resolvedName }
        }
    }

    if ($renderValues.Count -eq 0) { return $null }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        DisplayName         = 'sIDHistory'
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = $true
        Values              = $renderValues
    }
}

# --- Owner Transformer ---
function Convert-OwnerToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $ownerSID = $Context.OwnerSID
    if (-not $ownerSID) { return $null }

    $domainSID = $Script:LDAPContext.DomainSID
    $isDefault = Test-IsDefaultOwner -SID $ownerSID -DomainSID $domainSID

    if ($isDefault) {
        # Default owner - show as standard, no highlighting
        return @{
            RowType             = 'SingleValue'
            OverallSeverity     = 'Standard'
            ForceAttributeClass = $false
            Values              = @(
                New-RenderValue -Display ([string]$Value) -Severity 'Standard' -RawValue $Value
            )
        }
    }

    # Non-default owner - Finding (red)
    $findingId = Get-FindingIdForAttribute -Name 'Owner' -Value $Value
    if (-not $findingId) { $findingId = 'NON_DEFAULT_COMPUTER_OWNERS' }
    return @{
        DisplayName         = 'Owner (non-default)'
        RowType             = 'SingleValue'
        OverallSeverity     = 'Finding'
        ForceAttributeClass = $true
        Values              = @(
            New-RenderValue -Display ([string]$Value) -Severity 'Finding' -FindingId $findingId -RawValue $Value
        )
    }
}

# --- msds-groupmsamembership Transformer ---
function Convert-GMSAToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $gmsaPrincipals = @()

    # Check unified object format (from Invoke-LDAPSearch)
    if ($Value -is [PSCustomObject] -and $Value.PSObject.Properties['ACEs']) {
        $gmsaPrincipals = @($Value.ACEs | Where-Object { $_.Type -eq 'Allow' } | ForEach-Object {
            [PSCustomObject]@{ Name = $_.Name; SID = $_.SID }
        })
    }
    elseif ($Value -is [array]) {
        $firstItem = $Value | Select-Object -First 1
        if ($firstItem -is [PSCustomObject] -and $firstItem.PSObject.Properties['Name'] -and $firstItem.PSObject.Properties['SID']) {
            # New structured format from Get-DomainUser
            $gmsaPrincipals = @($Value)
        } else {
            # Legacy format (string array)
            $gmsaAllowEntries = @($Value | Where-Object { $_ -match '^Allow\s+-' })
            $gmsaPrincipals = @($gmsaAllowEntries | ForEach-Object {
                $principalName = if ($_ -match '^Allow\s+-\s+(.+?)\s+-\s+') { $Matches[1] } else { $_ }
                [PSCustomObject]@{ Name = $principalName; SID = $null }
            })
        }
    }

    if ($gmsaPrincipals.Count -eq 0) { return $null }

    $renderValues = @()
    foreach ($principal in $gmsaPrincipals) {
        $severity = 'Hint'
        $findingId = 'GMSA_MEMBERSHIP_INFO'
        if ($principal.SID) {
            $privResult = Test-IsPrivileged -Identity $principal.SID
            if ($privResult.Category -eq 'Privileged') {
                $severity = 'Finding'
                $findingId = 'GMSA_PASSWORD_READABLE'
            }
            elseif ($privResult.Category -in @('Operator', 'BroadGroup')) {
                $severity = 'Finding'
                $findingId = 'GMSA_PASSWORD_READABLE'
            }
        }
        $renderValues += New-RenderValue -Display $principal.Name -Severity $severity `
            -FindingId $findingId -RawValue $principal -Metadata @{ SID = $principal.SID }
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        DisplayName         = 'PrincipalsAllowedToRetrievePassword'
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = $true
        Values              = $renderValues
    }
}

# --- dangerousRights Transformer ---
function Convert-DangerousRightsToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $sourceObject = $Context.SourceObject

    # Split comma-separated string into individual rights for per-value tooltips
    # Check modules output dangerousRights as "GenericAll, GenericWrite, WriteDacl, WriteOwner"
    $rightsValues = if ($Value -is [string] -and $Value -match ',') {
        @($Value -split ',\s*' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    } else {
        @($Value)
    }

    # Use dangerousRightsSeverity from context for overall classification
    $overallClass = Get-AttributeSeverity -Name 'dangerousRightsSeverity' `
        -Value $Context.DangerousRightsSeverity -SourceObject $sourceObject

    # Build display name with ESC code if present
    $displayName = if ($sourceObject.dangerousRightsESC) {
        "dangerousRights [$($sourceObject.dangerousRightsESC)]"
    } else { 'dangerousRights' }

    $renderValues = @()
    foreach ($right in $rightsValues) {
        $rightStr = [string]$right
        $findingId = if ($Context.IsExchangeGroup) {
            'EXCHANGE_GROUP_PERMISSIONS'
        } else {
            Get-FindingIdForAttribute -Name 'dangerousRights' -Value $rightStr
        }
        $renderValues += New-RenderValue -Display $rightStr -Severity $overallClass `
            -FindingId $findingId -RawValue $right
    }

    return @{
        DisplayName         = $displayName
        RowType             = 'MultiValue'
        OverallSeverity     = $overallClass
        ForceAttributeClass = $true
        Values              = $renderValues
    }
}

# --- affectedOUs Transformer ---
function Convert-AffectedOUsToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $ouValues = @($Value)
    $sourceObject = $Context.SourceObject

    $renderValues = @()
    foreach ($ou in $ouValues) {
        $severity = Get-AttributeSeverity -Name 'affectedOUs' -Value $ou -SourceObject $sourceObject
        $renderValues += New-RenderValue -Display ([string]$ou) -Severity $severity -RawValue $ou
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = $true
        Values              = $renderValues
    }
}

# --- inheritedFrom Transformer ---
function Convert-InheritedFromToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $inheritedValues = @($Value)
    $renderValues = @()
    foreach ($v in $inheritedValues) {
        $severity = Get-AttributeSeverity -Name 'inheritedFrom' -Value $v
        $renderValues += New-RenderValue -Display ([string]$v) -Severity $severity -RawValue $v
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = ($maxSev -ne 'Standard')
        Values              = $renderValues
    }
}

# --- TemplateACL Transformer ---
# Displays write/modify permissions on certificate templates (owner + dangerous rights)
# Color-coding: Standard = expected admin, Hint = operator/unknown, Finding = non-privileged
function Convert-TemplateACLToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $aces = @($Value)
    if ($aces.Count -eq 0) { return $null }

    $renderValues = @()
    foreach ($ace in $aces) {
        if ($ace -isnot [PSCustomObject]) { continue }

        $display = "$($ace.Identity): $($ace.Right)"
        $sid = $ace.SID

        # Determine severity based on privilege level
        $severity = 'Standard'
        if ($sid) {
            $privCheck = Test-IsPrivileged -Identity $sid
            $severity = switch ($privCheck.Category) {
                'Privileged'  { 'Standard' }   # Domain Admins, Enterprise Admins, SYSTEM - expected
                'BroadGroup'  { 'Finding' }    # Everyone, Auth Users, Domain Users - dangerous
                default       { 'Hint' }       # Operator-level or unknown
            }
        }

        $findingId = if ($severity -ne 'Standard') { 'ESC4_TEMPLATE' } else { $null }
        $renderValues += New-RenderValue -Display $display -Severity $severity `
            -FindingId $findingId -RawValue $ace
    }

    if ($renderValues.Count -eq 0) { return $null }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        DisplayName         = 'templateACL'
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = ($maxSev -ne 'Standard')
        Values              = $renderValues
    }
}

# --- MembersAdded Transformer (GPO local group assignments) ---
#
# The check reported the same principals twice: once in MembersAdded, and once more in a
# RiskyMembers row directly below it that only ever repeated a subset of the first. That
# row is gone; the risk it carried is shown where the members already are, by colouring
# the risky ones.
#
# Which members are risky is decided in the check and decided by SID - Everyone,
# Authenticated Users, Anonymous Logon, and the -513 RID for Domain Users - and arrives
# here as RiskyMembers on the source object. Matching those by display name is sound
# because the check writes both lists from the same string: a risky principal is named by
# its canonical English name in MembersAdded too, whatever the GPO called it.
#
# The colour is the severity the check already computed for this assignment rather than a
# fixed one. That value is escalated precisely because a risky member is present, so
# Everyone in Remote Desktop Users shows as a hint and Everyone in Administrators as a
# finding - one judgement, made once, in the check.
function Convert-MembersAddedToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $members = @($Value | Where-Object { $_ })
    if ($members.Count -eq 0) { return $null }

    $sourceObject = $Context.SourceObject

    $riskyLookup = @{}
    foreach ($risky in @($sourceObject.RiskyMembers)) {
        if ($risky) { $riskyLookup[[string]$risky] = $true }
    }

    # Falls back to Finding rather than to Standard: an object that reached this
    # transformer with a risky member and no severity is a defect upstream, and losing the
    # colour would hide the finding instead of the defect.
    $riskySeverity = [string]$sourceObject.Severity
    if ($riskySeverity -notin @('Finding', 'Hint', 'Note')) { $riskySeverity = 'Finding' }

    $renderValues = @()
    foreach ($member in $members) {
        $display = [string]$member
        if ($riskyLookup.ContainsKey($display)) {
            $renderValues += New-RenderValue -Display $display -Severity $riskySeverity `
                -FindingId 'GPO_LOCAL_GROUP_RISKY_MEMBER' -RawValue $member
        } else {
            $renderValues += New-RenderValue -Display $display -Severity 'Standard' -RawValue $member
        }
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = ($maxSev -ne 'Standard')
        Values              = $renderValues
    }
}
# --- DangerousACEs Transformer ---
function Convert-DangerousACEsToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $aces = @($Value)
    $renderValues = @()
    foreach ($ace in $aces) {
        if ($ace -is [PSCustomObject]) {
            $display = "$($ace.Identity): $($ace.DangerousRight)"
            $severity = if ($ace.Severity -in @('Expected', 'Attention')) { 'Hint' } else { 'Finding' }
            $findingId = 'ESC4_TEMPLATE'
            $renderValues += New-RenderValue -Display $display -Severity $severity `
                -FindingId $findingId -RawValue $ace
        } else {
            $renderValues += New-RenderValue -Display ([string]$ace) -Severity 'Finding' `
                -FindingId 'ESC4_TEMPLATE' -RawValue $ace
        }
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        DisplayName         = 'dangerousPermissions'
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = $true
        Values              = $renderValues
    }
}

# --- DangerousPermissions Transformer (GPO - 2 formats) ---
function Convert-DangerousPermToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $sourceObject = $Context.SourceObject

    # Get-AttributeSeverity (used here until this fix) calls Get-SeverityFromTrigger, which
    # calls Get-TriggerMatch and then keeps only .Severity - the FindingId the same call
    # already computed was thrown away. New-RenderValue below was therefore never given a
    # -FindingId, and every row this transformer ever produced rendered with the right
    # colour and no tooltip behind it, silently, for as long as the transformer existed.
    # Get-TriggerMatch is the combined lookup; every other transformer in this file already
    # uses it for exactly this reason.

    # Format 1: Array of objects with Trustee/Rights properties
    if ($Value -is [array] -and $Value.Count -gt 0 -and $Value[0].PSObject.Properties['Trustee']) {
        $summaryMatch = Get-TriggerMatch -Name 'DangerousPermissions' -Value $Value -IsComputer $Context.IsComputer -SourceObject $sourceObject
        $renderValues = @()
        # First line: summary count
        $renderValues += New-RenderValue -Display "$($Value.Count) non-privileged ACE(s)" `
            -Severity $summaryMatch.Severity -FindingId $summaryMatch.FindingId -RawValue $Value
        # Per-ACE details
        foreach ($perm in $Value) {
            $permMatch = Get-TriggerMatch -Name 'DangerousPermissions' -Value $perm.Rights -IsComputer $Context.IsComputer -SourceObject $sourceObject
            $renderValues += New-RenderValue -Display "$($perm.Trustee): $($perm.Rights)" `
                -Severity $permMatch.Severity -FindingId $permMatch.FindingId -RawValue $perm
        }
        $maxSev = Get-MaxSeverityFromValues -Values $renderValues
        return @{
            RowType             = 'MultiValue'
            OverallSeverity     = $maxSev
            ForceAttributeClass = $true
            Values              = $renderValues
        }
    }

    # Format 2: String or multiline string - what Get-GPOPermissions actually produces:
    # one "Identity (Right)" line per vulnerable ACE, newline-joined into a single property.
    if ($Value -is [string]) {
        $permValues = if ($Value -match "`n") { $Value -split "`n" } else { @($Value) }
        $renderValues = @()
        foreach ($pv in $permValues) {
            $pvMatch = Get-TriggerMatch -Name 'DangerousPermissions' -Value $pv -IsComputer $Context.IsComputer -SourceObject $sourceObject
            $renderValues += New-RenderValue -Display ([string]$pv) -Severity $pvMatch.Severity -FindingId $pvMatch.FindingId -RawValue $pv
        }
        $maxSev = Get-MaxSeverityFromValues -Values $renderValues
        return @{
            RowType             = 'MultiValue'
            OverallSeverity     = $maxSev
            ForceAttributeClass = $true
            Values              = $renderValues
        }
    }

    return $null
}

# --- EnrollmentPrincipals Transformer ---
function Convert-EnrollPrincipalsToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $principals = @($Value)
    $renderValues = @()
    foreach ($p in $principals) {
        $pStr = [string]$p
        $privCheck = Test-IsPrivileged -Identity $pStr
        $severity = switch ($privCheck.Category) {
            'Privileged'  { 'Standard' }   # Admins expected to enroll
            'BroadGroup'  { 'Finding' }    # Everyone, Auth Users, Domain Users
            default       { 'Hint' }
        }
        $findingId = switch ($severity) {
            'Finding' { 'ADCS_NONPRIV_ENROLLMENT' }
            'Hint'    { 'ADCS_NONPRIV_ENROLLMENT' }
            default   { $null }
        }
        $renderValues += New-RenderValue -Display $pStr -Severity $severity `
            -FindingId $findingId -RawValue $p
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        DisplayName         = 'enrollmentPrincipals'
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = ($maxSev -ne 'Standard')
        Values              = $renderValues
    }
}

# --- ExtendedKeyUsage Transformer ---
function Convert-EKUToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $ekuValues = @($Value)
    $renderValues = @()
    foreach ($eku in $ekuValues) {
        $ekuStr = [string]$eku
        $severity = 'Standard'
        $findingId = $null
        if ($ekuStr -match '2\.5\.29\.37\.0|Any Purpose') {
            $severity = 'Finding'
            $findingId = 'ESC2_TEMPLATE'
        }
        elseif ($ekuStr -match '1\.3\.6\.1\.5\.5\.7\.3\.2|Client Authentication') {
            $severity = 'Hint'
            $findingId = 'ADCS_CLIENT_AUTH_EKU'
        }
        elseif ($ekuStr -match '1\.3\.6\.1\.4\.1\.311\.20\.2\.2|Smartcard') {
            $severity = 'Hint'
            $findingId = 'ADCS_SMARTCARD_LOGON_EKU'
        }
        $renderValues += New-RenderValue -Display $ekuStr -Severity $severity `
            -FindingId $findingId -RawValue $eku
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        DisplayName         = 'extendedKeyUsage'
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = ($maxSev -ne 'Standard')
        Values              = $renderValues
    }
}

# --- CertificateNameFlagDisplay Transformer ---
function Convert-CertNameFlagToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $flagValues = @($Value)
    $renderValues = @()
    foreach ($flag in $flagValues) {
        $flagStr = [string]$flag
        $severity = if ($flagStr -eq 'ENROLLEE_SUPPLIES_SUBJECT') { 'Finding' } else { 'Standard' }
        $findingId = Get-FindingIdForAttribute -Name 'CertificateNameFlagDisplay' -Value $flagStr
        $renderValues += New-RenderValue -Display $flagStr -Severity $severity `
            -FindingId $findingId -RawValue $flag
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        DisplayName         = 'certificateNameFlag'
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = ($maxSev -ne 'Standard')
        Values              = $renderValues
    }
}

# --- EnrollmentFlagDisplay Transformer ---
function Convert-EnrollFlagToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $flagValues = @($Value)
    $renderValues = @()
    foreach ($flag in $flagValues) {
        $flagStr = [string]$flag
        $severity = 'Standard'
        $findingId = $null
        if ($flagStr -eq 'NO_SECURITY_EXTENSION') {
            $severity = 'Finding'
            $findingId = 'ESC9_CT_NO_SECURITY_EXTENSION'
        }
        elseif ($flagStr -eq 'PEND_ALL_REQUESTS') {
            $severity = 'Secure'
            $findingId = 'ENROLLMENT_REQUIRES_APPROVAL'
        }
        $renderValues += New-RenderValue -Display $flagStr -Severity $severity `
            -FindingId $findingId -RawValue $flag
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        DisplayName         = 'enrollmentFlag'
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = ($maxSev -ne 'Standard')
        Values              = $renderValues
    }
}

# --- WebEndpoints Transformer ---
function Convert-WebEndpointsToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $endpointValues = @($Value)
    $renderValues = @()
    foreach ($ep in $endpointValues) {
        $epStr = [string]$ep
        $match = Get-TriggerMatch -Name 'WebEndpoints' -Value $epStr
        $renderValues += New-RenderValue -Display $epStr -Severity $match.Severity `
            -FindingId $match.FindingId -RawValue $ep
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = $true
        Values              = $renderValues
    }
}

# --- WebEnrollmentEndpoints Transformer ---
function Convert-WebEnrollEndpointsToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $endpointValues = @($Value)
    $renderValues = @()
    foreach ($ep in $endpointValues) {
        $epStr = [string]$ep
        $match = Get-TriggerMatch -Name 'WebEnrollmentEndpoints' -Value $epStr
        $renderValues += New-RenderValue -Display $epStr -Severity $match.Severity `
            -FindingId $match.FindingId -RawValue $ep
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = $true
        Values              = $renderValues
    }
}

# --- KerberoastingHash / ASREPRoastingHash Transformer ---
function Convert-RoastingHashToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $findingId = Get-FindingIdForAttribute -Name $Name -Value $Value
    return @{
        RowType             = 'Hash'
        OverallSeverity     = 'Finding'
        ForceAttributeClass = $true
        Values              = @(
            New-RenderValue -Display ([string]$Value) -Severity 'Finding' `
                -FindingId $findingId -RawValue $Value
        )
    }
}

# --- msDS-KeyCredentialLink Transformer ---
function Convert-KeyCredentialLinkToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $entries = @($Value)
    $renderValues = @()
    foreach ($entry in $entries) {
        $renderValues += New-RenderValue -Display ([string]$entry) `
            -Severity 'Hint' -FindingId 'SHADOW_CREDENTIALS' `
            -RawValue $entry
    }
    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = $true
        Values              = $renderValues
    }
}

# --- GPOStatus Transformer ---
# Whether the GPO itself is switched on, and nothing about where it applies - that is
# LinkedOUs' subject, and the two used to overlap so completely that an unlinked policy
# said so twice in one block.
#
# Returns $null for a policy with nothing wrong with it, which suppresses the row: every
# GPO object carries GPOStatus from Get-DomainGPO, and "GPOStatus: Enabled" on each of them
# is a line that says nothing. Get-RenderModel skips a transformer that returns $null.
function Convert-GPOStatusToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $status = [string]$Value
    if ([string]::IsNullOrWhiteSpace($status)) { return $null }
    if ($status -eq 'Enabled') { return $null }

    # Note, like the unlinked row: a disabled half of a policy is the reason a dangerous
    # setting does not currently reach anything. It is not Secure - one click re-enables it,
    # and the setting is still sitting there.
    return @{
        RowType             = 'SingleValue'
        OverallSeverity     = 'Note'
        ForceAttributeClass = $true
        Values              = @(
            New-RenderValue -Display $status -Severity 'Note' -RawValue $Value
        )
    }
}

# --- LinkedOUs Transformer ---
# Where a GPO applies, and the only attribute that answers that question. When the policy
# is linked nowhere an explicit row is emitted rather than letting the empty array make the
# row vanish - an unlinked GPO is a statement, not an absence.
#
# The vocabulary is fixed here for every GPO check. It used to be spread over the checks
# themselves, which produced 'NOT LINKED', 'Not linked - these settings apply nowhere' and
# 'Not linked - GPO is not applied anywhere' for one and the same fact, in two different
# colours, and a fourth wording of it in the effectiveness sentence underneath.
#
# Note rather than Hint: a policy that reaches nothing is the one line in a finding block
# that lowers the risk. Not Secure either - the settings sit in the directory and apply the
# moment somebody links the GPO.
function Convert-LinkedOUsToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $items = @()
    if ($null -ne $Value) { $items = @($Value) }

    if ($items.Count -eq 0) {
        return @{
            RowType             = 'SingleValue'
            OverallSeverity     = 'Standard'
            ForceAttributeClass = $false
            Values              = @(
                New-RenderValue -Display 'Not linked' `
                    -Severity 'Note' -RawValue $null
            )
        }
    }

    $renderValues = @()
    foreach ($item in $items) {
        # Linkage records from Get-GPOLinkage carry DistinguishedName + LinkStatus.
        # Plain string entries are tolerated (cross-domain links, manual placeholders).
        $display = $null
        if ($item -is [PSCustomObject] -and $item.PSObject.Properties['DistinguishedName']) {
            $display = $item.DistinguishedName
            if ([string]::IsNullOrWhiteSpace($display)) { continue }
            if ($item.PSObject.Properties['LinkStatus'] -and $item.LinkStatus -and $item.LinkStatus -ne 'Enabled') {
                # "(link disabled)" rather than the bare status word: "(Disabled)" next to a
                # DN reads as though the OU were disabled, which is not a thing.
                $suffix = if ($item.LinkStatus -eq 'Disabled') { 'link disabled' } else { "link $($item.LinkStatus)".ToLower() }
                $display = "$display ($suffix)"
            }
        } else {
            $display = [string]$item
            if ([string]::IsNullOrWhiteSpace($display)) { continue }
        }

        $itemMatch = Get-TriggerMatch -Name $Name -Value $display -IsComputer $Context.IsComputer -SourceObject $Context.SourceObject
        $renderValues += New-RenderValue -Display $display -Severity $itemMatch.Severity `
            -FindingId $itemMatch.FindingId -RawValue $item
    }

    if ($renderValues.Count -eq 0) {
        # All entries were filtered as whitespace - still surface the unlinked state
        return @{
            RowType             = 'SingleValue'
            OverallSeverity     = 'Standard'
            ForceAttributeClass = $false
            Values              = @(
                New-RenderValue -Display 'Not linked' `
                    -Severity 'Note' -RawValue $null
            )
        }
    }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        RowType             = 'MultiValue'
        OverallSeverity     = $maxSev
        ForceAttributeClass = ($maxSev -ne 'Standard')
        Values              = $renderValues
    }
}

# --- scriptPath Transformer ---
function Convert-ScriptPathToRenderValues {
    [CmdletBinding()]
    param([string]$Name, $Value, $Context)

    $scriptPath = [string]$Value
    if ([string]::IsNullOrWhiteSpace($scriptPath)) { return $null }

    # Detect UNC path (\\server\share\...) or absolute local path (C:\...)
    $isHardcoded = ($scriptPath -match '^\\\\[^\\]+\\' -or $scriptPath -match '^[A-Za-z]:[\\\/]')

    if ($isHardcoded) {
        # UNC or absolute path: Hint (yellow), promoted to primary
        return @{
            RowType             = 'SingleValue'
            OverallSeverity     = 'Hint'
            ForceAttributeClass = $true
            Values              = @(
                New-RenderValue -Display $scriptPath -Severity 'Hint' `
                    -FindingId 'SCRIPTPATH_HARDCODED' -RawValue $scriptPath
            )
        }
    }

    # Relative path: Standard, stays in extended attributes
    return @{
        RowType             = 'SingleValue'
        OverallSeverity     = 'Standard'
        ForceAttributeClass = $false
        Values              = @(
            New-RenderValue -Display $scriptPath -Severity 'Standard' -RawValue $scriptPath
        )
    }
}

# ============================================================================
# Register all transformers in the registry
# ============================================================================

$Script:AttributeTransformers['memberOf']                    = ${function:Convert-MemberOfToRenderValues}
$Script:AttributeTransformers['privilegedGroups']            = ${function:Convert-PrivilegedGroupsToRenderValues}
$Script:AttributeTransformers['member']                      = ${function:Convert-MemberToRenderValues}
$Script:AttributeTransformers['userAccountControl']          = ${function:Convert-UACToRenderValues}
$Script:AttributeTransformers['servicePrincipalName']        = ${function:Convert-SPNToRenderValues}
$Script:AttributeTransformers['sIDHistory']                  = ${function:Convert-SIDHistoryToRenderValues}
$Script:AttributeTransformers['Owner']                       = ${function:Convert-OwnerToRenderValues}
$Script:AttributeTransformers['msds-groupmsamembership']     = ${function:Convert-GMSAToRenderValues}
$Script:AttributeTransformers['dangerousRights']             = ${function:Convert-DangerousRightsToRenderValues}
$Script:AttributeTransformers['affectedOUs']                 = ${function:Convert-AffectedOUsToRenderValues}
$Script:AttributeTransformers['inheritedFrom']               = ${function:Convert-InheritedFromToRenderValues}
$Script:AttributeTransformers['DangerousACEs']               = ${function:Convert-DangerousACEsToRenderValues}
$Script:AttributeTransformers['MembersAdded']               = ${function:Convert-MembersAddedToRenderValues}
$Script:AttributeTransformers['TemplateACL']                 = ${function:Convert-TemplateACLToRenderValues}
$Script:AttributeTransformers['DangerousPermissions']        = ${function:Convert-DangerousPermToRenderValues}
$Script:AttributeTransformers['EnrollmentPrincipals']        = ${function:Convert-EnrollPrincipalsToRenderValues}
$Script:AttributeTransformers['ExtendedKeyUsage']            = ${function:Convert-EKUToRenderValues}
$Script:AttributeTransformers['CertificateNameFlagDisplay']  = ${function:Convert-CertNameFlagToRenderValues}
$Script:AttributeTransformers['EnrollmentFlagDisplay']       = ${function:Convert-EnrollFlagToRenderValues}
$Script:AttributeTransformers['WebEndpoints']                = ${function:Convert-WebEndpointsToRenderValues}
$Script:AttributeTransformers['WebEnrollmentEndpoints']      = ${function:Convert-WebEnrollEndpointsToRenderValues}
$Script:AttributeTransformers['msDS-KeyCredentialLink']      = ${function:Convert-KeyCredentialLinkToRenderValues}
$Script:AttributeTransformers['scriptPath']                  = ${function:Convert-ScriptPathToRenderValues}
$Script:AttributeTransformers['LinkedOUs']                   = ${function:Convert-LinkedOUsToRenderValues}
$Script:AttributeTransformers['GPOStatus']                   = ${function:Convert-GPOStatusToRenderValues}
$Script:AttributeTransformers['KerberoastingHash']           = ${function:Convert-RoastingHashToRenderValues}
$Script:AttributeTransformers['ASREPRoastingHash']           = ${function:Convert-RoastingHashToRenderValues}
