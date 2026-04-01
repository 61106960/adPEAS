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
            $display = if ($resolvedName -and $resolvedName -ne $sidString) {
                "$resolvedName ($sidString)"
            } else { $sidString }

            $findingId = Get-FindingIdForAttribute -Name 'sIDHistory' -Value $sidString
            $renderValues += New-RenderValue -Display $display -Severity $sidClass `
                -FindingId $findingId -RawValue $sidString -Metadata @{ ResolvedName = $resolvedName }
        }
    }

    if ($renderValues.Count -eq 0) { return $null }

    $maxSev = Get-MaxSeverityFromValues -Values $renderValues
    return @{
        DisplayName         = 'sIDHistory (SID History Injection risk!)'
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

    # Format 1: Array of objects with Trustee/Rights properties
    if ($Value -is [array] -and $Value.Count -gt 0 -and $Value[0].PSObject.Properties['Trustee']) {
        $permClass = Get-AttributeSeverity -Name 'DangerousPermissions' -Value $Value -SourceObject $sourceObject
        $renderValues = @()
        # First line: summary count
        $renderValues += New-RenderValue -Display "$($Value.Count) non-privileged ACE(s)" `
            -Severity $permClass -RawValue $Value
        # Per-ACE details
        foreach ($perm in $Value) {
            $renderValues += New-RenderValue -Display "$($perm.Trustee): $($perm.Rights)" `
                -Severity $permClass -RawValue $perm
        }
        return @{
            RowType             = 'MultiValue'
            OverallSeverity     = $permClass
            ForceAttributeClass = $true
            Values              = $renderValues
        }
    }

    # Format 2: String or multiline string
    if ($Value -is [string]) {
        $permValues = if ($Value -match "`n") { $Value -split "`n" } else { @($Value) }
        $permClass = Get-AttributeSeverity -Name 'DangerousPermissions' -Value $permValues -SourceObject $sourceObject
        $renderValues = @()
        foreach ($pv in $permValues) {
            $pvSeverity = Get-AttributeSeverity -Name 'DangerousPermissions' -Value $pv -SourceObject $sourceObject
            $renderValues += New-RenderValue -Display ([string]$pv) -Severity $pvSeverity -RawValue $pv
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
$Script:AttributeTransformers['DangerousPermissions']        = ${function:Convert-DangerousPermToRenderValues}
$Script:AttributeTransformers['EnrollmentPrincipals']        = ${function:Convert-EnrollPrincipalsToRenderValues}
$Script:AttributeTransformers['ExtendedKeyUsage']            = ${function:Convert-EKUToRenderValues}
$Script:AttributeTransformers['CertificateNameFlagDisplay']  = ${function:Convert-CertNameFlagToRenderValues}
$Script:AttributeTransformers['EnrollmentFlagDisplay']       = ${function:Convert-EnrollFlagToRenderValues}
$Script:AttributeTransformers['WebEndpoints']                = ${function:Convert-WebEndpointsToRenderValues}
$Script:AttributeTransformers['WebEnrollmentEndpoints']      = ${function:Convert-WebEnrollEndpointsToRenderValues}
$Script:AttributeTransformers['msDS-KeyCredentialLink']      = ${function:Convert-KeyCredentialLinkToRenderValues}
$Script:AttributeTransformers['KerberoastingHash']           = ${function:Convert-RoastingHashToRenderValues}
$Script:AttributeTransformers['ASREPRoastingHash']           = ${function:Convert-RoastingHashToRenderValues}
