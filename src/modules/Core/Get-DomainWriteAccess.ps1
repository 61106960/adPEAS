# ============================================================================
# Get-DomainWriteAccess - what an account may write in the directory
# ============================================================================
#
# The tables below decide what the default view keeps. A right over the whole object -
# ownership, full control, a write of every property, WriteDacl, WriteOwner, all extended
# rights, every validated write, every child class - always stays. A single attribute,
# extended right, validated write or child class stays when it is listed here for a class
# the object belongs to: each one is a known step from a write to control of the object
# or of what it grants. -All shows everything. Constant tables, defined once at load.

# Attribute -> the classes it matters on. An object matches when any of its objectClass
# values is listed, so 'user' covers computers, managed service accounts and inetOrgPerson.
$Script:WriteAccessInterestingAttributes = [ordered]@{
    'member'                                   = @('group')                       # add a member
    'servicePrincipalName'                     = @('user')                        # targeted Kerberoasting
    'msDS-KeyCredentialLink'                   = @('user')                        # shadow credentials
    'msDS-AllowedToActOnBehalfOfOtherIdentity' = @('computer')                    # resource-based delegation
    'msDS-AllowedToDelegateTo'                 = @('user')                        # constrained delegation
    'userAccountControl'                       = @('user')                        # e.g. no pre-authentication
    'altSecurityIdentities'                    = @('user')                        # explicit certificate mapping
    'userPrincipalName'                        = @('user')                        # certificate mapping by UPN
    'dNSHostName'                              = @('computer')                    # certificate mapping by DNS name
    'scriptPath'                               = @('user')                        # logon script
    'profilePath'                              = @('user')                        # roaming profile path
    'homeDirectory'                            = @('user')                        # home directory path
    'managedBy'                                = @('computer', 'group')           # RODC administrator, Exchange group owner
    'msDS-RevealOnDemandGroup'                 = @('computer')                    # RODC allow list
    'msDS-NeverRevealGroup'                    = @('computer')                    # RODC deny list
    'msDS-GroupMSAMembership'                  = @('msDS-GroupManagedServiceAccount')     # who reads the gMSA password
    'msDS-ManagedAccountPrecededByLink'        = @('msDS-DelegatedManagedServiceAccount') # dMSA predecessor
    'msDS-DelegatedMSAState'                   = @('msDS-DelegatedManagedServiceAccount') # dMSA migration state
    'gPLink'                                   = @('organizationalUnit', 'domainDNS', 'site')
    'gPOptions'                                = @('organizationalUnit', 'domainDNS', 'site')
    'gPCFileSysPath'                           = @('groupPolicyContainer')
    'gPCMachineExtensionNames'                 = @('groupPolicyContainer')
    'gPCUserExtensionNames'                    = @('groupPolicyContainer')
    'ms-DS-MachineAccountQuota'                = @('domainDNS')
    'msPKI-Certificate-Name-Flag'              = @('pKICertificateTemplate')
    'msPKI-Enrollment-Flag'                    = @('pKICertificateTemplate')
    'msPKI-RA-Signature'                       = @('pKICertificateTemplate')
    'pKIExtendedKeyUsage'                      = @('pKICertificateTemplate')
    'msPKI-Certificate-Application-Policy'     = @('pKICertificateTemplate')
    'certificateTemplates'                     = @('pKIEnrollmentService')        # which templates a CA issues
    'cACertificate'                            = @('certificationAuthority')      # NTAuth and root stores
    'dnsRecord'                                = @('dnsNode')                     # DNS record in AD
}

# Extended right -> the classes it matters on.
$Script:WriteAccessInterestingExtendedRights = [ordered]@{
    'User-Force-Change-Password'                 = @('user')
    'DS-Replication-Get-Changes'                 = @('domainDNS')
    'DS-Replication-Get-Changes-All'             = @('domainDNS')
    'DS-Replication-Get-Changes-In-Filtered-Set' = @('domainDNS')
}

# Validated write -> the classes it applies to. Every validated write is kept; the classes
# only drop one that was inherited onto an object it means nothing on.
$Script:WriteAccessValidatedWriteClasses = @{
    'Self-Membership'                          = @('group')
    'Validated-SPN'                            = @('computer')
    'Validated-DNS-Host-Name'                  = @('computer')
    'Validated-MS-DS-Additional-DNS-Host-Name' = @('computer')
    'DS-Validated-Write-Computer'              = @('computer')
}

# Child classes whose creation is a known step: an account, a group, a policy, a DNS record,
# a certificate template.
$Script:WriteAccessInterestingClasses = @(
    'user', 'computer', 'group', 'inetOrgPerson', 'msDS-ManagedServiceAccount',
    'msDS-GroupManagedServiceAccount', 'msDS-DelegatedManagedServiceAccount',
    'groupPolicyContainer', 'dnsNode', 'pKICertificateTemplate'
)

# The access bits this function reads. Read access is not asked about.
$Script:WriteAccessBits = [ordered]@{
    CreateChild   = 0x1L
    DeleteChild   = 0x2L
    Self          = 0x8L
    WriteProperty = 0x20L
    DeleteTree    = 0x40L
    ExtendedRight = 0x100L
    Delete        = 0x10000L
    WriteDacl     = 0x40000L
    WriteOwner    = 0x80000L
}

function Get-DomainWriteAccess {
    <#
    .SYNOPSIS
    Lists what an account may write in the directory: which objects, which right, and
    through which of its groups.

    .DESCRIPTION
    Without -Identity the account adPEAS is bound as; with -Identity any user, computer,
    managed service account or group.

    The ACL evaluation is the same for both. The account's token is built - its SID and
    sIDHistory, every group it is a member of through member links, its primary group with
    that group's nesting, Everyone, Authenticated Users and This Organization with their
    nesting, and SELF on its own object - and every ACE of every object searched is read
    as the access check reads it: ACEs in their DACL order, the first one that matches a
    right decides it, an inherit-only ACE does not apply, an object ACE grants on the
    attribute, property set, extended right, validated write or class it names and nowhere
    else (MS-DTYP 2.5.3.2), a property set covers the attributes the schema puts in it, and
    the owner holds READ_CONTROL and WRITE_DAC unless an OWNER RIGHTS ACE says otherwise.

    For the bound account the directory is asked as well. A domain controller computes
    allowedAttributesEffective, allowedChildClassesEffective and sDRightsEffective for the
    requester with its real token (MS-ADTS 3.1.1.4.5) - so for the writable attributes,
    the child classes and WriteDacl/WriteOwner its answer is the truth. A right the ACL
    evaluation found and the directory confirms is marked 'ACL, directory'; one it does not
    confirm is left out and counted in a warning; one only the directory knows - a group
    the token did not contain, say - is added with Via '(directory)'. Extended rights and
    validated writes are not in those attributes and come from the ACL evaluation alone.
    A right on something the object cannot hold - an attribute its class lacks, a child
    class the schema does not allow below it (allowedAttributes, allowedChildClasses, read
    only for an object with an unconfirmed row) - is no disagreement and is set aside. An
    object whose ACL the account may not read is still covered by the directory's answer.

    GenericAll is every write right over the whole object. The delete rights are not
    writes; a principal without some of them gets GenericAll 'without Delete' and the like.
    -Verbose names every right left out and every unreadable ACL, and ends with a summary.

    Not evaluated: group memberships in other domains, SID history of groups, and an ACE
    whose ObjectType names a class the object derives from rather than its own class.

    .PARAMETER Identity
    The account to evaluate - sAMAccountName, DN, SID or DOMAIN\name. Without it, the
    account adPEAS is bound as.

    .PARAMETER SearchBase
    The subtrees to read. Default: the domain naming context and, where the configuration
    naming context is known, CN=Public Key Services,CN=Services in it - certificate
    templates, enrollment services and the NTAuth store.

    .PARAMETER LDAPFilter
    Limits the objects read within the search bases. Default: every object.

    .PARAMETER All
    Every right, not only the ones that are a known step to control (see the tables at
    the top of this file), and rights the account holds on its own object through SELF.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-DomainWriteAccess
    What the bound account may write, ACL evaluation checked against the directory.

    .EXAMPLE
    Get-DomainWriteAccess -Identity jdoe | Format-Table Object, Right, Target, Via
    What jdoe could write, if it were taken over.

    .EXAMPLE
    Get-DomainWriteAccess -Identity 'Helpdesk' -SearchBase 'OU=Admins,DC=contoso,DC=com' -All

    .OUTPUTS
    PSCustomObject per object and right: Object, ObjectClass, Right, Target, Via, Source,
    DistinguishedName. Right is Owner, GenericAll, GenericWrite, WriteDacl, WriteOwner,
    WriteProperty, ValidatedWrite, ExtendedRight or CreateChild.

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, Position=0)]
        [string]$Identity,

        [Parameter(Mandatory=$false)]
        [string[]]$SearchBase,

        [Parameter(Mandatory=$false)]
        [string]$LDAPFilter = '(objectClass=*)',

        [Parameter(Mandatory=$false)]
        [switch]$All,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-DomainWriteAccess] Starting"
    }

    process {
        # An inner scope has no access to the caller's $PSBoundParameters.
        $CredParams = @{}
        if ($PSBoundParameters.ContainsKey('Domain')) { $CredParams['Domain'] = $Domain }
        if ($PSBoundParameters.ContainsKey('Server')) { $CredParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $CredParams['Credential'] = $Credential }

        if (-not (Ensure-LDAPConnection @CredParams)) { return }

        $boundMode = -not $PSBoundParameters.ContainsKey('Identity')
        $token = Get-WriteAccessToken -Identity $Identity -Bound:$boundMode -CredParams $CredParams
        if (-not $token) { return }
        Write-Log "[Get-DomainWriteAccess] $($token.Name): $($token.SIDs.Count) SID(s) in the token"

        $schema = Get-WriteAccessSchema -CredParams $CredParams

        $bases = @($SearchBase | Where-Object { $_ })
        if ($bases.Count -eq 0) {
            $bases = @([string]$Script:LDAPContext.DomainDN)
            if ($Script:LDAPContext.ConfigurationNamingContext) {
                $bases += "CN=Public Key Services,CN=Services,$($Script:LDAPContext.ConfigurationNamingContext)"
            }
        }

        $properties = @('distinguishedName', 'name', 'sAMAccountName', 'objectClass', 'objectSid', 'nTSecurityDescriptor')
        if ($boundMode) {
            # Constructed for the requester by the domain controller (MS-ADTS 3.1.1.4.5).
            $properties += @('allowedAttributesEffective', 'allowedChildClassesEffective', 'sDRightsEffective')
        }

        $read = 0
        $unreadable = 0
        $unreadableCovered = 0
        $unconfirmed = 0
        $reported = 0
        $confirmedRows = 0
        $directoryRows = 0
        $effectiveSeen = $false
        $nameBySID = @{}

        foreach ($base in $bases) {
            $objects = @()
            try {
                $objects = @(Get-DomainObject -SearchBase $base -LDAPFilter $LDAPFilter -Properties $properties -Raw @CredParams)
            } catch {
                Write-Warning "[Get-DomainWriteAccess] $base could not be searched: $_"
                continue
            }
            Write-Log "[Get-DomainWriteAccess] $($objects.Count) object(s) under $base"

            foreach ($object in $objects) {
                if (-not $object -or -not $object.distinguishedName) { continue }

                $read++
                $result = Get-WriteAccessObjectRight -Object $object -Token $token -Schema $schema -All:$All
                $rows = @($result.Rows)

                $covered = $false
                if ($boundMode) {
                    $checked = Resolve-WriteAccessEffective -Object $object -Rows $rows -SelfOnly $result.SelfOnly -Classes $result.Classes `
                        -Schema $schema -CredParams $CredParams -All:$All
                    if ($checked.Available) { $effectiveSeen = $true; $covered = $true }
                    $unconfirmed += $checked.Unconfirmed
                    $rows = @($checked.Rows)
                }
                # An ACL the account may not read is not one without rights. For the bound
                # account the directory's answer still covers the object.
                if (-not $result.Readable) {
                    $unreadable++
                    if ($covered) { $unreadableCovered++ }
                    Write-Log "[Get-DomainWriteAccess] No readable ACL: $($object.distinguishedName)"
                }
                if ($rows.Count -eq 0) { continue }

                $dn = [string]$object.distinguishedName
                $objectName = [string]$object.sAMAccountName
                if (-not $objectName) { $objectName = [string]$object.name }
                if (-not $objectName -and $dn -match '^[^=]+=((?:\.|[^,])+)') { $objectName = $Matches[1] }
                $classes = @($result.Classes)
                $objectClass = ''
                if ($classes.Count -gt 0) { $objectClass = [string]$classes[-1] }

                foreach ($row in $rows) {
                    $via = @()
                    foreach ($sid in @($row.Via)) {
                        if ($sid -eq '(directory)') { $via += $sid; continue }
                        if (-not $nameBySID.ContainsKey($sid)) {
                            $resolved = $null
                            try { $resolved = ConvertFrom-SID -SID $sid } catch { }
                            $nameBySID[$sid] = $(if ($resolved) { [string]$resolved } else { $sid })
                        }
                        $via += $nameBySID[$sid]
                    }
                    $reported++
                    if ($row.Source -eq 'ACL, directory') { $confirmedRows++ }
                    elseif ($row.Source -eq 'directory') { $directoryRows++ }
                    [PSCustomObject]@{
                        Object            = $objectName
                        ObjectClass       = $objectClass
                        Right             = $row.Right
                        Target            = $row.Target
                        Via               = (@($via | Select-Object -Unique) -join ', ')
                        Source            = $row.Source
                        DistinguishedName = $dn
                    }
                }
            }
        }

        if ($unreadable -gt 0) {
            $coverage = 'they were not evaluated'
            if ($unreadableCovered -eq $unreadable) { $coverage = "only the directory's answer covers them" }
            elseif ($unreadableCovered -gt 0) { $coverage = "the directory's answer covers $unreadableCovered of them, the rest were not evaluated" }
            Write-Warning "[Get-DomainWriteAccess] The ACL of $unreadable object(s) could not be read - $coverage (-Verbose names them)"
        }
        if ($boundMode -and -not $effectiveSeen) {
            Write-Warning "[Get-DomainWriteAccess] The directory returned no effective rights - the result rests on the ACL evaluation alone"
        }
        if ($unconfirmed -gt 0) {
            Write-Warning "[Get-DomainWriteAccess] $unconfirmed right(s) the ACL evaluation found were not confirmed by the directory and were left out (-Verbose names them)"
        }

        $summary = "[Get-DomainWriteAccess] $read object(s) read, $unreadable without a readable ACL; $reported right(s) reported"
        if ($boundMode) {
            $summary += " - $confirmedRows confirmed by the directory, $directoryRows from the directory alone, $unconfirmed left out as unconfirmed"
        }
        Write-Log $summary
    }

    end {
        Write-Log "[Get-DomainWriteAccess] Completed"
    }
}

<#
.SYNOPSIS
    Evaluates one object's security descriptor against a token.

.DESCRIPTION
    Rights over the whole object first: each access bit is decided by the first ACE in
    DACL order that carries it and names nothing, or names the object's own class. All of
    them together are GenericAll; a write of every property and every validated write
    together are GenericWrite. Then the single attributes, validated writes, extended
    rights and child classes a bit over the whole object does not already cover, each
    decided by the first ACE that names it, the property set it belongs to, or nothing.

.OUTPUTS
    PSCustomObject: Readable, Rows, SelfOnly (row keys held through SELF alone), Classes.

.NOTES
    Internal helper function
#>
function Get-WriteAccessObjectRight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] $Object,
        [Parameter(Mandatory=$true)] $Token,
        [Parameter(Mandatory=$true)] $Schema,
        [Parameter(Mandatory=$false)] [switch]$All
    )

    $classes = @(@($Object.objectClass) | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $result = [PSCustomObject]@{ Readable = $false; Rows = @(); SelfOnly = @(); Classes = $classes }

    $parsed = $null
    if ($Object.nTSecurityDescriptor) {
        try { $parsed = ConvertTo-AccessRules -SecurityDescriptorBytes $Object.nTSecurityDescriptor } catch { $parsed = $null }
    }
    if (-not $parsed) { return $result }
    $result.Readable = $true

    # The object's own class is the root of its object type tree (MS-ADTS 5.1.3.3.3).
    $rootGuid = ''
    if ($classes.Count -gt 0 -and $Schema.ClassGuidByName.ContainsKey($classes[-1])) {
        $rootGuid = [string]$Schema.ClassGuidByName[$classes[-1]]
    }

    $objectSid = ConvertTo-WriteAccessSid -Value $Object.objectSid
    $isSelf = [bool]($objectSid -and $objectSid -eq $Token.SID)
    $ownerSid = [string]$parsed.OwnerSID
    $isOwner = [bool]($ownerSid -and $Token.SIDs.Contains($ownerSid))

    $writeMask = 0L
    foreach ($bit in $Script:WriteAccessBits.Values) { $writeMask = $writeMask -bor $bit }

    # The ACEs that can decide a write for this token, in DACL order.
    $rules = New-Object System.Collections.ArrayList
    $ownerRightsAce = $false
    $index = 0
    foreach ($ace in @($parsed.AccessRules)) {
        $index++
        if (-not $ace -or ([string]$ace.PropagationFlags) -match 'InheritOnly') { continue }
        $sid = [string]$ace.IdentityReference.Value
        # An OWNER RIGHTS ACE replaces the owner's implicit rights, whoever holds them.
        if ($sid -eq 'S-1-3-4') { $ownerRightsAce = $true }
        $applies = $Token.SIDs.Contains($sid) -or ($isSelf -and $sid -eq 'S-1-5-10') -or ($isOwner -and $sid -eq 'S-1-3-4')
        if (-not $applies) { continue }
        $mask = [long](ConvertTo-ExpandedADRightsValue -Rights $ace.ActiveDirectoryRights)
        if (($mask -band $writeMask) -eq 0) { continue }
        $objectType = ''
        if ($ace.ObjectType -and $ace.ObjectType -ne [Guid]::Empty) { $objectType = $ace.ObjectType.ToString().ToLower() }
        [void]$rules.Add([PSCustomObject]@{
            Index = $index; Sid = $sid; Type = [string]$ace.AccessControlType; Mask = $mask; ObjectType = $objectType
        })
    }
    $ownerImplicit = $isOwner -and -not $ownerRightsAce
    if ($rules.Count -eq 0 -and -not $ownerImplicit) { return $result }

    $whole = @{}
    foreach ($name in $Script:WriteAccessBits.Keys) {
        $decision = Get-WriteAccessDecision -Rules $rules -Bit $Script:WriteAccessBits[$name] -Node '' -Parent '' -Root $rootGuid
        if ($decision -and $decision.Type -eq 'Allow') { $whole[$name] = $decision }
    }

    $rows = New-Object System.Collections.ArrayList
    # The owner may rewrite the DACL whatever it says.
    if ($ownerImplicit) {
        [void]$rows.Add((New-WriteAccessRow -Right 'Owner' -Kind 'Whole' -Via @($ownerSid)))
    }

    # Full control is every write right over the whole object. The delete rights are not
    # writes: a principal that lacks one of them still controls the object, and one row that
    # says which it lacks reads better than five rows that leave it to the reader.
    $fullControl = $whole.ContainsKey('WriteDacl') -or $ownerImplicit
    foreach ($name in @('CreateChild', 'Self', 'WriteProperty', 'ExtendedRight', 'WriteOwner')) {
        if (-not $whole.ContainsKey($name)) { $fullControl = $false }
    }

    if ($fullControl) {
        $except = Get-WriteAccessException -Rules $rules -Whole $whole -Bits @('WriteProperty', 'Self', 'ExtendedRight', 'CreateChild') -Root $rootGuid -Schema $Schema
        $target = Format-WriteAccessExcept -Text '' -Except $except
        $missing = @(@('DeleteChild', 'DeleteTree', 'Delete') | Where-Object { -not $whole.ContainsKey($_) })
        if ($missing.Count -gt 0) {
            $without = "without $($missing -join ', ')"
            $target = if ($target) { "$without; $target" } else { $without }
        }
        [void]$rows.Add((New-WriteAccessRow -Right 'GenericAll' -Kind 'Whole' -Target $target -Via @($whole.Values | ForEach-Object { $_.Sid })))
    } else {
        if ($whole.ContainsKey('WriteDacl')) {
            [void]$rows.Add((New-WriteAccessRow -Right 'WriteDacl' -Kind 'Whole' -Via @($whole['WriteDacl'].Sid)))
        }
        if ($whole.ContainsKey('WriteOwner')) {
            [void]$rows.Add((New-WriteAccessRow -Right 'WriteOwner' -Kind 'Whole' -Via @($whole['WriteOwner'].Sid)))
        }
        $everyProperty = $whole.ContainsKey('WriteProperty')
        $everyValidated = $whole.ContainsKey('Self')
        if ($everyProperty -and $everyValidated) {
            $except = Get-WriteAccessException -Rules $rules -Whole $whole -Bits @('WriteProperty', 'Self') -Root $rootGuid -Schema $Schema
            [void]$rows.Add((New-WriteAccessRow -Right 'GenericWrite' -Kind 'Whole' -Target (Format-WriteAccessExcept -Text '' -Except $except) `
                -Via @($whole['WriteProperty'].Sid, $whole['Self'].Sid)))
        } elseif ($everyProperty) {
            $except = Get-WriteAccessException -Rules $rules -Whole $whole -Bits @('WriteProperty') -Root $rootGuid -Schema $Schema
            [void]$rows.Add((New-WriteAccessRow -Right 'WriteProperty' -Kind 'Whole' -Target (Format-WriteAccessExcept -Text '(every property)' -Except $except) `
                -Via @($whole['WriteProperty'].Sid)))
        } elseif ($everyValidated) {
            $except = Get-WriteAccessException -Rules $rules -Whole $whole -Bits @('Self') -Root $rootGuid -Schema $Schema
            [void]$rows.Add((New-WriteAccessRow -Right 'ValidatedWrite' -Kind 'Whole' -Target (Format-WriteAccessExcept -Text '(every validated write)' -Except $except) `
                -Via @($whole['Self'].Sid)))
        }
        if ($whole.ContainsKey('ExtendedRight')) {
            $except = Get-WriteAccessException -Rules $rules -Whole $whole -Bits @('ExtendedRight') -Root $rootGuid -Schema $Schema
            [void]$rows.Add((New-WriteAccessRow -Right 'ExtendedRight' -Kind 'Whole' -Target (Format-WriteAccessExcept -Text '(all extended rights)' -Except $except) `
                -Via @($whole['ExtendedRight'].Sid)))
        }
        if ($whole.ContainsKey('CreateChild')) {
            $except = Get-WriteAccessException -Rules $rules -Whole $whole -Bits @('CreateChild') -Root $rootGuid -Schema $Schema
            [void]$rows.Add((New-WriteAccessRow -Right 'CreateChild' -Kind 'Whole' -Target (Format-WriteAccessExcept -Text '(every class)' -Except $except) `
                -Via @($whole['CreateChild'].Sid)))
        }

        # The single nodes a right over the whole object does not cover already.
        foreach ($candidate in @(Get-WriteAccessCandidate -Rules $rules -Whole $whole -Classes $classes -Schema $Schema -All:$All)) {
            $decision = Get-WriteAccessDecision -Rules $rules -Bit $candidate.Bit -Node $candidate.Guid -Parent $candidate.Parent -Root $rootGuid
            if (-not $decision -or $decision.Type -ne 'Allow') { continue }
            # Decided by an ACE over the whole object: a row above says so already.
            if (-not $decision.ObjectType -or $decision.ObjectType -eq $rootGuid) { continue }
            $target = $candidate.Name
            if ($candidate.Parent -and $candidate.Parent -ne $candidate.Guid -and $decision.ObjectType -eq $candidate.Parent) {
                $target = "$target ($(Get-WriteAccessNodeName -Guid $candidate.Parent -Kind 'PropertySet' -Schema $Schema))"
            }
            [void]$rows.Add((New-WriteAccessRow -Right $candidate.Right -Kind $candidate.Kind -Name $candidate.Name `
                -NodeGuid $candidate.Guid -Target $target -Via @($decision.Sid)))
        }
    }

    # A right the account holds on its own object through SELF alone is the default every
    # account has; only -All shows it. Its key is kept, so the directory's answer does not
    # bring it back.
    $kept = New-Object System.Collections.ArrayList
    $selfOnly = @()
    foreach ($row in $rows) {
        if (@($row.Via | Where-Object { $_ -ne 'S-1-5-10' }).Count -eq 0) {
            $selfOnly += "$($row.Right):$($row.Name)"
            if (-not $All) { continue }
        }
        [void]$kept.Add($row)
    }
    $result.Rows = @($kept)
    $result.SelfOnly = $selfOnly
    return $result
}

<#
.SYNOPSIS
    The ACE that decides one access bit on one node of an object's type tree, or $null.

.DESCRIPTION
    An ACE reaches a node when it names nothing (the whole object), the object's own class
    (the root), the node itself, or the property set the node belongs to. The first ACE in
    DACL order that reaches the node and carries the bit decides it, Allow or Deny - which
    is the canonical order doing what the access check does with it.

.NOTES
    Internal helper function
#>
function Get-WriteAccessDecision {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [AllowEmptyCollection()] $Rules,
        [Parameter(Mandatory=$true)] [long]$Bit,
        [Parameter(Mandatory=$false)] [string]$Node = '',
        [Parameter(Mandatory=$false)] [string]$Parent = '',
        [Parameter(Mandatory=$false)] [string]$Root = ''
    )

    foreach ($rule in $Rules) {
        if (($rule.Mask -band $Bit) -eq 0) { continue }
        $objectType = $rule.ObjectType
        if ($objectType) {
            $reaches = ($Root -and $objectType -eq $Root) -or ($Node -and $objectType -eq $Node) -or ($Parent -and $objectType -eq $Parent)
            if (-not $reaches) { continue }
        }
        return $rule
    }
    return $null
}

<#
.SYNOPSIS
    The nodes a right over the whole object leaves out: a scoped Deny ahead of the ACE
    that grants it.

.NOTES
    Internal helper function
#>
function Get-WriteAccessException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [AllowEmptyCollection()] $Rules,
        [Parameter(Mandatory=$true)] [hashtable]$Whole,
        [Parameter(Mandatory=$true)] [string[]]$Bits,
        [Parameter(Mandatory=$false)] [string]$Root = '',
        [Parameter(Mandatory=$true)] $Schema
    )

    $kindByBit = @{ WriteProperty = 'Attribute'; Self = 'ValidatedWrite'; ExtendedRight = 'ExtendedRight'; CreateChild = 'Class' }
    $names = @()
    foreach ($bitName in $Bits) {
        if (-not $Whole.ContainsKey($bitName)) { continue }
        $bit = $Script:WriteAccessBits[$bitName]
        $before = $Whole[$bitName].Index
        foreach ($rule in $Rules) {
            if ($rule.Index -ge $before) { break }
            if ($rule.Type -ne 'Deny' -or -not $rule.ObjectType -or $rule.ObjectType -eq $Root) { continue }
            if (($rule.Mask -band $bit) -eq 0) { continue }
            $names += Get-WriteAccessNodeName -Guid $rule.ObjectType -Kind $kindByBit[$bitName] -Schema $Schema
        }
    }
    return @($names | Select-Object -Unique)
}

<#
.SYNOPSIS
    Appends the exceptions to a target text.

.NOTES
    Internal helper function
#>
function Format-WriteAccessExcept {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)] [AllowEmptyString()] [string]$Text = '',
        [Parameter(Mandatory=$false)] [AllowEmptyCollection()] [string[]]$Except = @()
    )

    $names = @($Except | Where-Object { $_ })
    if ($names.Count -eq 0) { return $Text }
    $suffix = "except $($names -join ', ')"
    if ($Text) { return "$Text $suffix" }
    return $suffix
}

<#
.SYNOPSIS
    One result row before its SIDs are resolved.

.NOTES
    Internal helper function
#>
function New-WriteAccessRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [string]$Right,
        [Parameter(Mandatory=$true)] [string]$Kind,
        [Parameter(Mandatory=$false)] [AllowEmptyString()] [string]$Target = '',
        [Parameter(Mandatory=$false)] [AllowEmptyString()] [string]$Name = '',
        [Parameter(Mandatory=$false)] [AllowEmptyString()] [string]$NodeGuid = '',
        [Parameter(Mandatory=$true)] [AllowEmptyCollection()] [string[]]$Via,
        [Parameter(Mandatory=$false)] [string]$Source = 'ACL'
    )

    [PSCustomObject]@{
        Right    = $Right
        Target   = $Target
        Kind     = $Kind
        Name     = $Name
        NodeGuid = $NodeGuid
        Via      = @($Via | Where-Object { $_ } | Select-Object -Unique)
        Source   = $Source
    }
}

<#
.SYNOPSIS
    Whether an object of these classes is one an entry of the tables applies to.

.NOTES
    Internal helper function
#>
function Test-WriteAccessClass {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$false)] [AllowEmptyCollection()] [string[]]$Classes = @(),
        [Parameter(Mandatory=$false)] [AllowEmptyCollection()] [string[]]$Wanted = @()
    )

    if (@($Wanted).Count -eq 0) { return $true }
    foreach ($class in $Wanted) {
        if ($Classes -contains $class) { return $true }
    }
    return $false
}

<#
.SYNOPSIS
    The single nodes to evaluate on one object.

.DESCRIPTION
    For each bit no ACE grants over the whole object: the attributes, extended rights and
    child classes of the tables at the top of this file that apply to the object's classes,
    and every validated write an Allow ACE names. With -All also every node an Allow ACE
    names for that bit - attributes, property sets, extended rights, classes, and GUIDs no
    table knows.

.NOTES
    Internal helper function
#>
function Get-WriteAccessCandidate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [AllowEmptyCollection()] $Rules,
        [Parameter(Mandatory=$true)] [hashtable]$Whole,
        [Parameter(Mandatory=$false)] [AllowEmptyCollection()] [string[]]$Classes = @(),
        [Parameter(Mandatory=$true)] $Schema,
        [Parameter(Mandatory=$false)] [switch]$All
    )

    $seen = @{}
    $list = New-Object System.Collections.ArrayList
    $named = @($Rules | Where-Object { $_.Type -eq 'Allow' -and $_.ObjectType })

    $add = {
        param($Right, $Kind, $Bit, $Guid, $Parent, $Name)
        $key = "$Bit|$Guid"
        if (-not $Guid -or $seen.ContainsKey($key)) { return }
        $seen[$key] = $true
        [void]$list.Add([PSCustomObject]@{ Right = $Right; Kind = $Kind; Bit = [long]$Bit; Guid = [string]$Guid; Parent = [string]$Parent; Name = [string]$Name })
    }

    if (-not $Whole.ContainsKey('WriteProperty')) {
        foreach ($name in $Script:WriteAccessInterestingAttributes.Keys) {
            if (-not (Test-WriteAccessClass -Classes $Classes -Wanted $Script:WriteAccessInterestingAttributes[$name])) { continue }
            $guid = $Schema.AttributeGuidByName[$name]
            & $add 'WriteProperty' 'Attribute' 0x20 $guid $Schema.PropertySetByAttribute[[string]$guid] $name
        }
        # Every named node with -All. Without the schema a property set cannot be opened up
        # into the attributes above, so it is shown by its own name rather than not at all.
        foreach ($rule in @($named | Where-Object { ($_.Mask -band 0x20) -ne 0 })) {
            $guid = $rule.ObjectType
            if ($Schema.AttributeNameByGuid.ContainsKey($guid)) {
                if ($All) {
                    & $add 'WriteProperty' 'Attribute' 0x20 $guid $Schema.PropertySetByAttribute[$guid] $Schema.AttributeNameByGuid[$guid]
                }
            } elseif ($All -or (-not $Schema.FromDirectory -and $Schema.PropertySetNameByGuid.ContainsKey($guid))) {
                & $add 'WriteProperty' 'PropertySet' 0x20 $guid '' (Get-WriteAccessNodeName -Guid $guid -Kind 'PropertySet' -Schema $Schema)
            }
        }
    }

    # Every validated write is a known step; the classes only drop one that was inherited
    # onto an object it means nothing on.
    if (-not $Whole.ContainsKey('Self')) {
        foreach ($rule in @($named | Where-Object { ($_.Mask -band 0x8) -ne 0 })) {
            $name = Get-WriteAccessNodeName -Guid $rule.ObjectType -Kind 'ValidatedWrite' -Schema $Schema
            if (-not $All -and $Script:WriteAccessValidatedWriteClasses.ContainsKey($name) -and
                -not (Test-WriteAccessClass -Classes $Classes -Wanted $Script:WriteAccessValidatedWriteClasses[$name])) { continue }
            & $add 'ValidatedWrite' 'ValidatedWrite' 0x8 $rule.ObjectType '' $name
        }
    }

    if (-not $Whole.ContainsKey('ExtendedRight')) {
        foreach ($name in $Script:WriteAccessInterestingExtendedRights.Keys) {
            if (-not (Test-WriteAccessClass -Classes $Classes -Wanted $Script:WriteAccessInterestingExtendedRights[$name])) { continue }
            & $add 'ExtendedRight' 'ExtendedRight' 0x100 $Schema.ExtendedRightGuidByName[$name] '' $name
        }
        if ($All) {
            foreach ($rule in @($named | Where-Object { ($_.Mask -band 0x100) -ne 0 })) {
                & $add 'ExtendedRight' 'ExtendedRight' 0x100 $rule.ObjectType '' (Get-WriteAccessNodeName -Guid $rule.ObjectType -Kind 'ExtendedRight' -Schema $Schema)
            }
        }
    }

    if (-not $Whole.ContainsKey('CreateChild')) {
        foreach ($name in $Script:WriteAccessInterestingClasses) {
            & $add 'CreateChild' 'Class' 0x1 $Schema.ClassGuidByName[$name] '' $name
        }
        if ($All) {
            foreach ($rule in @($named | Where-Object { ($_.Mask -band 0x1) -ne 0 })) {
                & $add 'CreateChild' 'Class' 0x1 $rule.ObjectType '' (Get-WriteAccessNodeName -Guid $rule.ObjectType -Kind 'Class' -Schema $Schema)
            }
        }
    }

    return @($list)
}

<#
.SYNOPSIS
    The name of a GUID as the right it is asked for: one GUID can be an attribute, a
    property set and a validated write at once (dNSHostName), so the bit decides.

.NOTES
    Internal helper function
#>
function Get-WriteAccessNodeName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)] [AllowEmptyString()] [string]$Guid,
        [Parameter(Mandatory=$true)] [string]$Kind,
        [Parameter(Mandatory=$true)] $Schema
    )

    $order = switch ($Kind) {
        'Attribute'      { @('AttributeNameByGuid', 'PropertySetNameByGuid') }
        'PropertySet'    { @('PropertySetNameByGuid', 'AttributeNameByGuid') }
        'ValidatedWrite' { @('ValidatedWriteNameByGuid', 'ExtendedRightNameByGuid') }
        # Control access on an attribute or a property set: the read of a confidential one.
        'ExtendedRight'  { @('ExtendedRightNameByGuid', 'AttributeNameByGuid', 'PropertySetNameByGuid') }
        'Class'          { @('ClassNameByGuid') }
        default          { @() }
    }
    foreach ($map in $order) {
        if ($Schema.$map.ContainsKey($Guid)) { return [string]$Schema.$map[$Guid] }
    }
    return $Guid
}

<#
.SYNOPSIS
    Checks one object's rows against what the directory computed for the bound account.

.DESCRIPTION
    sDRightsEffective says WriteOwner (1) and WriteDacl (4), allowedAttributesEffective the
    attributes, allowedChildClassesEffective the child classes. A row those can check is
    kept as 'ACL, directory' when they agree and dropped when they do not; extended rights
    and validated writes cannot be checked and stay 'ACL'. What the directory grants and no
    row explains is added with Via '(directory)'. An object without sDRightsEffective was
    not computed for and passes unchanged.

.OUTPUTS
    PSCustomObject: Rows, Unconfirmed (rows dropped), Available (the object carried the
    directory's answer).

.NOTES
    Internal helper function
#>
function Resolve-WriteAccessEffective {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] $Object,
        [Parameter(Mandatory=$true)] [AllowEmptyCollection()] $Rows,
        [Parameter(Mandatory=$false)] [AllowEmptyCollection()] $SelfOnly = @(),
        [Parameter(Mandatory=$false)] [AllowEmptyCollection()] [string[]]$Classes = @(),
        [Parameter(Mandatory=$true)] $Schema,
        [Parameter(Mandatory=$false)] [hashtable]$CredParams = @{},
        [Parameter(Mandatory=$false)] [switch]$All
    )

    $result = [PSCustomObject]@{ Rows = @($Rows); Unconfirmed = 0; Available = $false }
    # Read only for an object with a row the directory does not confirm.
    $structure = $null
    if (-not $Object.PSObject.Properties['sDRightsEffective']) { return $result }
    $result.Available = $true

    $sdRights = 0
    try { $sdRights = [int]([string](@($Object.sDRightsEffective)[0])) } catch { $sdRights = 0 }
    $attributes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($value in @($Object.allowedAttributesEffective)) { if ($value) { [void]$attributes.Add([string]$value) } }
    $childClasses = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($value in @($Object.allowedChildClassesEffective)) { if ($value) { [void]$childClasses.Add([string]$value) } }
    $selfOnlyKeys = @{}
    foreach ($key in @($SelfOnly)) { if ($key) { $selfOnlyKeys[[string]$key] = $true } }

    $kept = New-Object System.Collections.ArrayList
    foreach ($row in @($Rows)) {
        $confirmed = $null
        switch ($row.Right) {
            'GenericAll'    { $confirmed = (($sdRights -band 5) -eq 5) }
            'WriteDacl'     { $confirmed = (($sdRights -band 4) -ne 0) }
            'WriteOwner'    { $confirmed = (($sdRights -band 1) -ne 0) }
            'Owner'         { $confirmed = (($sdRights -band 4) -ne 0) }
            'GenericWrite'  { $confirmed = ($attributes.Count -gt 0) }
            'WriteProperty' {
                if ($row.Kind -eq 'Attribute') { $confirmed = $attributes.Contains([string]$row.Name) }
                else { $confirmed = ($attributes.Count -gt 0) }
            }
            'CreateChild'   {
                if ($row.Kind -eq 'Class') { $confirmed = $childClasses.Contains([string]$row.Name) }
                else { $confirmed = ($childClasses.Count -gt 0) }
            }
        }
        if ($null -eq $confirmed) { [void]$kept.Add($row); continue }
        if ($confirmed) {
            $row.Source = 'ACL, directory'
            [void]$kept.Add($row)
        } else {
            # An ACE may grant what the object cannot hold - an attribute its class does not
            # have, a child class the schema does not allow below it. The directory leaves
            # those out of its answer, and that is no disagreement.
            if ($null -eq $structure) { $structure = Get-WriteAccessStructure -DistinguishedName ([string]$Object.distinguishedName) -CredParams $CredParams }
            if (-not (Test-WriteAccessHeld -Row $row -Structure $structure -Schema $Schema)) {
                Write-Log "[Get-DomainWriteAccess] Granted on something $($Object.distinguishedName) cannot hold: $($row.Right) $($row.Target)"
                continue
            }
            $result.Unconfirmed++
            Write-Log "[Get-DomainWriteAccess] Not confirmed by the directory on $($Object.distinguishedName): $($row.Right) $($row.Target) via $(@($row.Via) -join ', ')"
        }
    }

    $rights = @($kept | ForEach-Object { $_.Right })
    $everyProperty = @($kept | Where-Object { $_.Right -eq 'GenericAll' -or $_.Right -eq 'GenericWrite' -or ($_.Right -eq 'WriteProperty' -and $_.Kind -eq 'Whole') }).Count -gt 0
    $everyClass = @($kept | Where-Object { $_.Right -eq 'GenericAll' -or ($_.Right -eq 'CreateChild' -and $_.Kind -eq 'Whole') }).Count -gt 0

    if (($sdRights -band 4) -and @($rights | Where-Object { @('GenericAll', 'WriteDacl', 'Owner') -contains $_ }).Count -eq 0 -and
        ($All -or -not $selfOnlyKeys.ContainsKey('WriteDacl:'))) {
        [void]$kept.Add((New-WriteAccessRow -Right 'WriteDacl' -Kind 'Whole' -Via @('(directory)') -Source 'directory'))
    }
    if (($sdRights -band 1) -and @($rights | Where-Object { @('GenericAll', 'WriteOwner') -contains $_ }).Count -eq 0 -and
        ($All -or -not $selfOnlyKeys.ContainsKey('WriteOwner:'))) {
        [void]$kept.Add((New-WriteAccessRow -Right 'WriteOwner' -Kind 'Whole' -Via @('(directory)') -Source 'directory'))
    }

    if (-not $everyProperty) {
        foreach ($attribute in @($attributes)) {
            if (-not $All) {
                if (-not $Script:WriteAccessInterestingAttributes.Contains($attribute)) { continue }
                if (-not (Test-WriteAccessClass -Classes $Classes -Wanted $Script:WriteAccessInterestingAttributes[$attribute])) { continue }
                if ($selfOnlyKeys.ContainsKey("WriteProperty:$attribute")) { continue }
            }
            # Explained by a row already: the attribute itself, or the property set it is in.
            $set = ''
            $attributeGuid = $Schema.AttributeGuidByName[$attribute]
            if ($attributeGuid) { $set = [string]$Schema.PropertySetByAttribute[[string]$attributeGuid] }
            $explained = @($kept | Where-Object {
                $_.Right -eq 'WriteProperty' -and (($_.Kind -eq 'Attribute' -and $_.Name -eq $attribute) -or ($set -and $_.Kind -eq 'PropertySet' -and $_.NodeGuid -eq $set))
            }).Count -gt 0
            if ($explained) { continue }
            [void]$kept.Add((New-WriteAccessRow -Right 'WriteProperty' -Kind 'Attribute' -Name $attribute -Target $attribute -Via @('(directory)') -Source 'directory'))
        }
    }

    if (-not $everyClass) {
        foreach ($class in @($childClasses)) {
            if (-not $All) {
                if ($Script:WriteAccessInterestingClasses -notcontains $class) { continue }
                if ($selfOnlyKeys.ContainsKey("CreateChild:$class")) { continue }
            }
            if (@($kept | Where-Object { $_.Right -eq 'CreateChild' -and $_.Kind -eq 'Class' -and $_.Name -eq $class }).Count -gt 0) { continue }
            [void]$kept.Add((New-WriteAccessRow -Right 'CreateChild' -Kind 'Class' -Name $class -Target $class -Via @('(directory)') -Source 'directory'))
        }
    }

    $result.Rows = @($kept)
    return $result
}

<#
.SYNOPSIS
    The SIDs an account's token carries in this domain.

.DESCRIPTION
    Its own SID and sIDHistory; every group it reaches through member links, in-chain
    (Get-RecursiveGroupMembership); its primary group, which leaves no member link, with
    that group's own nesting; and Everyone, Authenticated Users and This Organization,
    which every authenticated token holds, with the groups their foreign security
    principals are members of - Pre-Windows 2000 Compatible Access, for one.

    Without -Identity, the account adPEAS is bound as, by the DN, SID or name the
    connection recorded.

.OUTPUTS
    PSCustomObject: SID, DistinguishedName, Name, SIDs (HashSet), or $null.

.NOTES
    Internal helper function
#>
function Get-WriteAccessToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)] [AllowEmptyString()] [string]$Identity,
        [Parameter(Mandatory=$false)] [switch]$Bound,
        [Parameter(Mandatory=$false)] [hashtable]$CredParams = @{}
    )

    if ($Bound) {
        $Identity = ''
        # What Connect-LDAP verified, most precise first. Username is what was typed, and a
        # bracketed value there is a placeholder for an identity nobody could establish.
        foreach ($key in @('AuthenticatedUserDN', 'AuthenticatedUserSID', 'AuthenticatedUserSAM', 'AuthenticatedUserUPN', 'Username')) {
            if (-not $Script:LDAPContext -or -not $Script:LDAPContext[$key]) { continue }
            $value = [string]$Script:LDAPContext[$key]
            if ($value.StartsWith('[')) { continue }
            $Identity = $value
            break
        }
        if (-not $Identity) {
            Write-Warning "[Get-DomainWriteAccess] The account adPEAS is bound as is not known - name it with -Identity"
            return $null
        }
    }
    if (-not $Identity) {
        Write-Warning "[Get-DomainWriteAccess] No identity given"
        return $null
    }

    $properties = @('objectSid', 'distinguishedName', 'sAMAccountName', 'name', 'primaryGroupID', 'sIDHistory', 'objectClass')
    $found = @(Get-DomainObject -Identity $Identity -Properties $properties @CredParams | Where-Object { $_ -and $_.objectSid })
    # A user principal name is not one of the forms -Identity takes.
    if ($found.Count -eq 0 -and $Identity -match '^[^\=@]+@[^@]+$') {
        $upn = Escape-LDAPFilterValue -Value $Identity
        $found = @(Get-DomainObject -LDAPFilter "(userPrincipalName=$upn)" -Properties $properties @CredParams | Where-Object { $_ -and $_.objectSid })
    }
    # The name form also matches cn and name; an exact sAMAccountName wins over those.
    if ($found.Count -gt 1) {
        $exact = @($found | Where-Object { [string]$_.sAMAccountName -eq $Identity })
        if ($exact.Count -eq 1) { $found = $exact }
    }
    if ($found.Count -eq 0) {
        Write-Warning "[Get-DomainWriteAccess] '$Identity' was not found"
        return $null
    }
    if ($found.Count -gt 1) {
        Write-Warning "[Get-DomainWriteAccess] '$Identity' matches $($found.Count) objects - name it by DN or SID"
        return $null
    }
    $principal = $found[0]

    $sid = [string]$principal.objectSid
    $sids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    [void]$sids.Add($sid)
    foreach ($historySid in @($principal.sIDHistory)) { if ($historySid) { [void]$sids.Add([string]$historySid) } }
    foreach ($groupSid in @(Get-RecursiveGroupMembership -IdentitySID $sid -IdentityDN ([string]$principal.distinguishedName))) {
        if ($groupSid) { [void]$sids.Add([string]$groupSid) }
    }
    # The primary group's RID is relative to the account's own domain.
    if ($principal.primaryGroupID -and $sid -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$') {
        $primaryGroupSid = "$($Matches[1])-$($principal.primaryGroupID)"
        [void]$sids.Add($primaryGroupSid)
        foreach ($groupSid in @(Get-RecursiveGroupMembership -IdentitySID $primaryGroupSid)) {
            if ($groupSid) { [void]$sids.Add([string]$groupSid) }
        }
    }
    foreach ($wellKnown in @('S-1-1-0', 'S-1-5-11', 'S-1-5-15')) {
        [void]$sids.Add($wellKnown)
        foreach ($groupSid in @(Get-RecursiveGroupMembership -IdentitySID $wellKnown)) {
            if ($groupSid) { [void]$sids.Add([string]$groupSid) }
        }
    }

    $name = [string]$principal.sAMAccountName
    if (-not $name) { $name = [string]$principal.name }
    return [PSCustomObject]@{
        SID               = $sid
        DistinguishedName = [string]$principal.distinguishedName
        Name              = $name
        SIDs              = $sids
    }
}

<#
.SYNOPSIS
    The schema facts the evaluation needs, read once per session.

.DESCRIPTION
    Attribute name and schemaIDGUID, and the property set each attribute belongs to
    (attributeSecurityGUID); class name and schemaIDGUID; and the controlAccessRight
    objects under CN=Extended-Rights with what each one is - an extended right (0x100 in
    validAccesses), a validated write (0x8) or a property set (0x30). The static tables in
    adPEAS-GUIDs.ps1 are loaded first, so a schema that cannot be read still names the
    common GUIDs; it cannot say which attributes a property set holds, and a write through
    a set is then named by the set alone.

.NOTES
    Internal helper function. Cached in $Script:WriteAccessSchemaCache, cleared by
    Clear-SessionState - the schema belongs to the forest of the session.
#>
function Get-WriteAccessSchema {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)] [hashtable]$CredParams = @{}
    )

    if ($null -ne $Script:WriteAccessSchemaCache) { return $Script:WriteAccessSchemaCache }

    $schema = [PSCustomObject]@{
        AttributeNameByGuid      = @{}
        AttributeGuidByName      = @{}
        PropertySetByAttribute   = @{}
        ClassNameByGuid          = @{}
        ClassGuidByName          = @{}
        PropertySetNameByGuid    = @{}
        ValidatedWriteNameByGuid = @{}
        ExtendedRightNameByGuid  = @{}
        ExtendedRightGuidByName  = @{}
        FromDirectory            = $false
    }

    foreach ($entry in $Script:PropertyGUIDs.GetEnumerator()) {
        $guid = $entry.Value.ToString().ToLower()
        $schema.AttributeNameByGuid[$guid] = $entry.Key
        $schema.AttributeGuidByName[$entry.Key] = $guid
    }
    foreach ($entry in $Script:SchemaClassGUIDs.GetEnumerator()) {
        $guid = $entry.Value.ToString().ToLower()
        $schema.ClassNameByGuid[$guid] = $entry.Key
        $schema.ClassGuidByName[$entry.Key] = $guid
    }
    foreach ($entry in $Script:PropertySetGUIDs.GetEnumerator()) {
        $schema.PropertySetNameByGuid[$entry.Value.ToString().ToLower()] = $entry.Key
    }
    foreach ($entry in $Script:ValidatedWriteGUIDs.GetEnumerator()) {
        $schema.ValidatedWriteNameByGuid[$entry.Value.ToString().ToLower()] = $entry.Key
    }
    foreach ($entry in $Script:ExtendedRightsGUIDs.GetEnumerator()) {
        $guid = ([string]$entry.Key).ToLower()
        $schema.ExtendedRightNameByGuid[$guid] = $entry.Value
        if (-not $schema.ExtendedRightGuidByName.ContainsKey($entry.Value)) { $schema.ExtendedRightGuidByName[$entry.Value] = $guid }
    }

    $configDN = ''
    $schemaDN = ''
    if ($Script:LDAPContext) {
        $configDN = [string]$Script:LDAPContext.ConfigurationNamingContext
        $schemaDN = [string]$Script:LDAPContext.SchemaNamingContext
    }
    if (-not $schemaDN -and $configDN) { $schemaDN = "CN=Schema,$configDN" }

    try {
        if ($schemaDN) {
            $attributes = @(Get-DomainObject -LDAPFilter '(objectClass=attributeSchema)' -SearchBase $schemaDN `
                -Properties 'lDAPDisplayName', 'schemaIDGUID', 'attributeSecurityGUID' -Raw @CredParams)
            foreach ($attribute in $attributes) {
                $guid = ConvertTo-WriteAccessGuid -Value $attribute.schemaIDGUID
                $name = [string]$attribute.lDAPDisplayName
                if (-not $guid -or -not $name) { continue }
                $schema.AttributeNameByGuid[$guid] = $name
                $schema.AttributeGuidByName[$name] = $guid
                $set = ConvertTo-WriteAccessGuid -Value $attribute.attributeSecurityGUID
                if ($set) { $schema.PropertySetByAttribute[$guid] = $set }
            }
            $classes = @(Get-DomainObject -LDAPFilter '(objectClass=classSchema)' -SearchBase $schemaDN `
                -Properties 'lDAPDisplayName', 'schemaIDGUID' -Raw @CredParams)
            foreach ($class in $classes) {
                $guid = ConvertTo-WriteAccessGuid -Value $class.schemaIDGUID
                $name = [string]$class.lDAPDisplayName
                if (-not $guid -or -not $name) { continue }
                $schema.ClassNameByGuid[$guid] = $name
                $schema.ClassGuidByName[$name] = $guid
            }
            $schema.FromDirectory = ($attributes.Count -gt 0)
        }
    } catch {
        Write-Log "[Get-DomainWriteAccess] The schema could not be read completely: $_"
    }

    # On its own: a schema that cannot be read is no reason to go without the rights' names.
    try {
        if ($configDN) {
            $rights = @(Get-DomainObject -LDAPFilter '(objectClass=controlAccessRight)' -SearchBase "CN=Extended-Rights,$configDN" `
                -Properties 'name', 'rightsGuid', 'validAccesses' @CredParams)
            foreach ($right in $rights) {
                $guid = ConvertTo-WriteAccessGuid -Value $right.rightsGuid
                $name = [string]$right.name
                if (-not $guid -or -not $name) { continue }
                $validAccesses = 0
                try { $validAccesses = [int]([string](@($right.validAccesses)[0])) } catch { $validAccesses = 0 }
                if ($validAccesses -band 0x100) {
                    $schema.ExtendedRightNameByGuid[$guid] = $name
                    $schema.ExtendedRightGuidByName[$name] = $guid
                }
                if ($validAccesses -band 0x8) { $schema.ValidatedWriteNameByGuid[$guid] = $name }
                if ($validAccesses -band 0x30) { $schema.PropertySetNameByGuid[$guid] = $name }
            }
        }
    } catch {
        Write-Log "[Get-DomainWriteAccess] The control access rights could not be read: $_"
    }

    if (-not $schema.FromDirectory) {
        Write-Warning "[Get-DomainWriteAccess] The schema could not be read - a write through a property set is named by the set, not by its attributes"
    }
    Write-Log "[Get-DomainWriteAccess] Schema: $($schema.AttributeNameByGuid.Count) attribute(s), $($schema.PropertySetByAttribute.Count) in a property set, $($schema.ClassNameByGuid.Count) class(es)"

    $Script:WriteAccessSchemaCache = $schema
    return $schema
}

<#
.SYNOPSIS
    A GUID in registry form, lower case, from a schema attribute value.

.DESCRIPTION
    schemaIDGUID and attributeSecurityGUID arrive as 16 bytes - unless those bytes happen
    to be valid UTF-8, in which case the search hands them over as text, which encodes
    back to the same bytes. rightsGuid is text in registry form.

.NOTES
    Internal helper function
#>
function ConvertTo-WriteAccessGuid {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)] [AllowNull()] $Value
    )

    if ($null -eq $Value) { return '' }
    if ($Value -is [array] -and $Value -isnot [byte[]]) {
        if ($Value.Count -eq 1) { $Value = $Value[0] }
        elseif ($Value.Count -eq 16) { $Value = [byte[]]@($Value) }
    }
    try {
        if ($Value -is [byte[]]) {
            if ($Value.Length -ne 16) { return '' }
            return ([Guid]::new($Value)).ToString()
        }
        $text = ([string]$Value).Trim('{', '}')
        $parsed = [Guid]::Empty
        if ([Guid]::TryParse($text, [ref]$parsed)) { return $parsed.ToString() }
        $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$Value)
        if ($bytes.Length -eq 16) { return ([Guid]::new($bytes)).ToString() }
    } catch {
        Write-Log "[Get-DomainWriteAccess] Not a GUID: $_"
    }
    return ''
}

<#
.SYNOPSIS
    An objectSid value - raw bytes or text - as a SID string.

.NOTES
    Internal helper function
#>
function ConvertTo-WriteAccessSid {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)] [AllowNull()] $Value
    )

    if ($null -eq $Value) { return '' }
    try {
        if ($Value -is [byte[]]) { return (New-Object System.Security.Principal.SecurityIdentifier($Value, 0)).Value }
        $text = [string]$Value
        if ($text -match '^S-1-') { return $text }
    } catch {
        Write-Log "[Get-DomainWriteAccess] Not a SID: $_"
    }
    return ''
}

<#
.SYNOPSIS
    The attributes and child classes an object can hold at all, as the directory computes
    them for its class and auxiliary classes (allowedAttributes, allowedChildClasses).

.OUTPUTS
    PSCustomObject: Read, Attributes (HashSet), Classes (HashSet).

.NOTES
    Internal helper function
#>
function Get-WriteAccessStructure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] [string]$DistinguishedName,
        [Parameter(Mandatory=$false)] [hashtable]$CredParams = @{}
    )

    $structure = [PSCustomObject]@{
        Read       = $false
        Attributes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        Classes    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }
    try {
        $object = @(Get-DomainObject -SearchBase $DistinguishedName -Scope Base -LDAPFilter '(objectClass=*)' `
            -Properties 'allowedAttributes', 'allowedChildClasses' -Raw @CredParams)[0]
        if ($object) {
            foreach ($value in @($object.allowedAttributes)) { if ($value) { [void]$structure.Attributes.Add([string]$value) } }
            foreach ($value in @($object.allowedChildClasses)) { if ($value) { [void]$structure.Classes.Add([string]$value) } }
            $structure.Read = ($structure.Attributes.Count -gt 0)
        }
    } catch {
        Write-Log "[Get-DomainWriteAccess] The structure of $DistinguishedName could not be read: $_"
    }
    return $structure
}

<#
.SYNOPSIS
    Whether the object can hold what a row grants. $true when that cannot be decided -
    a row is only set aside for a reason the directory itself gave.

.NOTES
    Internal helper function
#>
function Test-WriteAccessHeld {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)] $Row,
        [Parameter(Mandatory=$true)] $Structure,
        [Parameter(Mandatory=$true)] $Schema
    )

    if (-not $Structure.Read) { return $true }
    switch ($Row.Kind) {
        'Attribute' { return $Structure.Attributes.Contains([string]$Row.Name) }
        'Class'     { return $Structure.Classes.Contains([string]$Row.Name) }
        'PropertySet' {
            # Which attributes the set holds is known only from the schema itself.
            if (-not $Schema.FromDirectory) { return $true }
            foreach ($entry in $Schema.PropertySetByAttribute.GetEnumerator()) {
                if ($entry.Value -ne $Row.NodeGuid) { continue }
                $name = $Schema.AttributeNameByGuid[$entry.Key]
                if ($name -and $Structure.Attributes.Contains([string]$name)) { return $true }
            }
            return $false
        }
    }
    return $true
}
