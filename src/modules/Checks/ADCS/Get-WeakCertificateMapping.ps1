function Get-WeakCertificateMapping {
    <#
    .SYNOPSIS
    Detects ESC14 - explicit certificate mappings that can be abused to authenticate as
    another principal.

    .DESCRIPTION
    A certificate normally binds to an account through the SID extension the CA writes into
    it. altSecurityIdentities overrides that: it maps a certificate to an account
    explicitly, and Active Directory accepts six formats for it. Three of them are strong,
    because they name something about the certificate that cannot be reproduced, and three
    are weak, because they name something an attacker can put into a certificate of their
    own (KB5014754):

        X509:<I>Issuer<SR>Serial    strong   issuer and serial number
        X509:<SKI>...               strong   subject key identifier
        X509:<SHA1-PUKEY>...        strong   hash of the public key

        X509:<I>Issuer<S>Subject    weak     issuer and subject name
        X509:<S>Subject             weak     subject name only
        X509:<RFC822>mail@domain    weak     e-mail address

    The two issuer forms are told apart by their second tag, not by the first: <I> opens
    both the strong and the weak one, and only <SR> versus <S> decides which.

    Two things are reported, and they are different problems:

      1. A principal that already carries a weak mapping. Anyone who can get a certificate
         whose subject or e-mail matches it authenticates as that principal, and on a
         template where the enrollee supplies the subject that is a single request.

      2. A principal whose altSecurityIdentities attribute a non-privileged trustee may
         write. That is the mapping being added rather than found - the original ESC14, and
         it works whether or not a mapping is there today.

    The second part is limited to privileged principals on purpose. Write access to this
    attribute is only an escalation if the account it maps to is worth reaching, and a
    domain-wide ACL sweep over every user costs a great deal to answer a question that
    matters for a handful of them.

    .PARAMETER Domain
    Domain to analyze. Defaults to the domain of the current session.

    .PARAMETER Server
    Domain controller to query.

    .PARAMETER Credential
    Credentials for the connection.

    .EXAMPLE
    Get-WeakCertificateMapping

    .EXAMPLE
    Get-WeakCertificateMapping -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-WeakCertificateMapping] Starting ESC14 explicit certificate mapping analysis"
    }

    process {
        if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
            return
        }

        # Connection parameters for the inner Get-Domain* calls. Built explicitly rather
        # than splatted from $PSBoundParameters, which inner scopes cannot see.
        $connectionParams = @{}
        if ($PSBoundParameters.ContainsKey('Domain'))     { $connectionParams['Domain'] = $Domain }
        if ($PSBoundParameters.ContainsKey('Server'))     { $connectionParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

        # ==================================================================
        # 1. Principals that already carry an explicit mapping
        # ==================================================================
        Show-SubHeader "Analyzing explicit certificate mappings (ESC14)..." -ObjectType "WeakCertificateMapping"

        # Two phases, the way Get-NonDefaultUserOwners reads owners across the domain.
        #
        # Phase 1 asks for the distinguished name and the attribute and nothing else. The
        # filter is server-side, but in a smart-card deployment it still matches every
        # enrolled user - thousands of principals whose every attribute would otherwise
        # cross the wire so that a handful with a weak mapping can be reported. -Properties
        # is what rule 5 permits here: these objects are never shown, they only decide who
        # is worth a second look.
        $candidates = @()
        try {
            $lightProperties = @('distinguishedName', 'sAMAccountName', 'objectSid', 'altSecurityIdentities')

            foreach ($user in @(Get-DomainUser -LDAPFilter '(altSecurityIdentities=*)' -Properties $lightProperties @connectionParams)) {
                if ($user) { $candidates += [PSCustomObject]@{ Object = $user; IsComputer = $false } }
            }
            foreach ($computer in @(Get-DomainComputer -LDAPFilter '(altSecurityIdentities=*)' -Properties $lightProperties @connectionParams)) {
                if ($computer) { $candidates += [PSCustomObject]@{ Object = $computer; IsComputer = $true } }
            }
        }
        catch {
            Write-Log "[Get-WeakCertificateMapping] Query for altSecurityIdentities failed: $_" -Level Warning
            Show-Line "Could not read explicit certificate mappings: $($_.Exception.Message)" -Class Note
            return
        }

        Write-Log "[Get-WeakCertificateMapping] Found $(@($candidates).Count) principal(s) with an explicit mapping"

        $weakFindings = @()
        foreach ($candidate in $candidates) {
            $principal = $candidate.Object

            $weakMappings   = @()
            $strongMappings = @()

            foreach ($mapping in @($principal.altSecurityIdentities)) {
                if ([string]::IsNullOrWhiteSpace($mapping)) { continue }

                $strength = Get-CertificateMappingStrength -Mapping ([string]$mapping)
                if ($strength -eq 'Weak') {
                    $weakMappings += [string]$mapping
                } elseif ($strength -eq 'Strong') {
                    $strongMappings += [string]$mapping
                } else {
                    # Neither an X509 form nor anything AD maps a certificate through -
                    # Kerberos and NTLM identities also live in this attribute. Reported as
                    # neither, rather than guessed at.
                    Write-Log "[Get-WeakCertificateMapping] Ignoring non-X509 mapping on '$($principal.sAMAccountName)': $mapping"
                }
            }

            if (@($weakMappings).Count -eq 0) { continue }

            $isPrivileged = $false
            try {
                $isPrivileged = [bool](Test-IsPrivileged -Identity $principal.objectSid @connectionParams)
            } catch {
                Write-Log "[Get-WeakCertificateMapping] Privilege check failed for '$($principal.sAMAccountName)': $_"
            }

            # Phase 2, and only now: the full object, without -Properties, because this one
            # is going to be shown and Show-Object decides what a reader sees. One query per
            # finding rather than per candidate.
            $displayObject = $null
            try {
                $displayObject = if ($candidate.IsComputer) {
                    @(Get-DomainComputer -Identity $principal.distinguishedName @connectionParams)[0]
                } else {
                    @(Get-DomainUser -Identity $principal.distinguishedName @connectionParams)[0]
                }
            } catch {
                Write-Log "[Get-WeakCertificateMapping] Could not re-read '$($principal.distinguishedName)': $_"
            }

            # The light object still carries name, SID and the mappings, so a failed
            # re-read costs detail rather than the finding.
            if (-not $displayObject) { $displayObject = $principal }

            $displayObject | Add-Member -NotePropertyName 'weakCertificateMappings' -NotePropertyValue @($weakMappings) -Force
            if (@($strongMappings).Count -gt 0) {
                $displayObject | Add-Member -NotePropertyName 'strongCertificateMappings' -NotePropertyValue @($strongMappings) -Force
            }
            $displayObject | Add-Member -NotePropertyName 'mappingIsPrivilegedTarget' -NotePropertyValue $isPrivileged -Force
            $displayObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'WeakCertificateMapping' -Force

            $weakFindings += [PSCustomObject]@{
                Object       = $displayObject
                IsPrivileged = $isPrivileged
            }
        }

        if (@($weakFindings).Count -gt 0) {
            $privilegedCount = @($weakFindings | Where-Object { $_.IsPrivileged }).Count
            $countText = if ($privilegedCount -gt 0) {
                "$(@($weakFindings).Count) principal(s) with a weak explicit certificate mapping, $privilegedCount of them privileged"
            } else {
                "$(@($weakFindings).Count) principal(s) with a weak explicit certificate mapping"
            }
            Show-Line "Found $countText" -Class Finding -FindingId 'ESC14_WEAK_EXPLICIT_MAPPING'

            # Privileged targets first: those are the ones worth the reader's attention.
            foreach ($finding in ($weakFindings | Sort-Object -Property @{Expression = { -not $_.IsPrivileged }})) {
                Show-Object $finding.Object -Class Finding
            }
        }
        elseif (@($candidates).Count -gt 0) {
            Show-Line "All $(@($candidates).Count) explicit certificate mapping(s) use a strong format" -Class Secure
        }
        else {
            Show-Line "No principal uses an explicit certificate mapping" -Class Secure
        }

        # ==================================================================
        # 2. Who may write altSecurityIdentities on a privileged principal
        # ==================================================================
        $writableFindings = @()
        try {
            # One query for every privileged principal and its security descriptor, rather
            # than Get-ObjectACL per account: that helper reads the object it is given, so
            # a loop over it costs one LDAP round trip per privileged account, and
            # adminCount is a sticky flag - it stays set after the account leaves the group,
            # so the list is longer than the domain's actual administrators. -Raw keeps
            # nTSecurityDescriptor as the bytes ConvertFrom-SecurityDescriptor takes.
            $privilegedTargets = @(Get-DomainUser -LDAPFilter '(adminCount=1)' `
                -Properties 'distinguishedName', 'sAMAccountName', 'nTSecurityDescriptor' -Raw @connectionParams)
            Write-Log "[Get-WeakCertificateMapping] Checking altSecurityIdentities write access on $(@($privilegedTargets).Count) privileged principal(s)"

            foreach ($target in $privilegedTargets) {
                if (-not $target.distinguishedName) { continue }
                if (-not $target.nTSecurityDescriptor) { continue }

                $descriptor = $null
                try {
                    $descriptor = ConvertFrom-SecurityDescriptor -SecurityDescriptorBytes $target.nTSecurityDescriptor
                } catch {
                    Write-Log "[Get-WeakCertificateMapping] Could not read the descriptor of '$($target.distinguishedName)': $_"
                    continue
                }

                $writers = @()
                foreach ($ace in @($descriptor.ACEs)) {
                    if (-not $ace) { continue }
                    # ConvertFrom-SecurityDescriptor names these Type and SID.
                    if ($ace.Type -ne 'Allow') { continue }
                    if (-not (Test-AltSecurityIdentitiesWrite -Ace $ace)) { continue }

                    $trusteeSID = [string]$ace.SID
                    if ([string]::IsNullOrWhiteSpace($trusteeSID)) { continue }

                    $trusteePrivileged = $false
                    try {
                        $trusteePrivileged = [bool](Test-IsPrivileged -Identity $trusteeSID @connectionParams)
                    } catch { }

                    # A trustee that is already privileged holds nothing it did not have.
                    if ($trusteePrivileged) { continue }

                    $trusteeName = if ($ace.Name) { $ace.Name } else { ConvertFrom-SID -SID $trusteeSID }
                    $writers += "${trusteeName}: $($ace.Rights)"
                }

                if (@($writers).Count -eq 0) { continue }

                # Second phase again: the full object, only for an account that is actually
                # reported.
                $displayObject = $null
                try {
                    $displayObject = @(Get-DomainUser -Identity $target.distinguishedName @connectionParams)[0]
                } catch {
                    Write-Log "[Get-WeakCertificateMapping] Could not re-read '$($target.distinguishedName)': $_"
                }
                if (-not $displayObject) { $displayObject = $target }

                $displayObject | Add-Member -NotePropertyName 'altSecurityIdentitiesWriters' -NotePropertyValue @($writers) -Force
                $displayObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'WeakCertificateMapping' -Force
                $writableFindings += $displayObject
            }
        }
        catch {
            Write-Log "[Get-WeakCertificateMapping] Write-access analysis failed: $_" -Level Warning
        }

        if (@($writableFindings).Count -gt 0) {
            Show-Line "Found $(@($writableFindings).Count) privileged principal(s) whose altSecurityIdentities a non-privileged principal may write" -Class Finding -FindingId 'ESC14_WRITABLE_MAPPING'
            foreach ($finding in $writableFindings) {
                Show-Object $finding -Class Finding
            }
        }
        else {
            Show-Line "No non-privileged principal can write altSecurityIdentities on a privileged account" -Class Secure
        }
    }

    end {
        Write-Log "[Get-WeakCertificateMapping] Completed"
    }
}

<#
.SYNOPSIS
    Classifies one altSecurityIdentities value as a strong or weak certificate mapping.
.DESCRIPTION
    The six X509 forms from KB5014754. The order of the tests matters: <I> opens both the
    strong issuer-and-serial form and the weak issuer-and-subject form, so the second tag
    decides, and <SR> has to be looked for before <S> - a test for <S> alone matches the
    "<SR>" text as well.
.PARAMETER Mapping
    One raw value of the altSecurityIdentities attribute.
.OUTPUTS
    [string] 'Strong', 'Weak', or 'Other' for a value that maps no certificate at all
    (the attribute also holds Kerberos and NTLM identities).
#>
function Get-CertificateMappingStrength {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]$Mapping
    )

    if ([string]::IsNullOrWhiteSpace($Mapping)) { return 'Other' }

    $value = $Mapping.Trim()
    if ($value -notmatch '^(?i)X509:') { return 'Other' }

    # Strong first, because two of the three weak patterns are prefixes of a strong one.
    if ($value -match '(?i)<SKI>')        { return 'Strong' }
    if ($value -match '(?i)<SHA1-PUKEY>') { return 'Strong' }
    if ($value -match '(?i)<SR>')         { return 'Strong' }

    if ($value -match '(?i)<RFC822>')     { return 'Weak' }
    if ($value -match '(?i)<S>')          { return 'Weak' }

    # An X509 value in none of the six shapes. Not classified rather than guessed at.
    return 'Other'
}

<#
.SYNOPSIS
    Decides whether one ACE grants write access to altSecurityIdentities.
.DESCRIPTION
    Three ways to hold it: a WriteProperty ACE naming the attribute, a WriteProperty ACE
    naming nothing (which covers every property), or one of the blanket rights.
.PARAMETER Ace
    A formatted ACE as ConvertFrom-SecurityDescriptor returns it.
.OUTPUTS
    [bool]
#>
function Test-AltSecurityIdentitiesWrite {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # AllowNull so the guard below is reachable: without it the binding rejects $null
        # first and the guard is dead code. An ACL can legitimately hand back an empty slot.
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Ace
    )

    if (-not $Ace) { return $false }

    $rights = [string]$Ace.Rights
    if ([string]::IsNullOrWhiteSpace($rights)) { return $false }

    # The blanket rights carry it regardless of what the ACE names.
    if ($rights -match '(?i)GenericAll|GenericWrite|WriteDacl|WriteOwner') { return $true }

    if ($rights -notmatch '(?i)WriteProperty') { return $false }

    # A WriteProperty ACE that names the attribute, or names nothing at all - the latter
    # applies to every property of the object.
    $objectType = [string]$Ace.ObjectType
    if ([string]::IsNullOrWhiteSpace($objectType)) { return $true }
    if ($objectType -match '(?i)altSecurityIdentities') { return $true }
    if ($objectType -match '(?i)00fbf30c-91fe-11d1-aebc-0000f80367c1') { return $true }

    return $false
}
