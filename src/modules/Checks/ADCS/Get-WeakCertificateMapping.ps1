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

    Its writers are reported in two lists rather than one. The Exchange service groups -
    Exchange Trusted Subsystem, Exchange Servers, Organization Management and the rest of
    the Microsoft Exchange Security Groups OU - hold blanket rights on user objects because
    the Exchange setup writes that ACL, and it lands on every privileged account in the
    domain at once. Those rights are real, and Exchange holding GenericAll on an
    administrator is a documented escalation path, so they are kept and shown; they are not
    the delegation this check is looking for, so they are shown apart and in a different
    colour. Reporting them red alongside the genuine ones taught the reader to skip the
    section that carries both.

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
        [Management.Automation.PSCredential]$Credential,

        # Exchange service groups hold these rights by design. Without this switch the
        # check printed them in every scan of every domain that runs Exchange, and the
        # green verdict below could never be reached.
        [Parameter(Mandatory = $false)]
        [switch]$IncludePrivileged
    )

    begin {
        Write-Log "[Get-WeakCertificateMapping] Starting ESC14 explicit certificate mapping analysis"
    }

    process {
        # Connection parameters for Ensure-LDAPConnection and for the inner Get-Domain*
        # calls. Built explicitly rather than splatted from $PSBoundParameters: that one
        # carries every parameter the caller passed, and Ensure-LDAPConnection accepts only
        # these three - so adding any further parameter to this check made the splat throw
        # on the first line of the check, in every scan, before anything ran.
        $connectionParams = @{}
        if ($PSBoundParameters.ContainsKey('Domain'))     { $connectionParams['Domain'] = $Domain }
        if ($PSBoundParameters.ContainsKey('Server'))     { $connectionParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

        if (-not (Ensure-LDAPConnection @connectionParams)) {
            return
        }

        # ==================================================================
        # 1. Principals that already carry an explicit mapping
        # ==================================================================
        Show-SubHeader "Analyzing explicit certificate mappings..." -ObjectType "WeakCertificateMapping"

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

            # .IsPrivileged, not [bool] of the result: Test-IsPrivileged returns an object,
            # and [bool] of any object is $true - so every weak mapping was reported as
            # sitting on a privileged principal. And no connection splat: the function takes
            # Identity, IncludeOperators and NoCache and nothing else, so passing Domain or
            # Server threw, which the catch below turned into "not privileged" for every
            # principal. The answer was wrong in one direction or the other depending only
            # on whether the caller had named a domain.
            $isPrivileged = $false
            try {
                $isPrivileged = ((Test-IsPrivileged -Identity $principal.objectSid).IsPrivileged -eq $true)
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

        # Can a certificate authenticate in this domain at all? A mapping names a pattern,
        # not a certificate, so there is no chain to validate here - the certificate does
        # not exist until someone enrols one. What can be established is whether any
        # issuer is trusted to begin with, and without one the pattern matches nothing.
        # Resolved guards the downgrade: an unreadable Configuration partition must not
        # quietly turn a real finding into a hint.
        $trustAnchor = Get-CertificateTrustAnchor
        $noTrustAnchor = ($trustAnchor.Resolved -and -not $trustAnchor.HasAuthenticationAnchor)
        $mappingClass = if ($noTrustAnchor) { 'Hint' } else { 'Finding' }

        if (@($weakFindings).Count -gt 0) {
            $privilegedCount = @($weakFindings | Where-Object { $_.IsPrivileged }).Count
            $countText = if ($privilegedCount -gt 0) {
                "$(@($weakFindings).Count) principal(s) with a weak explicit certificate mapping, $privilegedCount of them privileged"
            } else {
                "$(@($weakFindings).Count) principal(s) with a weak explicit certificate mapping"
            }
            Show-Line "Found $countText" -Class $mappingClass -FindingId 'ESC14_WEAK_EXPLICIT_MAPPING'
            if ($noTrustAnchor) { Show-NoTrustAnchorNote }

            # Privileged targets first: those are the ones worth the reader's attention.
            foreach ($finding in ($weakFindings | Sort-Object -Property @{Expression = { -not $_.IsPrivileged }})) {
                Show-Object $finding.Object -Class $mappingClass
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
        # Its own header. The two halves answer different questions - what is mapped today,
        # and who could map something tomorrow - and under one header the secure verdict of
        # the first read as a verdict on ESC14 as a whole, with the findings of the second
        # contradicting it on the next line.
        Show-SubHeader "Checking write access to altSecurityIdentities on privileged accounts..." -ObjectType "WeakCertificateMapping"

        $writableFindings = @()
        $exchangeOnlyFindings = @()
        try {
            # One query for every privileged principal and its security descriptor, rather
            # than Get-ObjectACL per account: that helper reads the object it is given, so
            # a loop over it costs one LDAP round trip per privileged account, and
            # adminCount is a sticky flag - it stays set after the account leaves the group,
            # so the list is longer than the domain's actual administrators. -Raw keeps
            # nTSecurityDescriptor as the bytes ConvertFrom-SecurityDescriptor takes.
            #
            # Over every principal that can authenticate, not over users alone. Domain
            # Controllers is an AdminSDHolder-protected group, so a DC computer account
            # carries adminCount=1 - and a write to altSecurityIdentities on a domain
            # controller is DC impersonation by certificate, the most valuable target this
            # check has. Get-DomainUser filters
            # (objectCategory=person)(objectClass=user)(!(objectClass=computer)), so every
            # computer account and every managed service account fell out of the query, and
            # the section closed with "No non-privileged principal can write
            # altSecurityIdentities on a privileged account".
            $privilegedFilter = '(&(adminCount=1)(|(objectCategory=person)(objectCategory=computer)' +
                                '(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount)))'
            $privilegedTargets = @(Get-DomainObject -LDAPFilter $privilegedFilter `
                -Properties 'distinguishedName', 'sAMAccountName', 'nTSecurityDescriptor' -Raw @connectionParams)

            # One schema lookup for the whole check: which property set contains the
            # attribute, so a delegation that names the set instead of the attribute is
            # recognised as what it is.
            $altSecPropertySet = Get-AltSecurityIdentitiesPropertySet -CredParams $connectionParams
            if ($altSecPropertySet) {
                Write-Log "[Get-WeakCertificateMapping] altSecurityIdentities belongs to property set $altSecPropertySet"
            } elseif (@($privilegedTargets).Count -gt 0) {
                Show-Line "The property set containing altSecurityIdentities could not be read - a delegation naming the set is not examined" -Class Note
            }
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
                $exchangeWriters = @()
                # The same trustee reaches an object through several ACEs - one written
                # here, one inherited from the OU, one from the domain root - and each
                # arrives separately. Listing "Exchange Trusted Subsystem: GenericAll"
                # three times says nothing the first line did not.
                $seenWriters = @{}
                foreach ($ace in @($descriptor.ACEs)) {
                    if (-not $ace) { continue }
                    # ConvertFrom-SecurityDescriptor names these Type and SID.
                    if ($ace.Type -ne 'Allow') { continue }
                    if (-not (Test-AltSecurityIdentitiesWrite -Ace $ace -PropertySetGUID $altSecPropertySet)) { continue }

                    $trusteeSID = [string]$ace.SID
                    if ([string]::IsNullOrWhiteSpace($trusteeSID)) { continue }

                    # Same two defects as above, and here they decided the whole section:
                    # [bool] of the returned object is always $true, so every trustee looked
                    # privileged and the continue below dropped all of them - this half of
                    # ESC14 reported nothing at all. With a connection splat it threw
                    # instead, the empty catch left $false, and SYSTEM and Domain Admins
                    # were reported as non-privileged writers.
                    $trusteePrivileged = $false
                    try {
                        $trusteePrivileged = ((Test-IsPrivileged -Identity $trusteeSID).IsPrivileged -eq $true)
                    } catch {
                        Write-Log "[Get-WeakCertificateMapping] Privilege check failed for trustee '$trusteeSID': $_"
                    }

                    # A trustee that is already privileged holds nothing it did not have.
                    if ($trusteePrivileged) { continue }

                    $trusteeName = if ($ace.Name) { $ace.Name } else { ConvertFrom-SID -SID $trusteeSID }
                    $entry = "${trusteeName}: $($ace.Rights)"
                    if ($seenWriters.ContainsKey($entry)) { continue }
                    $seenWriters[$entry] = $true

                    # Exchange service groups are kept apart rather than filtered out. The
                    # rights are real, and Exchange Trusted Subsystem holding GenericAll on
                    # a user object is a documented escalation path - but the Exchange setup
                    # writes that ACL on every privileged account in the domain at once, so
                    # reporting each one as an ESC14 delegation buries the account that
                    # carries a real one. The reader gets both lists, in different colours.
                    $trusteeIsExchange = $false
                    try {
                        $trusteeIsExchange = [bool](Test-IsExchangeServiceGroup -Identity $trusteeSID).IsExchangeService
                    } catch {
                        Write-Log "[Get-WeakCertificateMapping] Exchange check failed for trustee '$trusteeSID': $_"
                    }

                    if ($trusteeIsExchange) { $exchangeWriters += $entry } else { $writers += $entry }
                }

                # The owner holds WriteDacl implicitly: whatever the ACEs say, it can give
                # itself the write and then take the grant away again. Only the ACEs were
                # read here, so an account whose owner had been reassigned - the case
                # Get-NonDefaultUserOwners reports without ever connecting it to ESC14 -
                # produced no finding in this section.
                $ownerSID = ''
                if ($descriptor.Owner) { $ownerSID = [string]$descriptor.Owner.SID }
                if ($ownerSID) {
                    $ownerPrivileged = $false
                    try {
                        $ownerPrivileged = ((Test-IsPrivileged -Identity $ownerSID).IsPrivileged -eq $true)
                    } catch {
                        Write-Log "[Get-WeakCertificateMapping] Privilege check failed for owner '$ownerSID': $_"
                    }

                    if (-not $ownerPrivileged) {
                        $ownerName = if ($descriptor.Owner.Name) { $descriptor.Owner.Name } else { ConvertFrom-SID -SID $ownerSID }
                        $ownerEntry = "${ownerName}: Owner - may rewrite the DACL and grant itself the write"
                        if (-not $seenWriters.ContainsKey($ownerEntry)) {
                            $seenWriters[$ownerEntry] = $true
                            $ownerIsExchange = $false
                            try {
                                $ownerIsExchange = [bool](Test-IsExchangeServiceGroup -Identity $ownerSID).IsExchangeService
                            } catch {
                                Write-Log "[Get-WeakCertificateMapping] Exchange check failed for owner '$ownerSID': $_"
                            }
                            if ($ownerIsExchange) { $exchangeWriters += $ownerEntry } else { $writers += $ownerEntry }
                        }
                    }
                }

                if (@($writers).Count -eq 0 -and @($exchangeWriters).Count -eq 0) { continue }

                # Second phase again: the full object, only for an account that is actually
                # reported.
                # Get-DomainObject, not Get-DomainUser: the targets include computer
                # accounts and managed service accounts now, and a user query answers
                # nothing for those - the row would fall back to the three properties the
                # raw search asked for, with the descriptor bytes among them.
                $displayObject = $null
                try {
                    $displayObject = @(Get-DomainObject -Identity $target.distinguishedName @connectionParams)[0]
                } catch {
                    Write-Log "[Get-WeakCertificateMapping] Could not re-read '$($target.distinguishedName)': $_"
                }
                if (-not $displayObject) {
                    # The raw result as a last resort, without the binary descriptor: it
                    # renders as a wall of bytes and says nothing a reader can use.
                    $displayObject = $target
                    if ($displayObject.PSObject.Properties['nTSecurityDescriptor']) {
                        $displayObject.PSObject.Properties.Remove('nTSecurityDescriptor')
                    }
                }

                # Two attributes rather than one list, because the render pipeline colours
                # by attribute name: the delegated writers stay red, the Exchange ones go
                # yellow, and an account that carries both shows both rows.
                if (@($writers).Count -gt 0) {
                    $displayObject | Add-Member -NotePropertyName 'altSecurityIdentitiesWriters' -NotePropertyValue @($writers) -Force
                }
                if (@($exchangeWriters).Count -gt 0) {
                    $displayObject | Add-Member -NotePropertyName 'exchangeServiceWriters' -NotePropertyValue @($exchangeWriters) -Force
                }
                $displayObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'WeakCertificateMapping' -Force

                if (@($writers).Count -gt 0) {
                    $writableFindings += $displayObject
                } else {
                    $exchangeOnlyFindings += $displayObject
                }
            }
        }
        catch {
            Write-Log "[Get-WeakCertificateMapping] Write-access analysis failed: $_" -Level Warning
        }

        if (@($writableFindings).Count -gt 0) {
            # Same dampening as above, and for the same reason: the mapping an attacker
            # would add still needs an issuer the domain accepts.
            Show-Line "Found $(@($writableFindings).Count) privileged principal(s) whose altSecurityIdentities a non-privileged principal may write" -Class $mappingClass -FindingId 'ESC14_WRITABLE_MAPPING'
            if ($noTrustAnchor) { Show-NoTrustAnchorNote }
            foreach ($finding in $writableFindings) {
                Show-Object $finding -Class $mappingClass
            }
        }

        if (@($exchangeOnlyFindings).Count -gt 0) {
            # Held back by default, the way Get-DangerousACLs holds back an Exchange
            # service group: the ACL is written by Exchange setup and cannot be removed
            # without breaking Exchange. Not in silence though - one short line says how
            # many there are, so a reader who has not met the switch can still learn that
            # Exchange reaches these accounts.
            if ($IncludePrivileged) {
                Show-Line "$(@($exchangeOnlyFindings).Count) privileged account(s) writable only by Exchange service groups (by design):" -Class Hint
                foreach ($finding in $exchangeOnlyFindings) {
                    Show-Object $finding -Class Hint
                }
            } else {
                Show-Line "$(@($exchangeOnlyFindings).Count) privileged account(s) writable only by Exchange service groups (by design) - use -IncludePrivileged" -Class Note
            }
        }

        # Only the real findings decide this. The Exchange ACL is by design and holds no
        # non-privileged principal, so counting it here meant the green verdict - which is
        # exactly what this line claims - could never be printed in a domain with Exchange.
        if (@($writableFindings).Count -eq 0) {
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
<#
.SYNOPSIS
    Says why an ESC14 finding was reported as a hint rather than a vulnerability.
.DESCRIPTION
    Printed under a finding when this directory publishes no certificate issuer trusted
    for authentication. Two sentences, because both halves matter: the mapping cannot be
    used today, and that is not the same as it being harmless.

    The wording stops short of "not exploitable". The Enterprise NTAuth store is a machine
    store as well as a directory object: certutil -enterprise -addstore NTAuth writes an
    issuer onto one machine without publishing it, and an issuer added that way on a domain
    controller is invisible from here. So this is a reason to go and look, not a clean bill
    of health. Nor is it durable - publishing an issuer tomorrow makes every one of these
    mappings live without anyone touching an account.
.OUTPUTS
    None. Writes one Note line.
#>
function Show-NoTrustAnchorNote {
    [CmdletBinding()]
    param()

    Show-Line ("No issuer is published in the NTAuth store, so no certificate can " +
               "currently authenticate against these mappings - neither through PKINIT " +
               "nor through Schannel. Check the domain controllers' own NTAuth store " +
               "with 'certutil -viewstore -enterprise NTAuth' before ruling it out, " +
               "because an issuer can be added there without being published, and treat " +
               "the mappings as live again the moment one is.") -Class Note
}

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
        $Ace,

        # The property set that contains altSecurityIdentities, read from the schema by the
        # caller. Empty means it could not be read, and then the question is simply not
        # asked - a guessed GUID would be a verdict about an attribute nobody looked up.
        [Parameter(Mandatory = $false)]
        [string]$PropertySetGUID
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

    # Or a WriteProperty ACE that names the property set the attribute belongs to. That is
    # the shape the "helpdesk may maintain user attributes" delegation takes, and it was
    # the one way in that this test did not cover: an attacker who holds it writes
    # altSecurityIdentities on a Tier-0 account while the section printed its green line.
    #
    # The set is resolved from the schema by the caller rather than hardcoded here. The
    # usual answer is Public-Information, but attributeSecurityGUID is what the DC
    # enforces, and a schema extension can move an attribute into another set.
    if ($PropertySetGUID -and $objectType -match ('(?i)' + [regex]::Escape($PropertySetGUID))) { return $true }

    return $false
}

<#
.SYNOPSIS
    Reads the property set that altSecurityIdentities belongs to out of the schema.

.DESCRIPTION
    An ACE granting WriteProperty on a property set grants it on every attribute in that
    set, so a delegation naming the set is a write to altSecurityIdentities without ever
    naming the attribute. Which set contains it is a schema fact, readable from
    attributeSecurityGUID on the attributeSchema object.

    Asked once per run, and $null when the schema cannot be read - which leaves that one
    way of holding the write unexamined rather than guessing at a GUID.

.OUTPUTS
    [string] GUID in registry form without braces, or $null.
#>
function Get-AltSecurityIdentitiesPropertySet {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$CredParams = @{}
    )

    $schemaDN = [string]$Script:LDAPContext.SchemaNamingContext
    if ([string]::IsNullOrWhiteSpace($schemaDN)) { return $null }

    try {
        $attributeFilter = '(&(objectClass=attributeSchema)(lDAPDisplayName=altSecurityIdentities))'
        $attribute = @(Get-DomainObject -LDAPFilter $attributeFilter -SearchBase $schemaDN `
            -Properties 'attributeSecurityGUID' -ResultLimit 1 @CredParams)[0]
        if (-not $attribute) { return $null }

        $raw = $attribute.attributeSecurityGUID
        if (-not $raw) { return $null }

        # Either the raw octet string or an already converted value, depending on whether
        # the caller asked for -Raw.
        if ($raw -is [byte[]]) {
            if (@($raw).Count -ne 16) { return $null }
            return (New-Object System.Guid -ArgumentList (,[byte[]]$raw)).ToString()
        }
        return ([string]$raw).Trim('{', '}')
    } catch {
        Write-Log "[Get-AltSecurityIdentitiesPropertySet] Schema lookup failed: $_"
        return $null
    }
}
