function Get-TrustSIDFilteringVerdict {
    <#
    .SYNOPSIS
    Decides whether a trust lets SID history from the other side reach this domain.

    .DESCRIPTION
    The single most consequential thing a trust can be misconfigured for. Without SID
    filtering, a principal in the trusted domain can carry a SID from this domain in its
    token - Domain Admins, say - and this domain will honour it. Whoever owns the other
    side owns this one.

    Three things decide it, and all three are already on the trust object.

    Direction. trustDirection 2 is outbound, which means this domain trusts the partner and
    the partner's principals authenticate here (MS-ADTS 6.1.6.7.12). That is the direction
    the risk runs in. A purely inbound trust means the partner trusts us, and its exposure
    is theirs rather than ours. The names invite the opposite reading, which is exactly why
    it is written out here.

    Where the forest boundary is. WITHIN_FOREST means the trust is between two domains of
    one forest, and a forest is a single security boundary by design - there is no SID
    filtering between its domains and its absence is not a misconfiguration.

    Which filter applies. An external trust is quarantined by default, and QUARANTINED_DOMAIN
    is the bit that says so; its absence on an external trust means filtering was turned off.
    A forest trust filters differently - it accepts SIDs from the trusted forest and rejects
    the rest, and QUARANTINED_DOMAIN is normally not set on one. TREAT_AS_EXTERNAL is what
    weakens it: the forest trust is then treated as external for SID filtering, so SIDs from
    any domain of the trusted forest are accepted rather than only its own.

    .PARAMETER Direction
    The decoded trustDirection: Inbound, Outbound, Bidirectional or Disabled.

    .PARAMETER AttributeFlag
    The decoded trustAttributes flags.

    .OUTPUTS
    Hashtable with Status, Risk and Severity. Risk is $null when there is nothing to say.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [string]$Direction,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [string[]]$AttributeFlag
    )

    $flags = @($AttributeFlag)
    $withinForest = ($flags -contains 'WITHIN_FOREST')
    $forestTrust  = ($flags -contains 'FOREST_TRANSITIVE')
    $quarantined  = ($flags -contains 'QUARANTINED_DOMAIN')
    $asExternal   = ($flags -contains 'TREAT_AS_EXTERNAL')

    # Only a trust this domain extends can be abused against this domain.
    $weTrustThem = ($Direction -eq 'Outbound' -or $Direction -eq 'Bidirectional')

    if ($withinForest) {
        return @{
            Status   = 'Not applicable - both domains are in one forest, which is a single security boundary'
            Risk     = $null
            Severity = 'Note'
        }
    }

    if (-not $weTrustThem) {
        return @{
            Status   = "Not applicable - this domain does not trust the partner (direction: $Direction)"
            Risk     = $null
            Severity = 'Note'
        }
    }

    if ($forestTrust) {
        if ($asExternal) {
            return @{
                Status   = 'Weakened - TREAT_AS_EXTERNAL downgrades the forest trust to external filtering'
                Risk     = 'This domain trusts the partner forest and TREAT_AS_EXTERNAL is set, so SID history naming any domain of that forest is honoured here. A Domain Admin SID of this domain injected on the other side is accepted.'
                Severity = 'Finding'
            }
        }
        return @{
            Status   = 'Enabled - a forest trust filters SIDs from outside the trusted forest by default'
            Risk     = $null
            Severity = 'Note'
        }
    }

    # An external or realm trust. Quarantine is the default and its absence is the finding.
    if (-not $quarantined) {
        return @{
            Status   = 'DISABLED - QUARANTINED_DOMAIN is not set on an external trust'
            Risk     = 'This domain trusts the partner and SID filtering is off, so a principal there can carry a SID of this domain in its token and this domain will honour it. Whoever controls the trusted domain controls this one.'
            Severity = 'Finding'
        }
    }

    return @{
        Status   = 'Enabled - QUARANTINED_DOMAIN is set'
        Risk     = $null
        Severity = 'Note'
    }
}

function Get-DomainTrusts {
    <#
    .SYNOPSIS
    Enumerates domain trusts and reports the ones that let SID history reach this domain.

    .DESCRIPTION
    Collects every trust relationship - direction, type and the decoded trustAttributes -
    and then answers the question the attributes exist for: does this trust let a principal
    on the other side carry a SID of this domain in its token?

    Without SID filtering it does, and whoever owns the trusted domain owns this one. The
    verdict combines three things, none of which is a finding on its own:

    - Direction. trustDirection 2 is outbound, which means THIS domain trusts the partner
      and the partner's principals authenticate here. That is the direction the risk runs
      in; a purely inbound trust is the partner's exposure, not ours.
    - The forest boundary. WITHIN_FOREST means one forest, which is a single security
      boundary by design - no filtering between its domains, and that is not a defect.
    - Which filter applies. An external trust carries QUARANTINED_DOMAIN by default and its
      absence means filtering was switched off. A forest trust filters differently, and
      TREAT_AS_EXTERNAL is what weakens it to external semantics.

    Also reported: the encryption types Kerberos may use across each trust, read from
    msDS-SupportedEncryptionTypes on the trust object - a trust without it supports RC4 and
    no AES - and a hint where no AES is among them; the domain SID of the partner; and on a
    trust the partner extends to this domain, when the password of its interdomain trust
    account <flatName>$ was last changed - the trusting domain does that about every 30
    days, so 90 days or more is a hint.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-DomainTrusts

    .EXAMPLE
    Get-DomainTrusts -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Domain
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-DomainTrusts] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Searching for domain trusts..." -ObjectType "DomainTrust"

            $trustsRaw = Get-DomainObject -LDAPFilter "(objectClass=trustedDomain)" @PSBoundParameters

            # Filter out self-referencing trust objects (e.g. child domain's trust back to us
            # returned as phantom object from GC, or trust object where trustPartner = own domain)
            #
            # The key is Domain. DomainDNS is written nowhere in the project, so this read
            # answered $null and the comparison below was "trustPartner -ne $null" - true
            # for every trust object there is. The filter has never removed anything.
            $domainDNS = $Script:LDAPContext.Domain
            $trusts = @($trustsRaw) | Where-Object {
                $_.trustPartner -and $_.trustPartner -ne $domainDNS
            }

            if (@($trusts).Count -gt 0) {
                Show-Line "Found $(@($trusts).Count) domain trust(s):" -Class Hint

                # The interdomain trust accounts. A trust with direction Inbound or
                # Bidirectional has a user account <flatName>$ in the users container of
                # this domain (MS-ADTS 6.1.6.8), and the trusting domain changes its password
                # about every 30 days. One query for all of them, and only where a trust can
                # have one; $null when the read failed.
                $staleTrustPasswordDays = 90
                $trustAccounts = @{}
                if (@($trusts | Where-Object { $_.trustDirection -in @('Inbound', 'Bidirectional') }).Count -gt 0) {
                    try {
                        foreach ($account in @(Get-DomainObject -LDAPFilter '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2048))' @PSBoundParameters)) {
                            if ($account -and $account.sAMAccountName) { $trustAccounts[[string]$account.sAMAccountName] = $account }
                        }
                    } catch {
                        Write-Log "[Get-DomainTrusts] Could not read the interdomain trust accounts: $_"
                        $trustAccounts = $null
                    }
                }

                $riskyTrusts = 0
                $weakKeyTrusts = 0
                $staleTrusts = 0
                foreach ($trust in $trusts) {
                    # trustDirection, trustType and trustAttributes are already decoded
                    # by Invoke-LDAPSearch into readable strings/arrays
                    $direction = $trust.trustDirection
                    $type = $trust.trustType
                    $attrFlags = @($trust.trustAttributes)

                    # Derive boolean flags from decoded trustAttributes array
                    $isBidirectional = ($direction -eq 'Bidirectional')
                    $isTransitive = ($attrFlags -notcontains 'NON_TRANSITIVE')
                    $isQuarantined = ($attrFlags -contains 'QUARANTINED_DOMAIN')
                    $isForestTrust = ($attrFlags -contains 'FOREST_TRANSITIVE')
                    $isCrossOrg = ($attrFlags -contains 'CROSS_ORGANIZATION')
                    $isWithinForest = ($attrFlags -contains 'WITHIN_FOREST')
                    $isTreatAsExternal = ($attrFlags -contains 'TREAT_AS_EXTERNAL')
                    $usesRC4 = ($attrFlags -contains 'USES_RC4_ENCRYPTION')

                    # Create enhanced trust object for Show-Object
                    # No distinguishedName - custom objects without standard AD attributes
                    # use the dynamic fallback in Get-RenderModel for console output
                    $trustObject = [PSCustomObject]@{
                        trustPartner = $trust.trustPartner
                        flatName = $trust.flatName
                        trustDirection = $direction
                        trustType = $type
                        trustAttributes = $attrFlags
                        isBidirectional = $isBidirectional
                        isTransitive = $isTransitive
                        isForestTrust = $isForestTrust
                        isWithinForest = $isWithinForest
                        isQuarantined = $isQuarantined
                        isCrossOrg = $isCrossOrg
                        isTreatAsExternal = $isTreatAsExternal
                        usesRC4 = $usesRC4
                        whenCreated = $trust.whenCreated
                    }

                    # The verdict the attributes above exist for. Collected and never drawn
                    # until now: every trust went out as a flat list of flags, and the one
                    # combination that matters was left for the reader to spot.
                    $verdict = Get-TrustSIDFilteringVerdict -Direction $direction -AttributeFlag $attrFlags
                    $trustObject | Add-Member -NotePropertyName 'sidFiltering' -NotePropertyValue $verdict.Status -Force
                    if ($verdict.Risk) {
                        $riskyTrusts++
                        $trustObject | Add-Member -NotePropertyName 'trustRisk' -NotePropertyValue $verdict.Risk -Force
                    }

                    # The domain SID of the partner - the SIDs SID filtering keeps out or lets
                    # in begin with it.
                    if ($trust.securityIdentifier) {
                        $trustObject | Add-Member -NotePropertyName 'partnerDomainSID' -NotePropertyValue ([string]$trust.securityIdentifier) -Force
                    }

                    # The password of the inbound side, on its interdomain trust account. A
                    # password the trusting domain no longer changes keeps a trust key that
                    # was extracted once working for as long as it stays.
                    $passwordStale = $false
                    if ($direction -in @('Inbound', 'Bidirectional') -and $trust.flatName) {
                        $accountName = "$($trust.flatName)`$"
                        $lastSetText = $null
                        if ($null -eq $trustAccounts) {
                            $lastSetText = 'Unknown - the interdomain trust accounts could not be read'
                        } elseif (-not $trustAccounts.ContainsKey($accountName)) {
                            $lastSetText = "Unknown - no interdomain trust account $accountName was found in this domain"
                        } else {
                            $pwdLastSet = $trustAccounts[$accountName].pwdLastSet
                            if ($pwdLastSet -is [DateTime]) {
                                $ageDays = [int][Math]::Floor(((Get-Date) - $pwdLastSet).TotalDays)
                                $lastSetText = "$(Format-adPEASDate $pwdLastSet 'yyyy-MM-dd') ($ageDays days ago, on $accountName)"
                                if ($ageDays -ge $staleTrustPasswordDays) {
                                    $passwordStale = $true
                                    $trustObject | Add-Member -NotePropertyName 'trustPasswordRotation' `
                                        -NotePropertyValue "Stale - not changed for $ageDays days; the trusting domain changes it about every 30 days" -Force
                                }
                            } else {
                                $lastSetText = "Never - $accountName has no password change recorded"
                            }
                        }
                        $trustObject | Add-Member -NotePropertyName 'trustPasswordLastSet' -NotePropertyValue $lastSetText -Force
                    }

                    # The encryption types of Kerberos across the trust. A referral ticket
                    # across a trust is encrypted with the trust key, in a type the trust
                    # object allows: msDS-SupportedEncryptionTypes on it, which the checkbox
                    # "The other domain supports Kerberos AES Encryption" and ksetup
                    # /setenctypeattr set. Without it a trust supports RC4 and no AES
                    # (KB4492348), and the 2026 change that made AES the default for
                    # accounts leaves trusts alone - "The Kerberos Trust and referral flow
                    # ... is unaffected" (CVE-2026-20833). A downlevel (NT4) trust carries
                    # no Kerberos and gets no row. The -SK bit asks for AES session keys
                    # and is no type of the key.
                    #
                    # RC4 is weaker than AES, and on a realm trust to MIT Kerberos the trust
                    # password is one an administrator typed - but it is not on its own a
                    # way in, so it stays a hint.
                    #
                    # The verdict has no row of its own. trustEncryptionTypes is coloured by
                    # the TRUST_USES_RC4 trigger wherever it names no AES, and that card is
                    # the explanation - the HTML tooltip of the value. A sentence row said
                    # it again on the console, two rows under the value it explained.
                    $isAdTrust = ("$type" -eq 'Active Directory')
                    $isMitTrust = ("$type" -eq 'MIT Kerberos Realm')
                    $encTypeProp = $trust.PSObject.Properties['msDS-SupportedEncryptionTypes']
                    $keyTypes = @()
                    if ($encTypeProp -and $null -ne $encTypeProp.Value) {
                        $keyTypes = @(@($encTypeProp.Value) | ForEach-Object { ([string]$_).Trim() } | Where-Object {
                            ($_ -like 'RC4*' -or $_ -like 'AES*' -or $_ -like 'DES*') -and $_ -notlike '*-SK'
                        })
                    }
                    $hasAES = (@($keyTypes | Where-Object { $_ -like 'AES*' }).Count -gt 0)

                    $keyWeakness = $false
                    if ($isAdTrust -or ($isMitTrust -and $keyTypes.Count -gt 0)) {
                        if ($keyTypes.Count -eq 0) {
                            $trustObject | Add-Member -NotePropertyName 'trustEncryptionTypes' -NotePropertyValue 'Not set' -Force
                            $keyWeakness = $true
                        } else {
                            # Without AES the key is RC4, or DES, which Windows has refused
                            # by default since Windows 7 and Server 2008 R2.
                            $trustObject | Add-Member -NotePropertyName 'trustEncryptionTypes' -NotePropertyValue ($keyTypes -join ', ') -Force
                            $keyWeakness = (-not $hasAES)
                        }
                    } elseif ($isMitTrust -and $usesRC4) {
                        # No msDS-SupportedEncryptionTypes on a realm trust: the attribute
                        # bit is what MS-ADTS defines for it.
                        $trustObject | Add-Member -NotePropertyName 'trustEncryptionTypes' -NotePropertyValue 'RC4' -Force
                        $keyWeakness = $true
                    }
                    # MS-ADTS defines TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION for an MIT realm
                    # trust; on any other trust it is left over and says nothing about the
                    # key. trustAttributes still names it, and the card says what it means.

                    # The class of the object: the SID filtering verdict, raised to a hint
                    # by a key without AES or a password that is no longer changed.
                    $objectClass = $verdict.Severity
                    if ($keyWeakness) { $weakKeyTrusts++ }
                    if ($passwordStale) { $staleTrusts++ }
                    if (($keyWeakness -or $passwordStale) -and $objectClass -ne 'Finding') { $objectClass = 'Hint' }

                    $trustObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'DomainTrust' -Force
                    Show-Object $trustObject -Class $objectClass

                }

                if ($riskyTrusts -gt 0) {
                    Show-Line "$riskyTrusts of them let SID history from the other side reach this domain - whoever controls that domain controls this one" -Class Finding
                } else {
                    Show-Line "No trust lets SID history from another domain reach this one" -Class Secure
                }
                if ($weakKeyTrusts -gt 0) {
                    Show-Line "$weakKeyTrusts of them allow no AES for Kerberos across the trust" -Class Hint -FindingId 'TRUST_USES_RC4'
                }
                if ($staleTrusts -gt 0) {
                    Show-Line "$staleTrusts of them have a trust password that has not changed for $staleTrustPasswordDays days or more" -Class Hint -FindingId 'TRUST_PASSWORD_STALE'
                }
            }

            if (@($trusts).Count -eq 0) {
                Show-Line "No external domain trusts found (isolated domain)" -Class Note
            }

        } catch {
            Write-Log "[Get-DomainTrusts] Error: $_" -Level Error
            Show-Line "Error during check - domain trusts could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-DomainTrusts] Check completed"
    }
}
