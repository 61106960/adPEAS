function Get-RODCPasswordReplication {
    <#
    .SYNOPSIS
    Checks which privileged accounts a read-only Domain Controller may cache the password of,
    and who administers it.

    .DESCRIPTION
    A read-only Domain Controller holds no secrets of its own choosing. Its password
    replication policy decides which accounts it may cache: msDS-RevealOnDemandGroup on its
    computer object lists who is allowed, msDS-NeverRevealGroup who is denied, and deny
    wins. By default the deny list holds the Denied RODC Password Replication Group -
    Domain Admins, Enterprise Admins, Schema Admins and the other Tier-0 groups - and
    Administrators, Account Operators, Server Operators and Backup Operators. An RODC stands
    where physical security is weakest, so a privileged account whose password it may cache
    is exposed to whoever takes the server.

    For every privileged account - Get-PrivilegedAccountFilter with the operators,
    confirmed by Test-IsPrivileged - the check builds the groups of its token: the
    recursive membership, and the primary group with its own nesting, which leaves no
    member link. These are compared with each RODC's allow and deny list. The check also
    reads msDS-RevealedUsers, the accounts whose secrets the RODC has already received.

    A read-only Domain Controller has an administrator of its own as well. The principal
    named in managedBy on its computer object is an implicit member of its Administrators
    group - of that server's and of no other (MS-ADTS 6.1.1.3.2). That is the delegated
    administrator of a branch office, and administrator on the server holds every secret it
    has cached and the keys of its krbtgt account. The check reports a principal outside
    Tier-0 named there, a broad group as such, and every principal outside Tier-0 that may
    write managedBy and so make itself the administrator: the owner, full control, a write
    of every property or of managedBy itself, WriteDacl and WriteOwner.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-RODCPasswordReplication

    .EXAMPLE
    Get-RODCPasswordReplication -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Accounts
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
        Write-Log "[Get-RODCPasswordReplication] Starting check"
    }

    process {
        try {
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Checking the password replication policy and the administrators of read-only Domain Controllers..." -ObjectType "RODCPasswordReplication"

            # The Domain Controller definition lives in Get-DomainComputer; a read-only one is
            # the one with PARTIAL_SECRETS_ACCOUNT.
            $rodcs = @(Get-DomainComputer -DomainController @PSBoundParameters | Test-AccountActivity -IsEnabled |
                Where-Object { @($_.userAccountControl) -contains 'PARTIAL_SECRETS_ACCOUNT' })
            if ($rodcs.Count -eq 0) {
                Show-Line "No read-only Domain Controller in this domain - there is no password replication policy to check" -Class Note
                return
            }

            # The privileged accounts, each with the SIDs of its token.
            $privilegedFilter = Get-PrivilegedAccountFilter -IncludeOperators @PSBoundParameters
            $accountProperties = @('sAMAccountName', 'objectSid', 'distinguishedName', 'primaryGroupID')
            $candidates = @(Get-DomainUser -Enabled -LDAPFilter $privilegedFilter -Properties $accountProperties @PSBoundParameters)
            $candidates += @(Get-DomainUser -GMSA -Enabled -LDAPFilter $privilegedFilter -Properties $accountProperties @PSBoundParameters)

            $privileged = @()
            foreach ($candidate in $candidates) {
                if (-not (Test-IsPrivileged -Identity $candidate -IncludeOperators).IsPrivileged) { continue }

                $sid = [string]$candidate.objectSid
                $tokenSIDs = @($sid) + @(Get-RecursiveGroupMembership -IdentitySID $sid -IdentityDN ([string]$candidate.distinguishedName))
                # The primary group is in the token without a member link, so the recursive
                # membership does not return it; its RID is relative to the account's domain.
                if ($candidate.primaryGroupID -and $sid -match '^(S-1-5-21-\d+-\d+-\d+)-\d+$') {
                    $primaryGroupSID = "$($Matches[1])-$($candidate.primaryGroupID)"
                    $tokenSIDs += @($primaryGroupSID) + @(Get-RecursiveGroupMembership -IdentitySID $primaryGroupSID)
                }

                $privileged += [PSCustomObject]@{
                    Name              = [string]$candidate.sAMAccountName
                    DistinguishedName = [string]$candidate.distinguishedName
                    TokenSIDs         = $tokenSIDs
                }
            }

            # The allow and deny lists and managedBy hold DNs; the token holds SIDs. Every
            # DN once, with the name the managedBy line shows.
            $sidByDN = @{}
            $nameByDN = @{}
            foreach ($rodc in $rodcs) {
                foreach ($dn in (@($rodc.'msDS-RevealOnDemandGroup') + @($rodc.'msDS-NeverRevealGroup') + @($rodc.managedBy))) {
                    if (-not $dn -or $sidByDN.ContainsKey([string]$dn)) { continue }
                    $listed = @(Get-DomainObject -Identity ([string]$dn) -Properties 'objectSid', 'sAMAccountName' @PSBoundParameters)[0]
                    $sidByDN[[string]$dn] = if ($listed -and $listed.objectSid) { [string]$listed.objectSid } else { $null }
                    $nameByDN[[string]$dn] = if ($listed -and $listed.sAMAccountName) { [string]$listed.sAMAccountName } else { $null }
                }
            }

            $deniedGroupSID = "$($Script:LDAPContext.DomainSID)-572"

            foreach ($rodc in $rodcs) {
                $rodcName = ([string]$rodc.sAMAccountName).TrimEnd('$')

                $allowed = @{}
                foreach ($dn in @($rodc.'msDS-RevealOnDemandGroup')) {
                    if ($dn -and $sidByDN[[string]$dn]) { $allowed[$sidByDN[[string]$dn]] = $true }
                }
                $denied = @{}
                $unresolvedDenied = 0
                foreach ($dn in @($rodc.'msDS-NeverRevealGroup')) {
                    if (-not $dn) { continue }
                    if ($sidByDN[[string]$dn]) { $denied[$sidByDN[[string]$dn]] = $true } else { $unresolvedDenied++ }
                }

                $exposedNames = @()
                foreach ($account in $privileged) {
                    $isAllowed = @($account.TokenSIDs | Where-Object { $allowed.ContainsKey($_) }).Count -gt 0
                    $isDenied  = @($account.TokenSIDs | Where-Object { $denied.ContainsKey($_) }).Count -gt 0
                    if ($isAllowed -and -not $isDenied) { $exposedNames += $account.Name }
                }

                # msDS-RevealedUsers is DN-Binary, one value per secret attribute received:
                # B:<length>:<hex>:<DN>.
                $revealedDNs = @{}
                foreach ($value in @($rodc.'msDS-RevealedUsers')) {
                    if ("$value" -match '^B:\d+:[0-9A-Fa-f]*:(.+)$') { $revealedDNs[$Matches[1]] = $true }
                }
                $revealedNames = @($privileged | Where-Object { $revealedDNs.ContainsKey($_.DistinguishedName) } | ForEach-Object { $_.Name })

                $issues = 0
                if ($exposedNames.Count -gt 0) {
                    $issues++
                    Show-Line "$rodcName - $($exposedNames.Count) privileged account(s) may have their password cached, allowed and not denied by its password replication policy: $(Format-RODCAccountList $exposedNames)" -Class Finding -FindingId 'RODC_PRIVILEGED_PASSWORD_ALLOWED'
                }
                if ($revealedNames.Count -gt 0) {
                    $issues++
                    Show-Line "$rodcName - the secrets of $($revealedNames.Count) privileged account(s) are cached on it already: $(Format-RODCAccountList $revealedNames)" -Class Finding -FindingId 'RODC_PRIVILEGED_PASSWORD_REVEALED'
                }
                if (-not $denied.ContainsKey($deniedGroupSID)) {
                    $issues++
                    Show-Line "$rodcName - the Denied RODC Password Replication Group is not on its deny list" -Class Hint -FindingId 'RODC_DENIED_GROUP_MISSING'
                }
                if ($unresolvedDenied -gt 0) {
                    $issues++
                    Show-Line "$rodcName - $unresolvedDenied member(s) of its deny list could not be resolved and were not counted" -Class Note
                }

                # Who administers it. The principal in managedBy is an implicit member of
                # this server's Administrators group (MS-ADTS 6.1.1.3.2) - the delegated
                # administrator a promotion or a pre-created RODC account names. Tier-0 is
                # administrator on every Domain Controller already; anyone else gains it here.
                $managedByDN = [string]$rodc.managedBy
                if ($managedByDN) {
                    $adminSID = $sidByDN[$managedByDN]
                    if (-not $adminSID) {
                        $issues++
                        Show-Line "$rodcName - its managedBy could not be resolved, so its administrator was not checked: $managedByDN" -Class Note
                    } else {
                        $adminName = $nameByDN[$managedByDN]
                        # A foreign security principal - Authenticated Users, for one - has
                        # no sAMAccountName, only its SID.
                        if (-not $adminName) { $adminName = ConvertFrom-SID -SID $adminSID }
                        if (Test-IsBroadTrustee -SID $adminSID) {
                            $issues++
                            Show-Line "$rodcName - managedBy makes $adminName, a broad group, an administrator of it" -Class Finding -FindingId 'RODC_ADMIN_BROAD_GROUP'
                        } elseif ((Test-IsPrivileged -Identity $adminSID).Category -ne 'Privileged') {
                            # An operator group counts: it is not administrator on a Domain
                            # Controller by default.
                            $issues++
                            Show-Line "$rodcName - managedBy makes $adminName an administrator of it" -Class Finding -FindingId 'RODC_DELEGATED_ADMIN'
                        }
                    }
                }

                # Who may make itself the administrator, by writing its own name into
                # managedBy. An ACL that cannot be read is said so, not called clean.
                $aclResult = $null
                try {
                    $aclResult = Get-ObjectACL -DistinguishedName ([string]$rodc.distinguishedName) @PSBoundParameters
                } catch {
                    Write-Log "[Get-RODCPasswordReplication] The ACL of '$($rodc.distinguishedName)' could not be read: $_"
                }
                if (-not $aclResult) {
                    $issues++
                    Show-Line "$rodcName - its ACL could not be read, so who may write its managedBy was not checked" -Class Note
                } else {
                    $writerEntries = @()
                    foreach ($writer in @(Get-RODCManagedByWriter -ACL $aclResult -ObjectSID ([string]$rodc.objectSid))) {
                        # Tier-0 holds full control on a Domain Controller account by
                        # default; an operator does not and counts.
                        if ((Test-IsPrivileged -Identity $writer.SID).Category -eq 'Privileged') { continue }
                        $writerEntries += "$($writer.Name) ($(@($writer.Rights) -join '/'))"
                    }
                    if ($writerEntries.Count -gt 0) {
                        $issues++
                        Show-Line "$rodcName - $($writerEntries.Count) principal(s) outside Tier-0 may write its managedBy and make themselves its administrator: $(Format-RODCAccountList $writerEntries)" -Class Finding -FindingId 'RODC_MANAGEDBY_WRITE'
                    }
                }

                if ($issues -eq 0) {
                    Show-Line "$rodcName - no privileged account may have its password cached, none has, and only Tier-0 controls who administers it" -Class Secure
                }
            }

        } catch {
            Write-Log "[Get-RODCPasswordReplication] Error: $_" -Level Error
            Show-Line "Error during check - the password replication policy of the read-only Domain Controllers could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-RODCPasswordReplication] Check completed"
    }
}

<#
.SYNOPSIS
    Joins account names for a line, sorted, with at most twenty spelled out.

.NOTES
    Internal helper function
#>
function Format-RODCAccountList {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Name
    )

    $sorted = @($Name | Sort-Object)
    $shown = @($sorted | Select-Object -First 20) -join ', '
    if ($sorted.Count -gt 20) { $shown = "$shown, ... and $($sorted.Count - 20) more" }
    return $shown
}

<#
.SYNOPSIS
    Names the trustees of a read-only Domain Controller's ACL that may write its managedBy.

.DESCRIPTION
    The ways to hold the write, read as the access check reads them:

    - the owner, which may rewrite the DACL and grant itself the write
    - an ACE that names nothing and so applies to the whole object, with GenericAll,
      GenericWrite or WriteProperty, which write every property, or with WriteDacl or
      WriteOwner, which let the holder grant itself the write
    - an ACE naming managedBy with WriteProperty. managedBy belongs to no property set -
      MS-ADA2 gives it no attributeSecurityGUID - so no set can name it

    An object ACE naming anything else grants its rights there and nowhere else (MS-DTYP
    2.5.3.2), and an inherit-only ACE applies to the children only. An explicit Deny of the
    write cancels a write grant of the same trustee; it does not stop a holder that may
    rewrite the DACL, which can take the Deny away. An inherited Deny ranks below an
    explicit Allow and is not counted, as in Get-WeakCertificateMapping; a Deny is matched
    by trustee, not by the groups a trustee belongs to.

    SELF, CREATOR OWNER and CREATOR GROUP are left out, and so is the RODC's own account:
    whoever acts as the server is administrator on it already.

    Every trustee, Tier-0 included - the caller decides whom to report.

.PARAMETER ACL
    The result of Get-ObjectACL for the RODC's computer object, Deny ACEs included.

.PARAMETER ObjectSID
    The objectSid of the RODC's computer account.

.OUTPUTS
    PSCustomObject per trustee: SID, Name, Rights (the rights that carry the write).

.NOTES
    Internal helper function
#>
function Get-RODCManagedByWriter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowNull()]
        $ACL,

        [Parameter(Mandatory=$false)]
        [string]$ObjectSID
    )

    if (-not $ACL) { return }

    $managedByGuid = '0296c120-40da-11d1-a9c0-0000f80367c1'
    $noGuid = '00000000-0000-0000-0000-000000000000'

    $notReported = @($Script:SelfModificationSIDs)
    if ($ObjectSID) { $notReported += $ObjectSID }

    # Who is explicitly denied the write itself.
    $writeDenied = @{}
    foreach ($ace in @($ACL.ACEs)) {
        if (-not $ace -or [string]$ace.AccessControlType -ne 'Deny' -or $ace.IsInherited) { continue }
        if (-not (Test-ACEAppliesToSelf -ACE $ace)) { continue }
        $objectType = [string]$ace.ObjectType
        $scoped = $objectType -and $objectType -ne $noGuid
        if ($scoped -and $objectType -ine $managedByGuid) { continue }
        if (@($ace.RightsRaw) -contains 'WriteProperty') { $writeDenied[[string]$ace.TrusteeSID] = $true }
    }

    # Rights per trustee, so a trustee reached through several ACEs is one entry.
    $rightsBySID = [ordered]@{}
    $nameBySID = @{}

    $ownerSID = [string]$ACL.OwnerSID
    if ($ownerSID -and $notReported -notcontains $ownerSID) {
        $rightsBySID[$ownerSID] = @('Owner')
        $nameBySID[$ownerSID] = $(if ($ACL.Owner) { [string]$ACL.Owner } else { $ownerSID })
    }

    foreach ($ace in @($ACL.ACEs)) {
        if (-not $ace -or [string]$ace.AccessControlType -ne 'Allow') { continue }
        if (-not (Test-ACEAppliesToSelf -ACE $ace)) { continue }

        $sid = [string]$ace.TrusteeSID
        if (-not $sid -or $notReported -contains $sid) { continue }

        $rights = @($ace.RightsRaw)
        $objectType = [string]$ace.ObjectType
        $scoped = $objectType -and $objectType -ne $noGuid
        $isDenied = $writeDenied.ContainsKey($sid)

        $granted = @()
        if (-not $scoped) {
            if ($rights -contains 'GenericAll') {
                $granted += 'GenericAll'
            } else {
                if (-not $isDenied) {
                    if ($rights -contains 'GenericWrite') { $granted += 'GenericWrite' }
                    elseif ($rights -contains 'WriteProperty') { $granted += 'WriteProperty' }
                }
                if ($rights -contains 'WriteDacl') { $granted += 'WriteDacl' }
                if ($rights -contains 'WriteOwner') { $granted += 'WriteOwner' }
            }
        } elseif ($objectType -ieq $managedByGuid -and $rights -contains 'WriteProperty' -and -not $isDenied) {
            $granted += 'WriteProperty managedBy'
        }
        if ($granted.Count -eq 0) { continue }

        if (-not $rightsBySID.Contains($sid)) {
            $rightsBySID[$sid] = @()
            $nameBySID[$sid] = $(if ($ace.Trustee) { [string]$ace.Trustee } else { $sid })
        }
        $rightsBySID[$sid] = @($rightsBySID[$sid]) + $granted
    }

    foreach ($sid in @($rightsBySID.Keys)) {
        [PSCustomObject]@{
            SID    = $sid
            Name   = $nameBySID[$sid]
            Rights = @($rightsBySID[$sid] | Select-Object -Unique)
        }
    }
}
