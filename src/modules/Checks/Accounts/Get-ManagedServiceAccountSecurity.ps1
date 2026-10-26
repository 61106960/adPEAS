function Get-ManagedServiceAccountSecurity {
    <#
    .SYNOPSIS
    Analyzes Managed Service Account security configurations.

    .DESCRIPTION
    Identifies security issues with Managed Service Accounts (MSA/gMSA):

    1. gMSA Password Access Analysis:
       - Identifies who can retrieve gMSA passwords via msDS-GroupMSAMembership
       - Flags non-privileged principals with password access (security risk)
       - Reports the OWNER of that descriptor when it is not a privileged principal:
         an owner may rewrite the DACL inside it, so it can grant itself the password
         without appearing among the readers
       - Reports a rotation interval above 90 days (msDS-ManagedPasswordInterval, the
         upper bound on how long one stolen password stays valid) and an accountExpires
         date (the account stops authenticating when it passes)

    2. gMSA Password Retrieval:
       - Attempts to read msDS-ManagedPassword for each gMSA
       - If successful, displays the NT hash (for authentication)
       - gMSA passwords are 256 random Unicode characters

    3. Standalone MSA Detection:
       - Finds legacy Managed Service Accounts (not gMSA)
       - Standalone MSAs rotate their password automatically too, every 30 days by
         default, managed by the single host they are installed on. What they lack is
         the gMSA delegation model: the password cannot be shared across hosts and
         there is no msDS-GroupMSAMembership to say who may retrieve it

    4. Delegated Managed Service Account (dMSA) Links (Windows Server 2025):
       - A dMSA names the account it replaces, and once that account names the dMSA back
         the KDC issues the dMSA tickets with the account's group memberships and hands
         over the account's keys
       - Read from the replaced account, which a domain user can read - the dMSA itself
         grants Authenticated Users nothing by default
       - Reports a pairing outside a regular migration (account still enabled, or no
         migration state), a link the account does not return, and a privileged account
         a dMSA replaces

    Security Relevance:
    - gMSA passwords readable by non-privileged accounts = credential theft risk
    - Standalone MSAs are bound to one host and have no delegated retrieval model
    - Misconfigured gMSA access can lead to lateral movement
    - A dMSA paired with an account acts with that account's privileges and holds its keys

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-ManagedServiceAccountSecurity

    .EXAMPLE
    Get-ManagedServiceAccountSecurity -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Accounts
    Severity: High (if non-privileged gMSA access or standalone MSAs found)
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
        Write-Log "[Get-ManagedServiceAccountSecurity] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            # For the helpers below, which have no $PSBoundParameters of this function.
            $connectionParams = @{}
            foreach ($connectionKey in @('Domain', 'Server', 'Credential')) {
                if ($PSBoundParameters.ContainsKey($connectionKey)) { $connectionParams[$connectionKey] = $PSBoundParameters[$connectionKey] }
            }

            Show-SubHeader "Analyzing Managed Service Account security..." -ObjectType "gMSA"

            # ===== Check 1: gMSA Password Access Analysis =====
            Write-Log "[Get-ManagedServiceAccountSecurity] Checking gMSA password access permissions"

            # Get all gMSAs with details (includes msds-groupmsamembership)
            $gmsaAccounts = @(Get-DomainUser -GMSA -ShowGMSADetails @PSBoundParameters |
                Where-Object { $_.objectClass -icontains 'msDS-GroupManagedServiceAccount' })

            if ($gmsaAccounts.Count -gt 0) {
                Write-Log "[Get-ManagedServiceAccountSecurity] Found $($gmsaAccounts.Count) gMSA account(s)"

                $nonPrivilegedAccessFindings = @()

                # The descriptors as raw bytes - Get-ManagedAccountDescriptorMap says why
                # the parsed form Get-DomainUser hands over cannot be used.
                $gmsaDescriptors = Get-ManagedAccountDescriptorMap -ConnectionParams $connectionParams
                $gmsaDescriptorOwners = @{}

                # ----- Phase 1: who is granted password access, per gMSA -----
                $gmsaReaderSIDs = @{}
                $allReaderSIDs = @{}
                $analyzedGMSAs = 0
                $unparsedGMSAs = @()
                $undelegatedGMSAs = @()

                $totalGMSAs = @($gmsaAccounts).Count
                $currentIndex = 0
                foreach ($gmsa in $gmsaAccounts) {
                    $currentIndex++
                    if ($totalGMSAs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing gMSA security" -Current $currentIndex -Total $totalGMSAs -ObjectName $gmsa.sAMAccountName }
                    $gmsaName = $gmsa.sAMAccountName
                    $sdBytes = $null
                    foreach ($lookupKey in @([string]$gmsa.distinguishedName, [string]$gmsaName)) {
                        if (-not $lookupKey) { continue }
                        $lookupKey = $lookupKey.ToLowerInvariant()
                        if ($gmsaDescriptors.ContainsKey($lookupKey)) {
                            $sdBytes = $gmsaDescriptors[$lookupKey]
                            break
                        }
                    }

                    if (-not $sdBytes) {
                        # Either nobody is delegated password access or the attribute was
                        # not readable. The two are indistinguishable from here, so both
                        # are stated below instead of passing for the first one.
                        $undelegatedGMSAs += $gmsaName
                        continue
                    }

                    try {
                        $descriptor = Get-ManagedAccountDescriptorReader -Descriptor $sdBytes -Name $gmsaName
                        foreach ($aceSID in @($descriptor.SIDs)) { $allReaderSIDs[$aceSID] = $true }

                        # The owner of this descriptor may rewrite its DACL, so it can grant
                        # itself the password without ever appearing among the readers.
                        if ($descriptor.Owner) { $gmsaDescriptorOwners[$gmsaName] = $descriptor.Owner }

                        $analyzedGMSAs++
                        $gmsaReaderSIDs[$gmsaName] = @($descriptor.SIDs)
                    } catch {
                        $unparsedGMSAs += $gmsaName
                        Write-Log "[Get-ManagedServiceAccountSecurity] Failed to parse msDS-GroupMSAMembership for $gmsaName : $_"
                    }
                }
                if ($totalGMSAs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing gMSA security" -Completed }

                # ----- Phase 2: what kind of principal each reader is -----
                $readerKinds = Get-ManagedAccountReaderKind -SID @($allReaderSIDs.Keys) -ConnectionParams $connectionParams

                # ----- Phase 3: verdict per gMSA -----
                #
                # The verdict per reader is kept for every analyzed gMSA, flagged or not, and
                # handed to the row that lists the readers - see the output below.
                $readerVerdictsByGMSA = @{}
                foreach ($gmsa in $gmsaAccounts) {
                    $gmsaName = $gmsa.sAMAccountName
                    if (-not $gmsaReaderSIDs.ContainsKey($gmsaName)) { continue }

                    $passwordReaders = @(Get-ManagedAccountReader -SID $gmsaReaderSIDs[$gmsaName] -ReaderKind $readerKinds)
                    $hasBroadGroupAccess = @($passwordReaders | Where-Object { $_.IsBroadGroup }).Count -gt 0
                    $unexpectedReaders = @($passwordReaders | Where-Object { -not $_.IsExpected })

                    # Keyed by SID, so a principal the descriptor names without granting
                    # ReadProperty finds no entry and reads as no reader at all.
                    $verdictMap = @{}
                    foreach ($reader in $passwordReaders) { $verdictMap[[string]$reader.SID] = $reader.Verdict }
                    $readerVerdictsByGMSA[$gmsaName] = $verdictMap

                    if ($unexpectedReaders.Count -gt 0) {
                        $nonPrivilegedAccessFindings += [PSCustomObject]@{
                            gMSA = $gmsaName
                            DN = $gmsa.distinguishedName
                            NonPrivilegedReaders = $unexpectedReaders
                            AllReaders = $passwordReaders
                            HasBroadGroupAccess = $hasBroadGroupAccess
                        }
                    }
                }

                # ----- Who may rewrite the descriptor, as opposed to who may read -----
                #
                # The owner of a security descriptor may rewrite its DACL whether or not
                # that DACL grants it anything, so the owner of msDS-GroupMSAMembership
                # can grant itself the password and does not appear among the readers.
                # The analysis above parsed the descriptor and looked only at its ACEs.
                #
                # Computed before the access findings are printed, so an account that is
                # reported there carries the owner row when it is rendered. Owners that
                # could rewrite the descriptor anyway are not reported: Administrators,
                # SYSTEM, Domain Admins and Enterprise Admins (Test-IsDefaultOwner), and
                # any privileged principal reaches the password by other means.
                $descriptorOwnerFindings = @()
                $reportedGMSANames = @($nonPrivilegedAccessFindings | ForEach-Object { $_.gMSA })
                foreach ($ownedGMSA in @($gmsaDescriptorOwners.Keys)) {
                    $ownerSID = $gmsaDescriptorOwners[$ownedGMSA]
                    if (Test-IsDefaultOwner -SID $ownerSID) { continue }
                    if ((Test-IsPrivileged -Identity $ownerSID -IncludeOperators).IsPrivileged) { continue }

                    $ownedObject = @($gmsaAccounts | Where-Object { $_.sAMAccountName -eq $ownedGMSA })[0]
                    if (-not $ownedObject) { continue }

                    $ownerName = ConvertFrom-SID -SID $ownerSID
                    if (-not $ownerName) { $ownerName = $ownerSID }
                    $ownedObject | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'gMSA' -Force
                    $ownedObject | Add-Member -NotePropertyName 'gmsaMembershipOwner' -NotePropertyValue "$ownerName ($ownerSID) - may rewrite who retrieves the password" -Force
                    $descriptorOwnerFindings += [PSCustomObject]@{ gMSA = $ownedGMSA; Owner = $ownerName; Object = $ownedObject }
                }

                # Output non-privileged access findings
                if (@($nonPrivilegedAccessFindings).Count -gt 0) {
                    # Count how many have broad group access (critical)
                    $broadGroupCount = @($nonPrivilegedAccessFindings | Where-Object { $_.HasBroadGroupAccess }).Count
                    $broadGroupInfo = if ($broadGroupCount -gt 0) { " ($broadGroupCount with broad group access - CRITICAL)" } else { "" }
                    Show-Line "Found $(@($nonPrivilegedAccessFindings).Count) gMSA(s) with non-privileged password access$broadGroupInfo`:" -Class Finding

                    foreach ($finding in $nonPrivilegedAccessFindings) {
                        # Output the gMSA object itself (Show-Object will display relevant attributes)
                        $gmsaObj = $gmsaAccounts | Where-Object { $_.sAMAccountName -eq $finding.gMSA }
                        $gmsaObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'gMSA' -Force

                        # Context depends on whether broad group access exists
                        $contextText = if ($finding.HasBroadGroupAccess) { 'CRITICAL: Broad group access' } else { 'Non-privileged access' }
                        $gmsaObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue $contextText -Force

                        # The verdict per reader, for the row that lists them. The transformer
                        # that renders msDS-GroupMSAMembership could only ask Test-IsPrivileged,
                        # which cannot tell a service host from a user account: it coloured
                        # Domain Admins red - the reader this check calls expected - and the
                        # user account that makes the gMSA a finding yellow.
                        if ($readerVerdictsByGMSA.ContainsKey($finding.gMSA)) {
                            $gmsaObj | Add-Member -NotePropertyName '_gmsaReaderVerdicts' -NotePropertyValue $readerVerdictsByGMSA[$finding.gMSA] -Force
                        }

                        # A finding, printed as one. Show-Object defaults to Standard, so the
                        # gMSA sat under a red headline in the renderer's neutral class.
                        Show-Object $gmsaObj -Class Finding

                        # Additional context about password readers - highlight broad groups
                        $readerList = ($finding.NonPrivilegedReaders | ForEach-Object {
                            $prefix = if ($_.IsBroadGroup) { "[CRITICAL] " } else { "" }
                            "$prefix$($_.Principal) ($($_.SID))"
                        }) -join ", "
                        Show-Line "Non-privileged password readers: $readerList" -Class Hint
                    }
                } elseif ($analyzedGMSAs -eq 0) {
                    Show-Line "gMSA password access could not be analyzed - no membership descriptor could be read" -Class Note
                } else {
                    $unanalyzedCount = $totalGMSAs - $analyzedGMSAs
                    if ($unanalyzedCount -gt 0) {
                        Show-Line "gMSA password access is restricted to privileged accounts and service hosts ($unanalyzedCount of $totalGMSAs not analyzed)" -Class Note
                    } else {
                        Show-Line "All gMSA password access is properly restricted to privileged accounts and service hosts" -Class Secure
                    }
                }

                # What was not analyzed, named rather than left out of the report
                if (@($undelegatedGMSAs).Count -gt 0) {
                    Show-Line "No password access is delegated on $(@($undelegatedGMSAs).Count) gMSA(s), or msDS-GroupMSAMembership was not readable: $(@($undelegatedGMSAs) -join ', ')" -Class Note
                }
                if (@($unparsedGMSAs).Count -gt 0) {
                    Show-Line "msDS-GroupMSAMembership could not be parsed on $(@($unparsedGMSAs).Count) gMSA(s) - their password access is unknown: $(@($unparsedGMSAs) -join ', ')" -Class Note
                }
                # ----- What the gMSA objects themselves say -----
                #
                # Three attributes the check asked the directory for and then never read.
                # The descriptor owner gets the object, because it is a finding about that
                # account; the other two get a line naming the accounts, because the
                # gMSAs that matter are printed above already.

                if (@($descriptorOwnerFindings).Count -gt 0) {
                    # The names are on the line, because the object itself may already
                    # have been printed above - the account is then reported once, with
                    # the owner row on it, instead of twice.
                    $ownerList = @($descriptorOwnerFindings | ForEach-Object { "$($_.gMSA) ($($_.Owner))" }) -join ', '

                    Show-Line "msDS-GroupMSAMembership is owned by a principal that is not privileged: $ownerList" -Class Finding -FindingId 'GMSA_MEMBERSHIP_OWNER'
                    foreach ($ownerFinding in $descriptorOwnerFindings) {
                        if ($reportedGMSANames -contains $ownerFinding.gMSA) { continue }
                        # Printed as the finding the line above announces, not at
                        # Show-Object's neutral default.
                        Show-Object $ownerFinding.Object -Class Finding
                    }
                }

                $longIntervals = @()
                $expiringGMSAs = @()
                foreach ($gmsa in $gmsaAccounts) {
                    # msDS-ManagedPasswordInterval is the upper bound on how long a password
                    # that was read once stays valid. The default is 30 days, and the value
                    # is read-only after creation.
                    $intervalDays = 0
                    if ([int]::TryParse([string]$gmsa.'msDS-ManagedPasswordInterval', [ref]$intervalDays) -and $intervalDays -gt 90) {
                        $longIntervals += "$($gmsa.sAMAccountName) ($intervalDays days)"
                    }

                    # accountExpires: 0 and 0x7FFFFFFFFFFFFFFF both mean "never". A date on a
                    # gMSA is a Note, not a finding - nothing is exposed by it, but every
                    # service running under the account stops authenticating when it passes.
                    #
                    # The value arrives converted: ConvertFrom-LDAPAttribute turns a real date
                    # into a DateTime and leaves only the two "never" values as numbers. This
                    # used to parse every value as a number, so a date never got through and
                    # the note never appeared.
                    $expiresRaw = @($gmsa.accountExpires)[0]
                    $expiryText = $null
                    if ($expiresRaw -is [DateTime]) {
                        $expiryText = Format-adPEASDate $expiresRaw 'yyyy-MM-dd'
                    } else {
                        $expiresValue = [long]0
                        if ([long]::TryParse([string]$expiresRaw, [ref]$expiresValue) -and
                            $expiresValue -gt 0 -and $expiresValue -ne 9223372036854775807) {
                            $expiryText = 'unreadable'
                            try { $expiryText = Format-adPEASDate ([DateTime]::FromFileTimeUtc($expiresValue)) 'yyyy-MM-dd' } catch {
                                Write-Log "[Get-ManagedServiceAccountSecurity] Could not read accountExpires of $($gmsa.sAMAccountName): $_"
                            }
                        }
                    }
                    if ($expiryText) {
                        $expiringGMSAs += "$($gmsa.sAMAccountName) ($expiryText)"
                    }
                }

                if (@($longIntervals).Count -gt 0) {
                    Show-Line "gMSA(s) rotating their password less often than every 90 days: $(@($longIntervals) -join ', ')" -Class Hint -FindingId 'GMSA_ROTATION_INTERVAL_LONG'
                }
                if (@($expiringGMSAs).Count -gt 0) {
                    Show-Line "gMSA(s) with an expiry date - the account stops authenticating when it passes: $(@($expiringGMSAs) -join ', ')" -Class Note
                }

                # ===== Check 2: Attempt to read gMSA passwords =====
                Write-Log "[Get-ManagedServiceAccountSecurity] Attempting to read gMSA passwords"
                Show-SubHeader "Checking gMSA password access for current user..." -ObjectType "gMSAPassword"

                $passwordsRetrieved = 0

                # A read the caller is not entitled to returns no attribute; it does not
                # throw. So a throw is a broken query rather than a negative result, and
                # counting them is what keeps the summary below from reporting a scan that
                # never ran as a domain where nobody can read a gMSA password.
                $readFailures = 0

                $totalGMSAs = @($gmsaAccounts).Count
                $currentIndex = 0
                foreach ($gmsa in $gmsaAccounts) {
                    $currentIndex++
                    if ($totalGMSAs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing gMSA security" -Current $currentIndex -Total $totalGMSAs -ObjectName $gmsa.sAMAccountName }
                    $gmsaName = $gmsa.sAMAccountName
                    $gmsaDN = $gmsa.distinguishedName

                    Write-Log "[Get-ManagedServiceAccountSecurity] Attempting to read password for $gmsaName"

                    try {
                        # Query msDS-ManagedPassword - this is a constructed attribute
                        # Only returned if the caller has permission to read it.
                        #
                        # -GMSA is what makes the lookup find the account at all. Without it
                        # Get-DomainUser searches persons that are not computers, and a gMSA is
                        # a computer object: the query matched nothing, for every gMSA, and
                        # the check reported "Current user cannot retrieve any gMSA passwords"
                        # to an account that could read them (measured with a reader listed
                        # in msDS-GroupMSAMembership).
                        $gmsaWithPassword = @(Get-DomainUser -Identity $gmsaName -GMSA -Properties 'msDS-ManagedPassword' @PSBoundParameters)[0]

                        $managedPasswordBlob = $gmsaWithPassword.'msDS-ManagedPassword'

                        if ($managedPasswordBlob) {
                            # Handle different return types
                            $passwordBytes = $null
                            if ($managedPasswordBlob -is [byte[]]) {
                                $passwordBytes = $managedPasswordBlob
                            } elseif ($managedPasswordBlob -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                                $passwordBytes = $managedPasswordBlob[0]
                            } elseif ($managedPasswordBlob.GetType().Name -eq 'Object[]' -and $managedPasswordBlob.Count -gt 0) {
                                $passwordBytes = $managedPasswordBlob[0]
                            }

                            if ($passwordBytes -and $passwordBytes -is [byte[]] -and $passwordBytes.Length -gt 0) {
                                # Parse the password blob
                                $parsedPassword = ConvertFrom-ManagedPassword -Blob $passwordBytes

                                if ($parsedPassword -and $parsedPassword.CurrentNTHash) {
                                    $passwordsRetrieved++

                                    Show-Line "Successfully retrieved password for gMSA: $gmsaName" -Class Finding

                                    # Create gMSA password object for consistent display
                                    $queryHours = [Math]::Round($parsedPassword.QueryPasswordInterval.TotalHours, 1)
                                    $unchangedHours = [Math]::Round($parsedPassword.UnchangedPasswordInterval.TotalHours, 1)

                                    $gmsaPasswordObj = [PSCustomObject]@{
                                        sAMAccountName = $gmsaName
                                        distinguishedName = $gmsaDN
                                        ntHash = $parsedPassword.CurrentNTHash
                                    }

                                    if ($parsedPassword.PreviousNTHash) {
                                        $gmsaPasswordObj | Add-Member -NotePropertyName 'previousNTHash' -NotePropertyValue $parsedPassword.PreviousNTHash
                                    }

                                    $gmsaPasswordObj | Add-Member -NotePropertyName 'queryInterval' -NotePropertyValue "$queryHours hours"
                                    $gmsaPasswordObj | Add-Member -NotePropertyName 'unchangedInterval' -NotePropertyValue "$unchangedHours hours"
                                    $gmsaPasswordObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'gMSAPassword' -Force

                                    # The hash itself, under "Successfully retrieved password".
                                    # It was printed at Show-Object's neutral default.
                                    Show-Object $gmsaPasswordObj -Class Finding

                                    Show-Line "Use NT hash with: Pass-the-Hash, Overpass-the-Hash, or DCSync impersonation" -Class Hint
                                    Show-EmptyLine
                                } else {
                                    Write-Log "[Get-ManagedServiceAccountSecurity] Failed to parse password blob for $gmsaName"
                                }
                            } else {
                                Write-Log "[Get-ManagedServiceAccountSecurity] Password blob is empty or invalid type for $gmsaName"
                            }
                        } else {
                            Write-Log "[Get-ManagedServiceAccountSecurity] No msDS-ManagedPassword returned for $gmsaName (access denied or not available)"
                        }
                    } catch {
                        $readFailures++
                        Write-Log "[Get-ManagedServiceAccountSecurity] Error reading password for $gmsaName : $_"
                    }
                }
                if ($totalGMSAs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing gMSA security" -Completed }

                # msDS-ManagedPassword is a confidential attribute: a DC releases it only
                # over an encrypted connection - LDAPS, or a SASL bind with sealing. A
                # Negotiate or Kerberos bind on port 389 is sealed by Windows on its own,
                # and the connection then reports SecureSocketLayer = $true as well
                # (measured), so the test below holds for those. A simple bind on 389 is not
                # encrypted: there the attribute does not arrive for an entitled caller
                # either, and without an error. An empty result is then no evidence about
                # anyone's permissions, which is what the secure line below used to claim.
                $encryptedSession = $false
                try {
                    if ($Script:LdapConnection -and $Script:LdapConnection.SessionOptions -and $Script:LdapConnection.SessionOptions.SecureSocketLayer) {
                        $encryptedSession = $true
                    }
                } catch {
                    Write-Log "[Get-ManagedServiceAccountSecurity] Could not read the session's encryption state: $_"
                }
                if (-not $encryptedSession -and $Script:LDAPContext -and $Script:LDAPContext.UseLDAPS) {
                    $encryptedSession = $true
                }

                if ($passwordsRetrieved -eq 0) {
                    # The check read msDS-ManagedPassword for every gMSA and got nothing
                    # back: a tested result, and the same kind of answer as the two lines
                    # above it, so it is rendered the same way.
                    if (-not $encryptedSession) {
                        Show-Line "gMSA password retrieval cannot be tested over an unencrypted connection - rerun with -UseLDAPS" -Class Note
                    } elseif ($readFailures -eq $totalGMSAs) {
                        Show-Line "gMSA password access could not be tested - every read failed" -Class Note
                    } elseif ($readFailures -gt 0) {
                        Show-Line "Current user cannot retrieve any gMSA passwords ($readFailures of $totalGMSAs could not be tested)" -Class Secure
                    } else {
                        Show-Line "Current user cannot retrieve any gMSA passwords" -Class Secure
                    }
                } else {
                    Show-Line "Retrieved $passwordsRetrieved of $($gmsaAccounts.Count) gMSA password(s)" -Class Finding
                }

                # Output all gMSAs for visibility (they will show adminCount, delegation, SPNs via Show-Object)
                # Neither kind of finding belongs under "proper password access
                # configuration". The owner findings were left out of this filter, so a gMSA
                # whose only problem is the owner of its descriptor was printed twice - as
                # the finding, and again as properly configured.
                $ownerFindingNames = @($descriptorOwnerFindings | ForEach-Object { $_.gMSA })
                $gmsasWithoutFindings = @($gmsaAccounts | Where-Object {
                    $_.sAMAccountName -notin ($nonPrivilegedAccessFindings | ForEach-Object { $_.gMSA }) -and
                    $_.sAMAccountName -notin $ownerFindingNames
                })

                if ($gmsasWithoutFindings.Count -gt 0) {
                    Show-SubHeader "gMSA accounts with proper password access configuration:" -ObjectType "gMSAPassword"
                    foreach ($gmsa in $gmsasWithoutFindings) {
                        $gmsa | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'gMSA' -Force

                        # The same verdicts as for a flagged gMSA. Without them the row under
                        # this "proper configuration" heading coloured its Domain Admins entry
                        # red and its service host yellow.
                        if ($readerVerdictsByGMSA.ContainsKey([string]$gmsa.sAMAccountName)) {
                            $gmsa | Add-Member -NotePropertyName '_gmsaReaderVerdicts' -NotePropertyValue $readerVerdictsByGMSA[[string]$gmsa.sAMAccountName] -Force
                        }
                        # Secure: the sub header is the statement about these objects, and
                        # it says their password access is configured properly.
                        Show-Object $gmsa -Class Secure
                    }
                }
            } else {
                Show-Line "No gMSA accounts found in domain" -Class Note
            }

            # ===== Check 3: Standalone MSA Detection =====
            Write-Log "[Get-ManagedServiceAccountSecurity] Checking for standalone MSAs"

            # Standalone MSAs are a different account type answering a different question,
            # and every other stage of this check announces itself. Without a header of its
            # own the MSA result ran on directly under the gMSA objects, reading as one
            # more line about the gMSA above it. The MSA ObjectType carries the section
            # title and the help text already - only the header was missing.
            Show-SubHeader "Checking for standalone Managed Service Accounts..." -ObjectType "MSA"

            # Get all MSAs (not gMSAs) - these are legacy standalone MSAs
            $standaloneMSAs = @(Get-DomainUser -GMSA @PSBoundParameters |
                Where-Object {
                    $_.objectClass -icontains 'msDS-ManagedServiceAccount' -and
                    $_.objectClass -inotcontains 'msDS-GroupManagedServiceAccount'
                })

            if ($standaloneMSAs.Count -gt 0) {
                # Hint, because STANDALONE_MSA_LEGACY says Risk = Hint and BaseScore 20.
                # A red line against its own card is one statement too many, and a legacy
                # account type is not a vulnerability.
                Show-Line "Found $($standaloneMSAs.Count) standalone MSA(s) (legacy, tied to one host):" -Class Hint

                foreach ($msa in $standaloneMSAs) {
                    $msa | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'MSA' -Force
                    Show-Object $msa -Class Hint
                }

                Show-Line "Recommendation: Migrate standalone MSAs to gMSAs for improved security" -Class Hint
            } else {
                Show-Line "No standalone MSAs found" -Class Note
            }

            # ===== Check 4: Delegated Managed Service Account links =====
            #
            # A dMSA (Windows Server 2025) names the account it replaces in
            # msDS-ManagedAccountPrecededByLink. Once that account names the dMSA back in
            # msDS-SupersededManagedAccountLink, the KDC issues the dMSA tickets with the
            # account's group memberships and hands over the account's keys.
            #
            # Read from the replaced account, because a domain user can read that one: the
            # dMSA class grants Authenticated Users nothing by default. Measured on Windows
            # Server 2025 as a plain domain user, a dMSA returned its DN and no attribute,
            # while every link showed on the accounts. Get-DomainUser -GMSA does not find a
            # dMSA either - the class derives from computer, not from
            # msDS-ManagedServiceAccount.
            Write-Log "[Get-ManagedServiceAccountSecurity] Checking delegated Managed Service Account links"

            # Only a schema with the class can hold a dMSA. Without it the section stays away
            # rather than reporting the absence of something the forest cannot have.
            $schemaDN = $null
            if ($Script:LDAPContext) {
                $schemaDN = [string]$Script:LDAPContext.SchemaNamingContext
                if (-not $schemaDN -and $Script:LDAPContext.ConfigurationNamingContext) {
                    # The schema container is always a direct child of the configuration
                    # container.
                    $schemaDN = "CN=Schema,$($Script:LDAPContext.ConfigurationNamingContext)"
                }
            }
            $dmsaClass = $null
            if ($schemaDN) {
                $dmsaClass = @(Get-DomainObject -LDAPFilter '(&(objectClass=classSchema)(lDAPDisplayName=msDS-DelegatedManagedServiceAccount))' -SearchBase $schemaDN -Properties 'lDAPDisplayName' @PSBoundParameters)[0]
            } else {
                Write-Log "[Get-ManagedServiceAccountSecurity] No schema naming context - dMSA links not checked"
            }

            if ($dmsaClass) {
                Show-SubHeader "Checking delegated Managed Service Account (dMSA) links..." -ObjectType "dMSALink"

                $linkedAccounts = @(Get-DomainObject -LDAPFilter '(|(msDS-ManagedAccountPrecededByLinkBL=*)(msDS-SupersededManagedAccountLink=*))' @PSBoundParameters)

                $irregularLinks = @()
                $oneSidedLinks = @()
                $oneSidedPrivileged = 0
                $privilegedPredecessors = @()
                $startedPairs = @()
                $completedPairs = @()
                $stalePairs = @()
                $linkedDMSAs = @()

                foreach ($account in $linkedAccounts) {
                    $link = Get-DelegatedMSALinkVerdict -Account $account
                    if (-not $link.Verdict) { continue }
                    $linkedDMSAs += @($link.DMSA)

                    # "account -> dMSA" for the note lines, the dMSA by its CN
                    $accountName = [string]$account.sAMAccountName
                    if (-not $accountName) { $accountName = [string]$account.distinguishedName }
                    $dmsaNames = @($link.DMSA | ForEach-Object {
                        if ([string]$_ -match '^CN=((?:\\.|[^,])+)') { $Matches[1] } else { [string]$_ }
                    })
                    $pairText = "$accountName -> $($dmsaNames -join ', ')"

                    # A completed migration hands the account's group memberships to the dMSA,
                    # which is then privileged without being a member of any privileged group.
                    $isPrivileged = $false
                    if ($link.Verdict -in @('OneSided', 'Completed') -and $account.objectSid) {
                        $isPrivileged = [bool](Test-IsPrivileged -Identity ([string]$account.objectSid) -IncludeOperators).IsPrivileged
                    }

                    switch ($link.Verdict) {
                        'IrregularEnabled' {
                            $account | Add-Member -NotePropertyName 'dmsaLink' -NotePropertyValue 'Irregular link - migration complete, account still enabled' -Force
                            $irregularLinks += $account
                        }
                        'IrregularNoState' {
                            $account | Add-Member -NotePropertyName 'dmsaLink' -NotePropertyValue 'Irregular link - no migration state on the account' -Force
                            $irregularLinks += $account
                        }
                        'OneSided' {
                            $account | Add-Member -NotePropertyName 'dmsaLink' -NotePropertyValue 'One-sided link - the account does not name the dMSA back' -Force
                            $oneSidedLinks += $account
                            if ($isPrivileged) { $oneSidedPrivileged++ }
                        }
                        'Completed' {
                            if ($isPrivileged) {
                                $account | Add-Member -NotePropertyName 'dmsaLink' -NotePropertyValue 'Privileged predecessor - the dMSA acts with its group memberships' -Force
                                $privilegedPredecessors += $account
                            } else {
                                $completedPairs += $pairText
                            }
                        }
                        'Started' { $startedPairs += $pairText }
                        'Stale'   { $stalePairs += $pairText }
                    }
                }

                foreach ($reported in @($irregularLinks) + @($oneSidedLinks) + @($privilegedPredecessors)) {
                    $reported | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'dMSALink' -Force
                }

                # Both sides name each other, so the KDC honours the pairing - and the account
                # is not in the state a migration leaves it in.
                if (@($irregularLinks).Count -gt 0) {
                    Show-Line "Found $(@($irregularLinks).Count) account(s) linked to a dMSA outside a regular migration:" -Class Finding
                    foreach ($reported in $irregularLinks) { Show-Object $reported -Class Finding }
                }

                # Half a pairing. The KDC honours only both halves, so this grants nothing yet;
                # whoever wrote it controls the dMSA, and one write to the account completes it.
                if (@($oneSidedLinks).Count -gt 0) {
                    $privilegedText = ''
                    if ($oneSidedPrivileged -gt 0) { $privilegedText = " ($oneSidedPrivileged privileged)" }
                    Show-Line "Found $(@($oneSidedLinks).Count) account(s) named as predecessor by a dMSA they do not name back$privilegedText`:" -Class Hint
                    foreach ($reported in $oneSidedLinks) { Show-Object $reported -Class Hint }
                }

                if (@($privilegedPredecessors).Count -gt 0) {
                    Show-Line "Found $(@($privilegedPredecessors).Count) privileged account(s) replaced by a dMSA:" -Class Hint
                    foreach ($reported in $privilegedPredecessors) { Show-Object $reported -Class Hint }
                }

                if (@($startedPairs).Count -gt 0) {
                    Show-Line "dMSA migration started: $(@($startedPairs) -join ', ')" -Class Note
                }
                if (@($completedPairs).Count -gt 0) {
                    Show-Line "dMSA migration completed: $(@($completedPairs) -join ', ')" -Class Note
                }
                if (@($stalePairs).Count -gt 0) {
                    Show-Line "Account(s) naming a dMSA that does not name them back: $(@($stalePairs) -join ', ')" -Class Note
                }

                if (@($linkedDMSAs).Count -eq 0) {
                    Show-Line "No account names or is named by a delegated Managed Service Account" -Class Note
                } else {
                    # The dMSA side - who may use it, which hosts - is on the dMSA object, and
                    # by default only administrators, Account Operators and its creator may
                    # read that (the section's help text says so). Said once, for the whole
                    # section, rather than left to look like an evaluation that found nothing.
                    $readableDMSA = $null
                    try {
                        $readableDMSA = @(Get-DomainObject -Identity ([string]@($linkedDMSAs)[0]) -Properties 'objectClass' @PSBoundParameters)[0]
                    } catch {
                        Write-Log "[Get-ManagedServiceAccountSecurity] Could not read the dMSA $(@($linkedDMSAs)[0]): $_"
                    }
                    if (-not $readableDMSA) {
                        Show-Line "The dMSA objects are not readable by this account - who may use each dMSA was not evaluated" -Class Note
                    }
                }

                # ----- Who may use each dMSA -----
                #
                # msDS-GroupMSAMembership names who may request a dMSA's ticket, and after a
                # migration that ticket carries the replaced account's group memberships.
                # The same descriptor as on a gMSA, judged the same way. Only where the scan
                # can read the dMSAs, which by default takes an administrator.
                $dmsaAccounts = @(Get-DomainUser -GMSA -ShowGMSADetails @PSBoundParameters |
                    Where-Object { $_.objectClass -icontains 'msDS-DelegatedManagedServiceAccount' })

                if ($dmsaAccounts.Count -gt 0) {
                    Show-SubHeader "Checking who may use delegated Managed Service Accounts..." -ObjectType "dMSA"

                    $dmsaDescriptors = Get-ManagedAccountDescriptorMap -ConnectionParams $connectionParams
                    $dmsaUserSIDs = @{}
                    $allDMSAUserSIDs = @{}
                    $dmsaOwners = @{}
                    $unusedDMSAs = @()
                    $unparsedDMSAs = @()

                    foreach ($dmsa in $dmsaAccounts) {
                        $dmsaName = [string]$dmsa.sAMAccountName
                        $sdBytes = $null
                        foreach ($lookupKey in @([string]$dmsa.distinguishedName, $dmsaName)) {
                            if (-not $lookupKey) { continue }
                            if ($dmsaDescriptors.ContainsKey($lookupKey.ToLowerInvariant())) {
                                $sdBytes = $dmsaDescriptors[$lookupKey.ToLowerInvariant()]
                                break
                            }
                        }
                        if (-not $sdBytes) {
                            # Nobody named, or the attribute was not readable - stated below,
                            # rather than passed off as the first.
                            $unusedDMSAs += $dmsaName
                            continue
                        }
                        try {
                            $descriptor = Get-ManagedAccountDescriptorReader -Descriptor $sdBytes -Name $dmsaName
                            $dmsaUserSIDs[$dmsaName] = @($descriptor.SIDs)
                            foreach ($userSID in @($descriptor.SIDs)) { $allDMSAUserSIDs[$userSID] = $true }
                            if ($descriptor.Owner) { $dmsaOwners[$dmsaName] = $descriptor.Owner }
                        } catch {
                            $unparsedDMSAs += $dmsaName
                            Write-Log "[Get-ManagedServiceAccountSecurity] Failed to parse msDS-GroupMSAMembership for $dmsaName : $_"
                        }
                    }

                    $dmsaUserKinds = Get-ManagedAccountReaderKind -SID @($allDMSAUserSIDs.Keys) -ConnectionParams $connectionParams
                    $usableByOthers = @()
                    foreach ($dmsa in $dmsaAccounts) {
                        $dmsaName = [string]$dmsa.sAMAccountName
                        if (-not $dmsaUserSIDs.ContainsKey($dmsaName)) { continue }

                        $dmsaUsers = @(Get-ManagedAccountReader -SID $dmsaUserSIDs[$dmsaName] -ReaderKind $dmsaUserKinds)
                        $verdictMap = @{}
                        foreach ($dmsaUser in $dmsaUsers) { $verdictMap[[string]$dmsaUser.SID] = $dmsaUser.Verdict }
                        # Read by the transformer of msDS-GroupMSAMembership, as on a gMSA.
                        $dmsa | Add-Member -NotePropertyName '_gmsaReaderVerdicts' -NotePropertyValue $verdictMap -Force

                        $unexpectedUsers = @($dmsaUsers | Where-Object { -not $_.IsExpected })
                        if ($unexpectedUsers.Count -gt 0) {
                            $usableByOthers += [PSCustomObject]@{
                                Account    = $dmsa
                                Unexpected = $unexpectedUsers
                                HasBroad   = (@($unexpectedUsers | Where-Object { $_.IsBroadGroup }).Count -gt 0)
                            }
                        }
                    }

                    if (@($usableByOthers).Count -gt 0) {
                        $broadCount = @($usableByOthers | Where-Object { $_.HasBroad }).Count
                        $broadInfo = ''
                        if ($broadCount -gt 0) { $broadInfo = " ($broadCount with broad group access - CRITICAL)" }
                        Show-Line "Found $(@($usableByOthers).Count) dMSA(s) that principals beyond administrators and service hosts may use$broadInfo`:" -Class Finding

                        foreach ($entry in $usableByOthers) {
                            $contextText = 'Non-privileged access'
                            if ($entry.HasBroad) { $contextText = 'CRITICAL: Broad group access' }
                            $entry.Account | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'dMSA' -Force
                            $entry.Account | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue $contextText -Force
                            Show-Object $entry.Account -Class Finding

                            $userList = @($entry.Unexpected | ForEach-Object {
                                $prefix = ''
                                if ($_.IsBroadGroup) { $prefix = '[CRITICAL] ' }
                                "$prefix$($_.Principal) ($($_.SID))"
                            }) -join ', '
                            Show-Line "Non-privileged principals allowed to use it: $userList" -Class Hint
                        }
                    }

                    # The owner of the descriptor may rewrite it and name itself.
                    $ownedDMSAs = @()
                    foreach ($ownedName in @($dmsaOwners.Keys | Sort-Object)) {
                        $ownerSID = $dmsaOwners[$ownedName]
                        if (Test-IsDefaultOwner -SID $ownerSID) { continue }
                        if ((Test-IsPrivileged -Identity $ownerSID -IncludeOperators).IsPrivileged) { continue }
                        $ownerName = ConvertFrom-SID -SID $ownerSID
                        if (-not $ownerName) { $ownerName = $ownerSID }
                        $ownedDMSAs += "$ownedName ($ownerName)"
                    }
                    if (@($ownedDMSAs).Count -gt 0) {
                        Show-Line "msDS-GroupMSAMembership of a dMSA is owned by a principal that is not privileged: $(@($ownedDMSAs) -join ', ')" -Class Finding -FindingId 'DMSA_MEMBERSHIP_OWNER'
                    }

                    if (@($unusedDMSAs).Count -gt 0) {
                        Show-Line "No principal may use $(@($unusedDMSAs).Count) dMSA(s), or msDS-GroupMSAMembership was not readable: $(@($unusedDMSAs) -join ', ')" -Class Note
                    }
                    if (@($unparsedDMSAs).Count -gt 0) {
                        Show-Line "msDS-GroupMSAMembership could not be parsed on $(@($unparsedDMSAs).Count) dMSA(s) - who may use them is unknown: $(@($unparsedDMSAs) -join ', ')" -Class Note
                    }

                    if (@($usableByOthers).Count -eq 0 -and @($ownedDMSAs).Count -eq 0 -and $dmsaUserSIDs.Count -gt 0) {
                        $unanalyzedDMSAs = $dmsaAccounts.Count - $dmsaUserSIDs.Count
                        if ($unanalyzedDMSAs -gt 0) {
                            Show-Line "dMSA use is restricted to privileged accounts and service hosts ($unanalyzedDMSAs of $($dmsaAccounts.Count) not analyzed)" -Class Note
                        } else {
                            Show-Line "Every dMSA can be used only by privileged accounts and service hosts" -Class Secure
                        }
                    }
                }
            }

        } catch {
            Write-Log "[Get-ManagedServiceAccountSecurity] Error: $_" -Level Error
            Show-Line "Error during check - managed service accounts could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-ManagedServiceAccountSecurity] Check completed"
    }
}

<#
.SYNOPSIS
    What the delegated Managed Service Account links on one account say.

.DESCRIPTION
    A dMSA names the account it replaces in msDS-ManagedAccountPrecededByLink; the account
    carries that as the back link msDS-ManagedAccountPrecededByLinkBL. In a migration the
    account names the dMSA in turn in msDS-SupersededManagedAccountLink, with
    msDS-SupersededServiceAccountState 1 while it runs and 2 once it is complete -
    Complete-ADServiceAccountMigration also disables the account. The KDC honours a pairing
    only when both sides name each other.

    One verdict per account, the first that applies:
    - OneSided:         a dMSA names the account and the account does not name it back.
    - Started:          both sides name each other, state 1.
    - Completed:        both sides name each other, state 2, the account disabled.
    - IrregularEnabled: both sides name each other, state 2, the account still enabled.
    - IrregularNoState: both sides name each other, no migration state at all.
    - Stale:            the account names a dMSA that does not name it.

.PARAMETER Account
    The account as Get-DomainObject returns it.

.OUTPUTS
    PSCustomObject with Verdict ($null for an account without a link) and DMSA, the DNs of
    the dMSAs the verdict is about.
#>
function Get-DelegatedMSALinkVerdict {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Account
    )

    $namedBy = @(@($Account.'msDS-ManagedAccountPrecededByLinkBL') | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $names   = @(@($Account.'msDS-SupersededManagedAccountLink') | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $state   = [string](@($Account.'msDS-SupersededServiceAccountState') | Where-Object { $null -ne $_ } | Select-Object -First 1)

    # Get-DomainObject hands userAccountControl over as flag names; a bare number is read
    # as well. Without the attribute the state is unknown, and an unknown state must not
    # turn a completed migration into a finding.
    $enabled = $null
    $uac = @($Account.userAccountControl | Where-Object { $null -ne $_ })
    if ($uac.Count -gt 0) {
        $uacNumber = 0
        if ($uac.Count -eq 1 -and [int]::TryParse([string]$uac[0], [ref]$uacNumber)) {
            $enabled = -not ($uacNumber -band 2)
        } else {
            $enabled = -not ($uac -contains 'ACCOUNTDISABLE')
        }
    }

    # -contains compares strings without regard to case, as the DC compares DNs.
    $oneSided = @($namedBy | Where-Object { $names -notcontains $_ })
    $paired   = @($namedBy | Where-Object { $names -contains $_ })
    $stale    = @($names | Where-Object { $namedBy -notcontains $_ })

    $verdict = $null
    $dmsa = @()
    if ($oneSided.Count -gt 0) {
        $verdict = 'OneSided'
        $dmsa = $oneSided
    } elseif ($paired.Count -gt 0) {
        $dmsa = $paired
        if ($state -eq '1') {
            $verdict = 'Started'
        } elseif ($state -eq '2') {
            if ($enabled -eq $true) { $verdict = 'IrregularEnabled' } else { $verdict = 'Completed' }
        } else {
            $verdict = 'IrregularNoState'
        }
    } elseif ($stale.Count -gt 0) {
        $verdict = 'Stale'
        $dmsa = $stale
    }

    [PSCustomObject]@{
        Verdict = $verdict
        DMSA    = $dmsa
    }
}

<#
.SYNOPSIS
    The msDS-GroupMSAMembership descriptors of every managed service account, as raw bytes.

.DESCRIPTION
    msDS-GroupMSAMembership is a security descriptor, and by the time Get-DomainUser has
    returned it ConvertFrom-LDAPAttribute has already replaced it with a parsed object
    carrying Owner and ACEs. Neither of the two guards that used to stand in the check -
    [byte[]] and ResultPropertyValueCollection - could therefore ever be true: the parse
    branch was dead code, and every domain was told its gMSA password access was properly
    restricted, no matter who could actually read the passwords.

    The parsed form cannot carry the verdict either. It renders the access mask as
    ActiveDirectoryRights names, and the SDDL generic bits have no name in that enum - an
    ACE written as "(A;;GA;;;<sid>)" comes out as the bare number 268435456, which no rights
    test can read. So the descriptors are fetched once as raw bytes, the same route the
    AdminSDHolder check in Get-PrivilegedGroupMembers takes.

    Keyed by both identifiers the query asks for, lowercased. If one of them did not come
    back, every lookup would miss and the check would report that it could not analyze
    anything - honest, but useless, and a second key costs nothing.

.PARAMETER ConnectionParams
    Domain, Server and Credential of the calling check.

.OUTPUTS
    Hashtable: lowercased DN and sAMAccountName -> byte[] descriptor. Accounts without one
    are absent.
#>
function Get-ManagedAccountDescriptorMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionParams = @{}
    )

    $descriptors = @{}
    try {
        foreach ($rawAccount in @(Get-DomainUser -GMSA -Properties 'distinguishedName', 'sAMAccountName', 'msDS-GroupMSAMembership' -Raw @ConnectionParams)) {
            $rawSD = $rawAccount.'msDS-GroupMSAMembership'
            if (-not ($rawSD -is [byte[]]) -or $rawSD.Length -eq 0) { continue }

            foreach ($rawKey in @([string]$rawAccount.distinguishedName, [string]$rawAccount.sAMAccountName)) {
                if ($rawKey) { $descriptors[$rawKey.ToLowerInvariant()] = $rawSD }
            }
        }
    } catch {
        Write-Log "[Get-ManagedServiceAccountSecurity] Could not read the managed service account membership descriptors: $_" -Level Warning
    }
    return $descriptors
}

<#
.SYNOPSIS
    Who an msDS-GroupMSAMembership descriptor lets use the account, and who owns it.

.DESCRIPTION
    Using a managed service account means reading msDS-ManagedPassword for a gMSA and
    requesting the account's ticket for a dMSA, and the descriptor grants both through
    ReadProperty - Windows writes "(A;;RP;;;<sid>)" for
    -PrincipalsAllowedToRetrieveManagedPassword. Test-ADRightsMask expands the generic bits,
    so an ACE granting it through GA or GR counts as well, while an ACE carrying ReadControl
    alone - which the old code counted as a reader - entitles its holder to nothing.

    GetAccessRules with SecurityIdentifier rather than .Access: .Access asks for the rules as
    NTAccount, which makes the scanning host resolve every SID and silently drops the ones it
    cannot - against a domain this host is not joined to that is every domain principal.

    The owner of the descriptor may rewrite its DACL whether or not the DACL grants it
    anything, so it is returned beside the readers.

.PARAMETER Descriptor
    The raw descriptor.

.PARAMETER Name
    The account, for the log.

.OUTPUTS
    PSCustomObject with SIDs (the principals granted ReadProperty, each once) and Owner (a
    SID string, or $null). Throws when the bytes are not a security descriptor.
#>
function Get-ManagedAccountDescriptorReader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Descriptor,

        [Parameter(Mandatory = $false)]
        [string]$Name
    )

    $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $sd.SetSecurityDescriptorBinaryForm($Descriptor)

    $grantedSIDs = @()
    foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if (-not (Test-ADRightsMask -Rights $ace.ActiveDirectoryRights -Has ([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty))) { continue }

        $aceSID = [string]$ace.IdentityReference.Value
        if ($aceSID -and ($grantedSIDs -notcontains $aceSID)) { $grantedSIDs += $aceSID }
    }

    $owner = $null
    try {
        $sdOwner = $sd.GetOwner([System.Security.Principal.SecurityIdentifier])
        if ($sdOwner) { $owner = [string]$sdOwner.Value }
    } catch {
        Write-Log "[Get-ManagedServiceAccountSecurity] Could not read the descriptor owner of $Name : $_"
    }

    [PSCustomObject]@{
        SIDs  = $grantedSIDs
        Owner = $owner
    }
}

<#
.SYNOPSIS
    What kind of principal each SID a membership descriptor grants is.

.DESCRIPTION
    What msDS-GroupMSAMembership is for is naming the hosts that run the service, so a
    computer account - or a group that holds only computer accounts, which is the
    documented way to grant them - is the intended configuration and not a finding. Calling
    everything outside Privileged/Operator a non-privileged reader would turn every
    correctly configured account into a finding.

    For a broad group, a privileged principal or an operator the category decides on its
    own, so no lookup is made for those - it would also send a query after SIDs that are
    not directory objects at all, such as S-1-5-11 or an NT SERVICE SID. Test-IsPrivileged
    caches its answer, so asking it here costs Get-ManagedAccountReader nothing.

    A group is judged by its direct members. A nested group is reported rather than walked:
    an unexpanded branch must not pass as a host. A group with no members grants nobody
    anything and stays a host group.

.PARAMETER SID
    The SIDs to classify.

.PARAMETER ConnectionParams
    Domain, Server and Credential of the calling check.

.OUTPUTS
    Hashtable: SID -> 'DecidedByCategory', 'Host', 'Principal' or 'Unresolved'.
#>
function Get-ManagedAccountReaderKind {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$SID = @(),

        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionParams = @{}
    )

    $hostClasses = @('computer', 'msDS-ManagedServiceAccount', 'msDS-GroupManagedServiceAccount')
    $readerKinds = @{}
    foreach ($readerSID in @($SID | Where-Object { $_ })) {
        if ((Test-IsPrivileged -Identity $readerSID).Category -in @('BroadGroup', 'Privileged', 'Operator')) {
            $readerKinds[$readerSID] = 'DecidedByCategory'
            continue
        }

        $readerKind = 'Principal'
        try {
            $readerObject = @(Get-DomainObject -Identity $readerSID -Properties 'objectClass', 'distinguishedName' @ConnectionParams)[0]
            if (-not $readerObject) {
                # A SID the directory does not resolve is not a host, and treating what
                # could not be looked up as harmless is exactly how a check reports an
                # unchecked state as a clean one.
                $readerKind = 'Unresolved'
            } elseif (@(@($readerObject.objectClass) | Where-Object { $hostClasses -icontains $_ }).Count -gt 0) {
                $readerKind = 'Host'
            } elseif (@($readerObject.objectClass) -icontains 'group') {
                $readerKind = 'Host'
                $memberFilter = "(memberOf=$(Escape-LDAPFilterDN -DistinguishedName ([string]$readerObject.distinguishedName)))"
                foreach ($groupMember in @(Get-DomainObject -LDAPFilter $memberFilter -Properties 'objectClass' @ConnectionParams)) {
                    if (@(@($groupMember.objectClass) | Where-Object { $hostClasses -icontains $_ }).Count -eq 0) {
                        $readerKind = 'Principal'
                        break
                    }
                }
            }
        } catch {
            $readerKind = 'Unresolved'
            Write-Log "[Get-ManagedServiceAccountSecurity] Could not classify password reader $readerSID : $_"
        }
        $readerKinds[$readerSID] = $readerKind
    }
    return $readerKinds
}

<#
.SYNOPSIS
    The verdict on each principal a membership descriptor grants.

.DESCRIPTION
    - Broad:      Everyone, Authenticated Users, Domain Users - every account in the domain
                  can use the account (CRITICAL)
    - Expected:   a privileged principal or an operator, which reach the account by other
                  means anyway, or a host - a computer account or a group of them, which is
                  what the attribute exists for
    - Unexpected: anything else - a user account, a group holding one, or a SID that does
                  not resolve

.PARAMETER SID
    The SIDs the descriptor grants.

.PARAMETER ReaderKind
    Get-ManagedAccountReaderKind's answer for them.

.OUTPUTS
    One PSCustomObject per SID: Principal, SID, Category, Kind, IsExpected, IsBroadGroup,
    Verdict.
#>
function Get-ManagedAccountReader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$SID = @(),

        [Parameter(Mandatory = $false)]
        [hashtable]$ReaderKind = @{}
    )

    foreach ($readerSID in @($SID | Where-Object { $_ })) {
        $principalName = ConvertFrom-SID -SID $readerSID
        if (-not $principalName) { $principalName = $readerSID }

        $category = (Test-IsPrivileged -Identity $readerSID).Category

        # $kind, not $readerKind: PowerShell names are case-insensitive, and the
        # [hashtable] parameter would refuse the string.
        $kind = 'Unresolved'
        if ($ReaderKind.ContainsKey($readerSID)) { $kind = $ReaderKind[$readerSID] }

        $isBroadGroup = $category -eq 'BroadGroup'
        $isExpected = $false
        if (-not $isBroadGroup) {
            $isExpected = ($category -in @('Privileged', 'Operator')) -or ($kind -eq 'Host')
        }

        $verdict = 'Unexpected'
        if ($isBroadGroup) { $verdict = 'Broad' } elseif ($isExpected) { $verdict = 'Expected' }

        [PSCustomObject]@{
            Principal    = $principalName
            SID          = $readerSID
            Category     = $category
            Kind         = $kind
            IsExpected   = $isExpected
            IsBroadGroup = $isBroadGroup
            Verdict      = $verdict
        }
    }
}
