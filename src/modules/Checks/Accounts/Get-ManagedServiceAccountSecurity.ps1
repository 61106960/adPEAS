function Get-ManagedServiceAccountSecurity {
    <#
    .SYNOPSIS
    Analyzes Managed Service Account security configurations.

    .DESCRIPTION
    Identifies security issues with Managed Service Accounts (MSA/gMSA):

    1. gMSA Password Access Analysis:
       - Identifies who can retrieve gMSA passwords via msDS-GroupMSAMembership
       - Flags non-privileged principals with password access (security risk)

    2. gMSA Password Retrieval:
       - Attempts to read msDS-ManagedPassword for each gMSA
       - If successful, displays the NT hash (for authentication)
       - gMSA passwords are 256 random Unicode characters

    3. Standalone MSA Detection:
       - Finds legacy Managed Service Accounts (not gMSA)
       - Standalone MSAs are less secure than gMSAs (single-host, no automatic rotation)

    Security Relevance:
    - gMSA passwords readable by non-privileged accounts = credential theft risk
    - Standalone MSAs lack the security benefits of gMSAs
    - Misconfigured gMSA access can lead to lateral movement

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

            Show-SubHeader "Analyzing Managed Service Account security..." -ObjectType "gMSA"

            # ===== Check 1: gMSA Password Access Analysis =====
            Write-Log "[Get-ManagedServiceAccountSecurity] Checking gMSA password access permissions"

            # Get all gMSAs with details (includes msds-groupmsamembership)
            $gmsaAccounts = @(Get-DomainUser -GMSA -ShowGMSADetails @PSBoundParameters |
                Where-Object { $_.objectClass -icontains 'msDS-GroupManagedServiceAccount' })

            if ($gmsaAccounts.Count -gt 0) {
                Write-Log "[Get-ManagedServiceAccountSecurity] Found $($gmsaAccounts.Count) gMSA account(s)"

                $nonPrivilegedAccessFindings = @()

                $totalGMSAs = @($gmsaAccounts).Count
                $currentIndex = 0
                foreach ($gmsa in $gmsaAccounts) {
                    $currentIndex++
                    if ($totalGMSAs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing gMSA security" -Current $currentIndex -Total $totalGMSAs -ObjectName $gmsa.sAMAccountName }
                    $gmsaName = $gmsa.sAMAccountName
                    $groupMsaMembership = $gmsa.'msds-groupmsamembership'

                    if ($groupMsaMembership) {
                        # Parse the security descriptor to get principals with password access
                        $passwordReaders = @()
                        $hasBroadGroupAccess = $false

                        try {
                            # msds-groupmsamembership is a security descriptor in binary format
                            $sdBytes = if ($groupMsaMembership -is [byte[]]) {
                                $groupMsaMembership
                            } elseif ($groupMsaMembership -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                                $groupMsaMembership[0]
                            } else {
                                $null
                            }

                            if ($sdBytes -and $sdBytes -is [byte[]]) {
                                $RawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor($sdBytes, 0)

                                foreach ($ace in $RawSD.DiscretionaryAcl) {
                                    if ($ace.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowed) {
                                        $principalSID = $ace.SecurityIdentifier.Value
                                        $principalName = ConvertFrom-SID -SID $principalSID

                                        # Use central Test-IsPrivileged for consistent classification
                                        $privCheck = Test-IsPrivileged -Identity $principalSID
                                        $category = $privCheck.Category

                                        # BroadGroup = Everyone, Authenticated Users, Domain Users (CRITICAL)
                                        # Privileged = Domain Admins, Enterprise Admins, etc. (expected)
                                        # Operator = Account Operators, Server Operators, etc. (noteworthy)
                                        # Standard = regular accounts (potential issue)
                                        $isPrivileged = $category -in @('Privileged', 'Operator')
                                        $isBroadGroup = $category -eq 'BroadGroup'

                                        if ($isBroadGroup) {
                                            $hasBroadGroupAccess = $true
                                        }

                                        $passwordReaders += [PSCustomObject]@{
                                            Principal = $principalName
                                            SID = $principalSID
                                            Category = $category
                                            IsPrivileged = $isPrivileged
                                            IsBroadGroup = $isBroadGroup
                                        }
                                    }
                                }
                            }
                        } catch {
                            Write-Log "[Get-ManagedServiceAccountSecurity] Failed to parse msDS-GroupMSAMembership for $gmsaName : $_"
                        }

                        # Check for non-privileged principals (includes BroadGroups which are especially critical)
                        $nonPrivReaders = @($passwordReaders | Where-Object { -not $_.IsPrivileged })

                        if ($nonPrivReaders.Count -gt 0) {
                            $nonPrivilegedAccessFindings += [PSCustomObject]@{
                                gMSA = $gmsaName
                                DN = $gmsa.distinguishedName
                                NonPrivilegedReaders = $nonPrivReaders
                                AllReaders = $passwordReaders
                                HasBroadGroupAccess = $hasBroadGroupAccess
                            }
                        }
                    }
                }
                if ($totalGMSAs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing gMSA security" -Completed }

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
                        Show-Object $gmsaObj

                        # Additional context about password readers - highlight broad groups
                        $readerList = ($finding.NonPrivilegedReaders | ForEach-Object {
                            $prefix = if ($_.IsBroadGroup) { "[CRITICAL] " } else { "" }
                            "$prefix$($_.Principal) ($($_.SID))"
                        }) -join ", "
                        Show-Line "Non-privileged password readers: $readerList" -Class Hint
                    }
                } else {
                    Show-Line "All gMSA password access is properly restricted to privileged accounts" -Class Secure
                }

                # ===== Check 2: Attempt to read gMSA passwords =====
                Write-Log "[Get-ManagedServiceAccountSecurity] Attempting to read gMSA passwords"
                Show-SubHeader "Checking gMSA password access for current user..." -ObjectType "gMSAPassword"

                $passwordsRetrieved = 0

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
                        # Only returned if the caller has permission to read it
                        $gmsaWithPassword = @(Get-DomainUser -Identity $gmsaName -Properties 'msDS-ManagedPassword' @PSBoundParameters)[0]

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

                                    Show-Object $gmsaPasswordObj

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
                        Write-Log "[Get-ManagedServiceAccountSecurity] Error reading password for $gmsaName : $_"
                    }
                }
                if ($totalGMSAs -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing gMSA security" -Completed }

                if ($passwordsRetrieved -eq 0) {
                    Show-Line "Current user cannot retrieve any gMSA passwords" -Class Note
                } else {
                    Show-Line "Retrieved $passwordsRetrieved of $($gmsaAccounts.Count) gMSA password(s)" -Class Finding
                }

                # Output all gMSAs for visibility (they will show adminCount, delegation, SPNs via Show-Object)
                $gmsasWithoutFindings = @($gmsaAccounts | Where-Object {
                    $_.sAMAccountName -notin ($nonPrivilegedAccessFindings | ForEach-Object { $_.gMSA })
                })

                if ($gmsasWithoutFindings.Count -gt 0) {
                    Show-SubHeader "gMSA accounts with proper password access configuration:" -ObjectType "gMSAPassword"
                    foreach ($gmsa in $gmsasWithoutFindings) {
                        $gmsa | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'gMSA' -Force
                        Show-Object $gmsa
                    }
                }
            } else {
                Show-Line "No gMSA accounts found in domain" -Class Note
            }

            # ===== Check 3: Standalone MSA Detection =====
            Write-Log "[Get-ManagedServiceAccountSecurity] Checking for standalone MSAs"

            # Get all MSAs (not gMSAs) - these are legacy standalone MSAs
            $standaloneMSAs = @(Get-DomainUser -GMSA @PSBoundParameters |
                Where-Object {
                    $_.objectClass -icontains 'msDS-ManagedServiceAccount' -and
                    $_.objectClass -inotcontains 'msDS-GroupManagedServiceAccount'
                })

            if ($standaloneMSAs.Count -gt 0) {
                Show-Line "Found $($standaloneMSAs.Count) standalone MSA(s) (legacy, less secure than gMSA):" -Class Finding

                foreach ($msa in $standaloneMSAs) {
                    $msa | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'MSA' -Force
                    Show-Object $msa
                }

                Show-Line "Recommendation: Migrate standalone MSAs to gMSAs for improved security" -Class Hint
            } else {
                Show-Line "No standalone MSAs found" -Class Note
            }

        } catch {
            Write-Log "[Get-ManagedServiceAccountSecurity] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-ManagedServiceAccountSecurity] Check completed"
    }
}
