function Get-ComputerPasswordAge {
    <#
    .SYNOPSIS
    Detects active computers whose machine account password is not rotated.

    .DESCRIPTION
    A domain member changes its machine account password itself, every 30 days by default
    ("Domain member: Maximum machine account password age"); a Domain Controller does the
    same. A computer that has logged on recently but has not changed its password for far
    longer has the rotation switched off - "Domain member: Disable machine account password
    changes", a join tool on a non-Windows member that does not rotate, or a cloned machine.
    Its machine account key then never ages out: whoever extracted it once can forge
    service tickets to the host, or act as the computer, for as long as it stays.

    Only enabled computers that logged on within -ActiveDays are asked. A computer that is
    switched off does not rotate either, and that is not the question here.
    lastLogonTimestamp lags by up to 14 days, which the 30-day default covers.

    A Domain Controller is reported on its own line, as a finding: its machine account
    replicates the directory, so a key that does not change is a lasting DCSync credential.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER PasswordAgeDays
    Machine account password age from which an active computer is reported (default: 90,
    three times the default rotation interval)

    .PARAMETER ActiveDays
    Number of days within which a computer must have logged on to count as active
    (default: 30)

    .EXAMPLE
    Get-ComputerPasswordAge

    .EXAMPLE
    Get-ComputerPasswordAge -PasswordAgeDays 60 -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Computer
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
        [ValidateRange(1, 3650)]
        [int]$PasswordAgeDays = 90,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 3650)]
        [int]$ActiveDays = 30
    )

    begin {
        Write-Log "[Get-ComputerPasswordAge] Starting check"
    }

    process {
        try {
            # The two thresholds are not connection parameters, so they stay out of the
            # splat: Ensure-LDAPConnection takes Domain, Server and Credential only.
            $connectionParams = @{}
            if ($PSBoundParameters.ContainsKey('Domain'))     { $connectionParams['Domain'] = $Domain }
            if ($PSBoundParameters.ContainsKey('Server'))     { $connectionParams['Server'] = $Server }
            if ($PSBoundParameters.ContainsKey('Credential')) { $connectionParams['Credential'] = $Credential }

            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Searching for active computers whose machine account password is not rotated..." -ObjectType "ComputerPasswordAge"

            $activeSince = (Get-Date).AddDays(-$ActiveDays).ToFileTime()
            $computers = @(Get-DomainComputer -Enabled -PasswordAgeDays $PasswordAgeDays -LDAPFilter "(lastLogonTimestamp>=$activeSince)" @connectionParams)

            if ($computers.Count -eq 0) {
                Show-Line "Every computer that logged on in the last $ActiveDays days has changed its machine account password within $PasswordAgeDays days" -Class Secure
                return
            }

            $domainControllers = @()
            $members = @()
            foreach ($computer in @($computers | Test-AccountActivity -IncludeDetails)) {
                $computer | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'ComputerPasswordAge' -Force
                $days = $computer.ActivityDetails.DaysSincePasswordChange

                # A writable DC is SERVER_TRUST_ACCOUNT, a read-only one PARTIAL_SECRETS_ACCOUNT -
                # the same two flags Get-DomainComputer -DomainController selects by.
                $uacFlags = @($computer.userAccountControl)
                if ($uacFlags -contains 'SERVER_TRUST_ACCOUNT' -or $uacFlags -contains 'PARTIAL_SECRETS_ACCOUNT') {
                    $computer | Add-Member -NotePropertyName 'machinePasswordAge' -NotePropertyValue "DOMAIN CONTROLLER - not rotated for $days days" -Force
                    $domainControllers += $computer
                } else {
                    $computer | Add-Member -NotePropertyName 'machinePasswordAge' -NotePropertyValue "Not rotated for $days days" -Force
                    $members += $computer
                }
            }

            if ($domainControllers.Count -gt 0) {
                Show-Line "$($domainControllers.Count) Domain Controller(s) have not changed their machine account password in $PasswordAgeDays days or more:" -Class Finding
                foreach ($computer in $domainControllers) { Show-Object $computer -Class Finding }
            }

            if ($members.Count -gt 0) {
                Show-Line "$($members.Count) active computer(s) have not changed their machine account password in $PasswordAgeDays days or more:" -Class Hint
                foreach ($computer in $members) { Show-Object $computer -Class Hint }
            }

        } catch {
            Write-Log "[Get-ComputerPasswordAge] Error: $_" -Level Error
            Show-Line "Error during check - the machine account password age could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-ComputerPasswordAge] Check completed"
    }
}
