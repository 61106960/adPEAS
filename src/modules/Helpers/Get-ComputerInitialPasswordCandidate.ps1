function Get-ComputerInitialPasswordCandidate {
    <#
    .SYNOPSIS
    Returns the enabled computer accounts that still carry the password they were created with.

    .DESCRIPTION
    The selection behind Get-ComputerInitialPassword, shared with Invoke-PasswordSpray
    -ComputerDefault so the check and the spray can never disagree about which accounts are
    candidates.

    Candidates are enabled computer accounts without operatingSystem and dNSHostName - a
    Windows join writes both. Those attributes, not the timestamps, keep a normally joined
    computer out: a join that creates the account sets its password in the same moment, and
    with rotation switched off pwdLastSet then stays at whenCreated for good. The base filter
    of Get-DomainComputer is objectCategory=computer, which a gMSA or dMSA does not have.

    Each returned account carries passwordSinceCreation:
    - "Never set - empty password": pwdLastSet 0 with PASSWD_NOTREQD ("dsadd computer").
      No Kerberos keys; it logs on over NTLM with an empty password.
    - "Unchanged, in use": the password was set within five minutes of whenCreated and the
      account has logged on since (lastLogonTimestamp).
    - "Unchanged, never used": the same, never logged on.

    Read-only: no logon attempt, no change to any account.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .OUTPUTS
    The computer objects as Get-DomainComputer returns them, with passwordSinceCreation added.

    .NOTES
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

    $candidates = @(Get-DomainComputer -Enabled -LDAPFilter '(&(!(operatingSystem=*))(!(dNSHostName=*)))' @PSBoundParameters)

    # How long after whenCreated a password still counts as the one it was created with. The
    # tools set it in the same second; a script that creates the account and then sets a
    # password gets some room.
    $creationWindowSeconds = 300

    foreach ($computer in $candidates) {
        $pwdLastSet = $computer.pwdLastSet
        $uacFlags = @($computer.userAccountControl)

        if ($pwdLastSet -isnot [datetime]) {
            # 0 is passed through raw by the FILETIME conversion. Without PASSWD_NOTREQD a 0
            # is "must change at next logon" on an account that has a password, not an
            # account without one.
            if ([string]@($pwdLastSet)[0] -eq '0' -and $uacFlags -contains 'PASSWD_NOTREQD') {
                $computer | Add-Member -NotePropertyName 'passwordSinceCreation' -NotePropertyValue 'Never set - empty password' -Force
                $computer
            }
            continue
        }

        $created = $computer.whenCreated
        if ($created -isnot [datetime]) { continue }
        # Compared in UTC: DateTime arithmetic ignores Kind.
        $secondsAfterCreation = ($pwdLastSet.ToUniversalTime() - $created.ToUniversalTime()).TotalSeconds
        if ([Math]::Abs($secondsAfterCreation) -gt $creationWindowSeconds) { continue }

        $verdict = if ($computer.lastLogonTimestamp -is [datetime]) { 'Unchanged, in use' } else { 'Unchanged, never used' }
        $computer | Add-Member -NotePropertyName 'passwordSinceCreation' -NotePropertyValue $verdict -Force
        $computer
    }
}

function Get-ComputerDefaultPassword {
    <#
    .SYNOPSIS
    The default password of a computer account created as a pre-Windows 2000 computer.

    .DESCRIPTION
    ADUC with "Assign this computer account as a pre-Windows 2000 computer" and
    "net computer /add" set a new computer account's password to its name in lowercase,
    without the trailing "$" and cut to 14 characters (the LAN Manager length of the
    pre-Windows 2000 days). Measured in a lab: a Kerberos TGT is issued for it.

    .PARAMETER SamAccountName
    The account name, with or without the trailing "$".

    .OUTPUTS
    [string]

    .EXAMPLE
    Get-ComputerDefaultPassword 'WS-CLIENT9$'    # ws-client9
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$SamAccountName
    )

    $name = $SamAccountName.Trim().TrimEnd('$').ToLowerInvariant()
    if ($name.Length -gt 14) { $name = $name.Substring(0, 14) }
    return $name
}
