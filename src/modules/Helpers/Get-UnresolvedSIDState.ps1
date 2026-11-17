function Get-UnresolvedSIDState {
    <#
    .SYNOPSIS
    What a SID stands for that did not resolve to a name.

    .DESCRIPTION
    A security descriptor names principals by SID, and a SID that no longer resolves was
    reported as a principal nobody could identify - "a deleted or foreign principal that
    still holds the delegation", or a non-privileged gMSA password reader. For a SID of the
    scanned domain the directory can say more than that, and this asks it:

    - Present:         an object carries this SID after all - it only has no name
                       ConvertFrom-SID could show (no sAMAccountName). The caller judges the
                       object.
    - SIDHistory:      no object has the SID, but an account carries it in sIDHistory. That
                       account receives the SID in its token and holds whatever the entry
                       grants - the caller judges that account (Carrier, CarrierSID).
    - Deleted:         neither: the principal is gone. A SID is never issued again, so no
                       account can ever hold the entry; restoring the object from the Recycle
                       Bin takes a privileged account. Only said when the bound account is
                       privileged, which can read every object.
    - DeletedOrHidden: the same, seen by an account that is not privileged - an object it may
                       not read looks exactly like one that does not exist.
    - Foreign:         a domain SID of another domain. It may be a real principal of a trusted
                       domain; nothing here can tell.
    - Unknown:         not a domain SID, or the lookup failed.

    .PARAMETER SID
    The SID, as a string. A decorated form ("S-1-5-21-... (UNRESOLVABLE in X)") is accepted;
    the SID is taken from its start.

    .PARAMETER ConnectionParams
    Domain, Server and Credential of the calling check.

    .OUTPUTS
    PSCustomObject: SID, State, Carrier, CarrierSID.

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SID,

        [Parameter(Mandatory = $false)]
        [hashtable]$ConnectionParams = @{}
    )

    $cleanSID = $SID.Trim()
    if ($cleanSID -match '^(S-1-[0-9-]+)') { $cleanSID = $Matches[1] }
    $result = [PSCustomObject]@{
        SID        = $cleanSID
        State      = 'Unknown'
        Carrier    = $null
        CarrierSID = $null
    }

    if ($cleanSID -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { return $result }
    $ownDomainSID = $null
    if ($Script:LDAPContext -and $Script:LDAPContext.DomainSID) { $ownDomainSID = [string]$Script:LDAPContext.DomainSID }
    if (-not $ownDomainSID) { return $result }
    if ($cleanSID.Substring(0, $cleanSID.LastIndexOf('-')) -ne $ownDomainSID) {
        $result.State = 'Foreign'
        return $result
    }

    try {
        # Hex-escaped binary, the form Get-DomainObject uses for objectSid as well
        $sidObject = New-Object System.Security.Principal.SecurityIdentifier($cleanSID)
        $sidBytes = New-Object byte[] $sidObject.BinaryLength
        $sidObject.GetBinaryForm($sidBytes, 0)
        $sidHex = ($sidBytes | ForEach-Object { '\' + $_.ToString('X2') }) -join ''

        $present = @(Get-DomainObject -LDAPFilter "(objectSid=$sidHex)" -Properties 'distinguishedName' @ConnectionParams)
        if ($present.Count -gt 0) {
            $result.State = 'Present'
            return $result
        }

        $carrier = @(Get-DomainObject -LDAPFilter "(sIDHistory=$sidHex)" -Properties 'objectSid', 'sAMAccountName', 'distinguishedName' @ConnectionParams)[0]
        if ($carrier) {
            $carrierSID = [string]$carrier.objectSid
            $result.State = 'SIDHistory'
            $result.CarrierSID = $carrierSID
            $carrierName = $null
            if ($carrierSID) { $carrierName = ConvertFrom-SID -SID $carrierSID }
            if (-not $carrierName) { $carrierName = [string]$carrier.sAMAccountName }
            if (-not $carrierName) { $carrierName = [string]$carrier.distinguishedName }
            $result.Carrier = $carrierName
            return $result
        }
    } catch {
        Write-Log "[Get-UnresolvedSIDState] Lookup of $cleanSID failed: $_"
        return $result
    }

    # Gone, as far as this account can see. Whether that is all there is depends on what it
    # may read: a privileged account reads every object, any other may be denied one.
    $boundIsPrivileged = $false
    $boundName = $null
    if ($Script:LDAPContext.AuthenticatedUserSAM) { $boundName = [string]$Script:LDAPContext.AuthenticatedUserSAM }
    elseif ($Script:LDAPContext.AuthenticatedUserDN) { $boundName = [string]$Script:LDAPContext.AuthenticatedUserDN }
    if ($boundName) {
        try {
            $boundIsPrivileged = ((Test-IsPrivileged -Identity $boundName).IsPrivileged -eq $true)
        } catch {
            Write-Log "[Get-UnresolvedSIDState] Privilege check for '$boundName' failed: $_"
        }
    }
    $result.State = if ($boundIsPrivileged) { 'Deleted' } else { 'DeletedOrHidden' }
    return $result
}
