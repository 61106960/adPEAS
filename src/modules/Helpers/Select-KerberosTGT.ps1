<#
.SYNOPSIS
    Picks, among the TGTs of the logon session's ticket cache, the one adPEAS's session
    authenticates with.

.DESCRIPTION
    A ticket cache can hold more than one TGT: the one adPEAS imported for the account
    it connected as, and one the logged-on user's own Windows session acquired - on a
    domain-joined host, or a host signed in to Entra ID, Windows renews its user's TGT on
    its own. Test-KerberosTGTExists took the first unexpired TGT it came across. When the
    user's own one came first, the session was declared invalid - "Kerberos TGT client
    mismatch (TGT=<logged-on user>, Expected=<scan account>)" - and Invoke-adPEAS aborted
    the scan, while the scan account's TGT sat next to it in the cache. Measured: a full
    scan aborted after 74 seconds that way, a TGT of the host's own user having appeared in
    the cache during the run.

    So the expected account's TGT wins, and among several of its TGTs one from the
    session's realm, then one that has not expired. Only when no TGT belongs to the
    expected account is another one returned, which the caller then reports as a
    mismatch - that case is real: the scan account's ticket is gone.

.PARAMETER Candidates
    The TGTs of the cache, each with ClientName, Realm and Expired, in cache order.

.PARAMETER ExpectedClient
    The account the session's TGT was issued to (TGTInfo.UserName). Without it the
    first unexpired TGT is returned, as before.

.PARAMETER ExpectedRealm
    The realm of the session (TGTInfo.Domain). Breaks a tie between TGTs of the same
    account name in different realms.

.OUTPUTS
    One of the candidates, or $null when there are none.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function Select-KerberosTGT {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Candidates,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedClient,

        [Parameter(Mandatory = $false)]
        [string]$ExpectedRealm
    )

    if ($Candidates.Count -eq 0) { return $null }

    $pool = @($Candidates)
    if ($ExpectedClient) {
        $own = @($Candidates | Where-Object { $_.ClientName -ieq $ExpectedClient })
        if ($own.Count -gt 0) {
            $pool = $own
            if ($ExpectedRealm) {
                $inRealm = @($own | Where-Object { $_.Realm -ieq $ExpectedRealm })
                if ($inRealm.Count -gt 0) { $pool = $inRealm }
            }
        }
    }

    $unexpired = @($pool | Where-Object { -not $_.Expired })
    if ($unexpired.Count -gt 0) { return $unexpired[0] }
    return $pool[0]
}
