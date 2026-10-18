<#
.SYNOPSIS
    Says how many organizational units and how many containers a list of DNs holds.

.DESCRIPTION
    The OU permission checks analyse organizational units and containers alike - CN=Users
    and CN=Computers hold most accounts in a great many domains - and their conclusions
    called all of them OUs: "12 analyzed OU(s)" for 4 organizational units and 8 containers,
    measured. A DN whose first RDN is OU= is an organizational unit; anything else is
    counted as a container.

.PARAMETER DistinguishedName
    The objects analysed.

.OUTPUTS
    String - "4 OU(s) and 8 container(s)", "2 OU(s)", "1 container(s)", or "0 OU(s)".
#>
function Format-OUContainerCount {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [string[]]$DistinguishedName
    )

    $dns = @($DistinguishedName | Where-Object { $_ })
    $ouCount = @($dns | Where-Object { $_ -match '^OU=' }).Count
    $containerCount = $dns.Count - $ouCount

    if ($containerCount -eq 0) { return "$ouCount OU(s)" }
    if ($ouCount -eq 0) { return "$containerCount container(s)" }
    return "$ouCount OU(s) and $containerCount container(s)"
}
