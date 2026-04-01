function Get-DomainComputer {
<#
.SYNOPSIS
    Central function for querying computer objects from Active Directory.

.DESCRIPTION
    Get-DomainComputer is a flexible helper function that unifies all computer queries in adPEAS v2.
    It builds on Invoke-LDAPSearch and provides:

    - Search by Identity (sAMAccountName, DN, SID, DOMAIN\computer)
    - Filter by specific criteria (OperatingSystem, SPN, Delegation, LAPS, etc.)
    - Flexible property selection
    - Custom LDAP filters

.PARAMETER Identity
    sAMAccountName, DistinguishedName, SID or DOMAIN\computer format.
    Wildcards are supported.

.PARAMETER OperatingSystem
    Filter by operating system (e.g. "Windows Server 2019", "*2016*").
    Wildcards are supported.

.PARAMETER SPN
    Return only computers with Service Principal Names.

.PARAMETER Unconstrained
    Computers with Unconstrained Delegation (TRUSTED_FOR_DELEGATION flag).
    Excludes Domain Controllers (primaryGroupID=516).

.PARAMETER Constrained
    Computers with Constrained Delegation (msDS-AllowedToDelegateTo attribute).
    Includes both regular Constrained Delegation and Protocol Transition variants.

.PARAMETER RBCD
    Computers with Resource-Based Constrained Delegation (msDS-AllowedToActOnBehalfOfOtherIdentity attribute).
    RBCD allows the target resource to control who can delegate to it.

.PARAMETER TrustedToAuth
    Computers with Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION flag).
    This is the more dangerous variant of Constrained Delegation with S4U2Self.

.PARAMETER LAPS
    Computers with LAPS enabled (detected via expiration time attributes).
    Searches for ms-Mcs-AdmPwdExpirationTime (Legacy LAPS) or msLAPS-PasswordExpirationTime (Windows LAPS).

.PARAMETER Enabled
    Only enabled computers (ACCOUNTDISABLE flag not set).

.PARAMETER Disabled
    Only disabled computers (ACCOUNTDISABLE flag set).

.PARAMETER HighValueSPN
    Computers running high-value services (security-critical targets).
    Includes: MSSQL, Exchange, SCCM, WSUS, ADFS, Certificate Authority, SCOM, Backup software.
    These are prime targets for lateral movement and privilege escalation.

.PARAMETER KnownSPN
    Filter by specific known service SPN. Available options:
    - MSSQL: SQL Server instances (MSSQLSvc/*)
    - Exchange: Exchange servers (exchangeMDB/*, exchangeRFR/*, exchangeAB/*)
    - SCCM: SCCM/MECM servers (SMS Site Server/*)
    - WSUS: WSUS servers
    - ADFS: AD Federation Services (adfssrv/*)
    - CA: Certificate Authorities (certsvc/*)
    - SCOM: System Center Operations Manager (MSOMHSvc/*, MSOMSdkSvc/*)
    - Backup: Backup servers (wbengine/*, veeam*)
    - HyperV: Hyper-V hosts (Microsoft Virtual Console Service/*)
    - RDP: RDP-enabled servers (TERMSRV/*)
    - WinRM: WinRM-enabled servers (WSMAN/*)
    - HTTP: Web servers (HTTP/*)
    - FTP: FTP servers (FTP/*)

.PARAMETER LDAPFilter
    Custom LDAP filter for special queries.

.PARAMETER Properties
    Array of attribute names to return.
    Default: All default properties from Invoke-LDAPSearch.

.PARAMETER SearchBase
    Alternative SearchBase (DN). Default: Domain DN.

.EXAMPLE
    Get-DomainComputer -Identity "DC01"
    Returns the Domain Controller DC01.

.EXAMPLE
    Get-DomainComputer -OperatingSystem "Windows Server 2019"
    Returns all Windows Server 2019 computers.

.EXAMPLE
    Get-DomainComputer -Unconstrained
    Returns all computers with Unconstrained Delegation (excluding DCs).

.EXAMPLE
    Get-DomainComputer -Constrained
    Returns all computers with Constrained Delegation.

.EXAMPLE
    Get-DomainComputer -TrustedToAuth
    Returns all computers with Protocol Transition (S4U2Self).

.EXAMPLE
    Get-DomainComputer -RBCD
    Returns all computers with Resource-Based Constrained Delegation configured.

.EXAMPLE
    Get-DomainComputer -LAPS
    Returns all computers with LAPS passwords.

.EXAMPLE
    Get-DomainComputer -LDAPFilter "(description=*SQL*)"
    Custom LDAP filter for special searches.

.EXAMPLE
    Get-DomainComputer -HighValueSPN
    Returns all computers running high-value services (MSSQL, Exchange, SCCM, etc.).

.EXAMPLE
    Get-DomainComputer -KnownSPN MSSQL
    Returns all SQL Server instances.

.EXAMPLE
    Get-DomainComputer -KnownSPN Exchange -Enabled
    Returns all enabled Exchange servers.

.OUTPUTS
    PSCustomObject with computer attributes

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('samAccountName', 'Name', 'Computer', 'DNSHostName')]
        [string]$Identity,

        # All filter parameters are combinable (no ParameterSetName restriction)
        [Parameter(Mandatory=$false)]
        [string]$OperatingSystem,

        [Parameter(Mandatory=$false)]
        [switch]$SPN,

        [Parameter(Mandatory=$false)]
        [switch]$Unconstrained,

        [Parameter(Mandatory=$false)]
        [switch]$Constrained,

        [Parameter(Mandatory=$false)]
        [switch]$RBCD,

        [Parameter(Mandatory=$false)]
        [switch]$TrustedToAuth,

        [Parameter(Mandatory=$false)]
        [switch]$LAPS,

        [Parameter(Mandatory=$false)]
        [switch]$Enabled,

        [Parameter(Mandatory=$false)]
        [switch]$Disabled,

        [Parameter(Mandatory=$false)]
        [switch]$HighValueSPN,

        [Parameter(Mandatory=$false)]
        [ValidateSet('MSSQL', 'Exchange', 'SCCM', 'WSUS', 'ADFS', 'CA', 'SCOM', 'Backup', 'HyperV', 'RDP', 'WinRM', 'HTTP', 'FTP')]
        [string]$KnownSPN,

        [Parameter(Mandatory=$false)]
        [string]$LDAPFilter,

        [Parameter(Mandatory=$false)]
        [string[]]$Properties,

        [Parameter(Mandatory=$false)]
        [switch]$ShowOwner,

        [Parameter(Mandatory=$false)]
        [string]$SearchBase,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$Raw,

        [Parameter(Mandatory=$false)]
        [int]$ResultLimit = 0
    )

    begin {
        Write-Log "[Get-DomainComputer] Starting computer enumeration"
    }

    process {
        try {
            # Base Filter: computer objects only
            $Filter = "(&(objectCategory=computer)(objectClass=computer))"

            # OperatingSystem filter
            if ($OperatingSystem) {
                $Filter = "(&$Filter(operatingSystem=$OperatingSystem))"
            }

            # Add computer-specific filters (not delegated to Get-DomainObject)
            if ($Unconstrained) {
                # TRUSTED_FOR_DELEGATION Flag (524288) - but NOT Domain Controllers
                $Filter = "(&$Filter(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))"
            }

            if ($Constrained) {
                # Constrained Delegation: Has msDS-AllowedToDelegateTo attribute
                # This includes both regular Constrained Delegation and Protocol Transition
                $Filter = "(&$Filter(msDS-AllowedToDelegateTo=*))"
            }

            if ($RBCD) {
                # Resource-Based Constrained Delegation: Has msDS-AllowedToActOnBehalfOfOtherIdentity attribute
                # The target resource controls who can delegate to it (stored as Security Descriptor)
                $Filter = "(&$Filter(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
            }

            if ($LAPS) {
                # Computers with LAPS enabled (Legacy or Native)
                # Legacy LAPS: ms-Mcs-AdmPwdExpirationTime
                # Windows LAPS: msLAPS-PasswordExpirationTime
                $Filter = "(&$Filter(|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*)))"
            }

            # HighValueSPN: Computers running high-value/security-critical services
            if ($HighValueSPN) {
                # Exchange SPNs are also registered on Domain Controllers for Autodiscover - exclude DCs for Exchange
                # Other services (MSSQL, CA, etc.) can legitimately run on DCs, so we don't exclude them globally
                $HighValueSPNFilter = "(|" +
                    "(servicePrincipalName=MSSQLSvc/*)" +           # SQL Server
                    "(&(|(servicePrincipalName=exchangeMDB/*)(servicePrincipalName=exchangeRFR/*)(servicePrincipalName=exchangeAB/*))(!(primaryGroupID=516)))" +  # Exchange (exclude DCs)
                    "(servicePrincipalName=SMS Site Server/*)" +    # SCCM/MECM
                    "(servicePrincipalName=CmRcService/*)" +        # SCCM Remote Control
                    "(servicePrincipalName=adfssrv/*)" +            # ADFS
                    "(servicePrincipalName=certsvc/*)" +            # Certificate Authority
                    "(servicePrincipalName=MSOMHSvc/*)" +           # SCOM
                    "(servicePrincipalName=MSOMSdkSvc/*)" +         # SCOM SDK
                    "(servicePrincipalName=wbengine/*)" +           # Windows Backup
                    "(servicePrincipalName=veeam*)" +               # Veeam Backup
                    "(servicePrincipalName=wsusService/*)" +        # WSUS
                    ")"
                $Filter = "(&$Filter$HighValueSPNFilter)"
                Write-Log "[Get-DomainComputer] HighValueSPN filter applied"
            }

            # KnownSPN: Filter by specific known service type
            if ($KnownSPN) {
                $SPNFilter = switch ($KnownSPN) {
                    'MSSQL'    { "(servicePrincipalName=MSSQLSvc/*)" }
                    # Exchange: Exclude Domain Controllers (primaryGroupID=516) as they also have Exchange SPNs for Autodiscover
                    'Exchange' { "(&(|(servicePrincipalName=exchangeMDB/*)(servicePrincipalName=exchangeRFR/*)(servicePrincipalName=exchangeAB/*))(!(primaryGroupID=516)))" }
                    'SCCM'     { "(|(servicePrincipalName=SMS Site Server/*)(servicePrincipalName=CmRcService/*))" }
                    'WSUS'     { "(|(servicePrincipalName=wsusService/*)(servicePrincipalName=WSUS/*))" }
                    'ADFS'     { "(servicePrincipalName=adfssrv/*)" }
                    'CA'       { "(servicePrincipalName=certsvc/*)" }
                    'SCOM'     { "(|(servicePrincipalName=MSOMHSvc/*)(servicePrincipalName=MSOMSdkSvc/*))" }
                    'Backup'   { "(|(servicePrincipalName=wbengine/*)(servicePrincipalName=veeam*))" }
                    'HyperV'   { "(|(servicePrincipalName=Microsoft Virtual Console Service/*)(servicePrincipalName=vmms/*))" }
                    'RDP'      { "(servicePrincipalName=TERMSRV/*)" }
                    'WinRM'    { "(servicePrincipalName=WSMAN/*)" }
                    'HTTP'     { "(servicePrincipalName=HTTP/*)" }
                    'FTP'      { "(servicePrincipalName=FTP/*)" }
                }
                $Filter = "(&$Filter$SPNFilter)"
                Write-Log "[Get-DomainComputer] KnownSPN filter applied: $KnownSPN"
            }

            # Append custom LDAP filter
            if ($LDAPFilter) {
                $Filter = "(&$Filter$LDAPFilter)"
            }

            Write-Log "[Get-DomainComputer] Using filter: $Filter"

            # Build parameters for Get-DomainObject
            $GetParams = @{
                LDAPFilter = $Filter
            }

            # Pass through Identity parameter
            if ($Identity) {
                $GetParams['Identity'] = $Identity
            }

            # Pass through other parameters
            if ($Properties) { $GetParams['Properties'] = $Properties }
            if ($ShowOwner) { $GetParams['ShowOwner'] = $true }
            if ($SearchBase) { $GetParams['SearchBase'] = $SearchBase }
            if ($Domain) { $GetParams['Domain'] = $Domain }
            if ($Server) { $GetParams['Server'] = $Server }
            if ($Credential) { $GetParams['Credential'] = $Credential }
            if ($Raw) { $GetParams['Raw'] = $true }

            # Pass through LDAP-optimized account filters to Get-DomainObject
            if ($Enabled) { $GetParams['IsEnabled'] = $true }
            if ($Disabled) { $GetParams['IsDisabled'] = $true }
            if ($SPN) { $GetParams['HasSPN'] = $true }
            if ($TrustedToAuth) { $GetParams['TrustedToAuthForDelegation'] = $true }
            if ($ResultLimit -gt 0) { $GetParams['ResultLimit'] = $ResultLimit }

            $Computers = @(Get-DomainObject @GetParams)

            Write-Log "[Get-DomainComputer] Found $($Computers.Count) computer(s)"

            return $Computers

        } catch {
            Write-Log "[Get-DomainComputer] Error: $_"
            throw
        }
    }

    end {
        Write-Log "[Get-DomainComputer] Computer enumeration completed"
    }
}
