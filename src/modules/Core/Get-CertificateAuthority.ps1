function Get-CertificateAuthority {
    <#
    .SYNOPSIS
    Retrieves Active Directory Certificate Services (AD CS) Certificate Authorities.

    .DESCRIPTION
    Queries the AD Configuration Partition for Certificate Authority (CA) objects.
    Returns detailed information about CA properties, security settings, and ACLs.

    .PARAMETER Identity
    Specific CA name (cn) to query. If not specified, returns all CAs.

    .PARAMETER Properties
    Additional LDAP properties to retrieve. Default properties are always included.

    .PARAMETER Domain
    Target domain (FQDN). If not specified, uses current domain from session.

    .PARAMETER Server
    Specific Domain Controller to query. If not specified, uses session server.

    .PARAMETER Credential
    PSCredential object for authentication. If not specified, uses session credentials.

    .EXAMPLE
    Get-CertificateAuthority
    Returns all Certificate Authorities in the domain.

    .EXAMPLE
    Get-CertificateAuthority -Identity "ContosoCA"
    Returns the "ContosoCA" Certificate Authority.

    .EXAMPLE
    Get-CertificateAuthority -Domain "contoso.com" -Credential (Get-Credential)
    Returns all CAs using specified credentials.

    .NOTES
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Identity,

        [Parameter(Mandatory=$false)]
        [string[]]$Properties,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-CertificateAuthority] Starting CA enumeration"
    }

    process {
        # Ensure LDAP connection exists
        if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
            return
        }

        # Get server and Configuration Naming Context from session
        $ldapServer = $Script:LDAPContext.Server
        $configNC = $Script:LDAPContext.ConfigurationNamingContext

        if (-not $configNC) {
            Write-Error "[Get-CertificateAuthority] No Configuration Naming Context available in LDAP session."
            return
        }

        Write-Log "[Get-CertificateAuthority] Server: $ldapServer, Configuration NC: $configNC"

        # Enrollment Services container path
        $enrollmentPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"

        # Default properties to load
        $defaultProperties = @(
            'cn',
            'displayName',
            'distinguishedName',
            'objectGUID',
            'dNSHostName',
            'cACertificate',
            'certificateTemplates',
            'nTSecurityDescriptor',
            'objectClass',
            'whenCreated',
            'whenChanged',
            'flags'
        )

        # Merge with user-specified properties
        if ($Properties) {
            $allPropertiesToLoad = $defaultProperties + $Properties | Select-Object -Unique
        } else {
            $allPropertiesToLoad = $defaultProperties
        }

        try {
            # Build LDAP filter
            if ($Identity) {
                $filter = "(&(objectClass=pKIEnrollmentService)(cn=$Identity))"
            } else {
                $filter = "(objectClass=pKIEnrollmentService)"
            }

            Write-Log "[Get-CertificateAuthority] LDAP Filter: $filter"
            Write-Log "[Get-CertificateAuthority] Search Base: $enrollmentPath"

            # Use Invoke-LDAPSearch with Configuration Partition SearchBase
            # OneLevel scope ensures we only get direct children of Enrollment Services container
            $results = Invoke-LDAPSearch -Filter $filter -SearchBase $enrollmentPath -Properties $allPropertiesToLoad -Scope OneLevel

            if (-not $results) {
                Write-Log "[Get-CertificateAuthority] No CAs found"
                return
            }

            # Ensure results is always an array
            $resultsArray = @($results)
            Write-Log "[Get-CertificateAuthority] Found $($resultsArray.Count) CA(s)"

            # Process results - Invoke-LDAPSearch already converts attributes
            foreach ($entry in $resultsArray) {
                # Build CA object from converted LDAP result
                $ca = [PSCustomObject]@{
                    Name = $entry.cn
                    DisplayName = $entry.displayName
                    DistinguishedName = $entry.distinguishedName
                    ObjectGUID = $entry.objectGUID
                    DNSHostName = $entry.dNSHostName

                    # Flags
                    Flags = if ($entry.flags) { [int]$entry.flags } else { 0 }

                    # Enabled templates
                    CertificateTemplates = if ($entry.certificateTemplates) {
                        @($entry.certificateTemplates)
                    } else { @() }

                    # CA Certificate (binary, kept as-is)
                    CACertificate = $entry.cACertificate

                    # Security Descriptor (already converted by Invoke-LDAPSearch)
                    SecurityDescriptor = $entry.nTSecurityDescriptor

                    # Timestamps
                    Created = $entry.whenCreated
                    Modified = $entry.whenChanged

                    # Raw LDAP entry for additional access
                    RawEntry = $entry
                }

                Write-Output $ca
            }
        }
        catch {
            Write-Log "[Get-CertificateAuthority] Error querying Certificate Authorities: $_"
            Write-Log "[Get-CertificateAuthority] Exception details: $($_.Exception.Message)"

            # Return error marker object so caller knows query failed vs. no CAs found
            [PSCustomObject]@{
                _QueryError = $true
                ErrorMessage = $_.Exception.Message
            }
        }
    }

    end {
        Write-Log "[Get-CertificateAuthority] Enumeration complete"
    }
}
