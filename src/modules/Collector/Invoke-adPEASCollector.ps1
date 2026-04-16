function Invoke-adPEASCollector {
<#
.SYNOPSIS
    BloodHound-compatible data collector for adPEAS v2.

.DESCRIPTION
    Collects Active Directory data and exports it in BloodHound-compatible JSON format.
    This is a DCOnly implementation focusing on LDAP-based collection:

    Collected Data:
    - Users (with properties, SPNs, delegation settings)
    - Groups (with members and ACEs)
    - Computers (with properties and delegation)
    - Domains (with trusts and properties)
    - OUs (with properties and links)
    - Containers (CN=Users, CN=Computers, etc.)
    - GPOs (with links and properties)
    - Certificate Templates (ADCS)
    - Enterprise CAs (ADCS)
    - Root CAs (ADCS)
    - AIA CAs (ADCS)
    - NTAuth Stores (ADCS)
    - Issuance Policies (ADCS)

    NOT included (requires Win32 API):
    - Session collection (NetSessionEnum)
    - Local group membership (NetLocalGroupGetMembers)

    Output Format:
    - BloodHound CE compatible JSON (version 6)
    - Packaged as ZIP file

.PARAMETER Domain
    Target domain to collect (optional, uses current session domain).

.PARAMETER Server
    Specific Domain Controller to query.

.PARAMETER Credential
    PSCredential for authentication.

.PARAMETER OutputPath
    Path for output ZIP file. Default: current directory.

.PARAMETER CollectionMethod
    What to collect. Default: DCOnly
    Options: DCOnly, ACL, ObjectProps, Trusts, Container, CertServices

    DCOnly collects everything available via LDAP (users, groups, computers,
    domains, OUs, containers, GPOs, ADCS objects, ACLs). The other options allow partial collection.

.PARAMETER NoZip
    Output individual JSON files instead of ZIP.

.PARAMETER PrettyPrint
    Format JSON with indentation (larger files but readable).

.EXAMPLE
    Invoke-adPEASCollector -OutputPath .\bloodhound_data.zip

.EXAMPLE
    Invoke-adPEASCollector -Domain "contoso.com" -Credential (Get-Credential)

.EXAMPLE
    Invoke-adPEASCollector -CollectionMethod ObjectProps -NoZip
    Collects only object properties (no ACLs) for faster collection.

.NOTES
    Category: Collector
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
        [string]$OutputPath,

        [Parameter(Mandatory=$false)]
        [ValidateSet('DCOnly', 'ACL', 'ObjectProps', 'Trusts', 'Container', 'CertServices')]
        [string]$CollectionMethod = 'DCOnly',

        [Parameter(Mandatory=$false)]
        [switch]$NoZip,

        [Parameter(Mandatory=$false)]
        [switch]$PrettyPrint
    )

    begin {
        Write-Log "[Invoke-adPEASCollector] Starting collection"
        $Script:CollectorVersion = "1.0.0"
        $Script:JsonVersion = 6
        $Script:CollectionTimestamp = Get-Date -Format "yyyyMMddHHmmss"
    }

    process {
        try {
            # Build connection params for Collect-BH* functions (they don't accept OutputPath, CollectionMethod, etc.)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            $domainName = $Script:LDAPContext.Domain.ToUpper()
            $domainDN = $Script:LDAPContext.DomainDN
            $domainSID = $null

            Show-SubHeader "Collecting BloodHound CE data..." -ObjectType "BloodHoundCollector"

            # Get Domain SID
            $domainObj = @(Get-DomainObject -LDAPFilter "(distinguishedName=$domainDN)" @connectionParams)[0]

            if ($domainObj.objectSid) {
                $domainSID = Convert-SidToString -SidInput $domainObj.objectSid
            }

            $defaultFileName = "$($Script:CollectionTimestamp)_$($domainName)_BloodHound.zip"

            if ([string]::IsNullOrEmpty($OutputPath)) {
                $OutputPath = Join-Path (Get-Location) $defaultFileName
            }
            elseif (Test-Path $OutputPath -PathType Container) {
                # OutputPath is an existing directory - append default filename
                $OutputPath = Join-Path $OutputPath $defaultFileName
                Write-Log "[Invoke-adPEASCollector] Output directory specified, using: $OutputPath"
            }
            elseif ($OutputPath -match '[\\/]$') {
                # OutputPath ends with slash - treat as directory
                if (-not (Test-Path $OutputPath)) {
                    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
                }
                $OutputPath = Join-Path $OutputPath $defaultFileName
                Write-Log "[Invoke-adPEASCollector] Output directory specified, using: $OutputPath"
            }

            $tempDir = Join-Path $env:TEMP "adPEAS_BH_$Script:CollectionTimestamp"
            if (-not (Test-Path $tempDir)) {
                New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
            }

            Write-Log "[Invoke-adPEASCollector] Temporary directory: $tempDir"

            $collectedData = @{
                Users             = @()
                Groups            = @()
                Computers         = @()
                Domains           = @()
                OUs               = @()
                Containers        = @()
                GPOs              = @()
                CertTemplates     = @()
                EnterpriseCAs     = @()
                RootCAs           = @()
                AIACAs            = @()
                NTAuthStores      = @()
                IssuancePolicies  = @()
            }

            # Determine what to collect based on CollectionMethod
            $collectUsers = $CollectionMethod -in @('DCOnly', 'ObjectProps', 'ACL')
            $collectGroups = $CollectionMethod -in @('DCOnly', 'ObjectProps', 'ACL')
            $collectComputers = $CollectionMethod -in @('DCOnly', 'ObjectProps', 'ACL')
            $collectDomains = $CollectionMethod -in @('DCOnly', 'Trusts')
            $collectOUs = $CollectionMethod -in @('DCOnly', 'Container', 'ACL')
            $collectContainers = $CollectionMethod -in @('DCOnly', 'Container')
            $collectGPOs = $CollectionMethod -in @('DCOnly', 'Container', 'ACL')
            $collectACLs = $CollectionMethod -in @('DCOnly', 'ACL')
            $collectADCS = $CollectionMethod -in @('DCOnly', 'ACL', 'CertServices')

            # Count total collection steps for progress display
            $totalSteps = 0
            if ($collectDomains) { $totalSteps++ }          # Domain
            if ($collectUsers) { $totalSteps++ }            # Users
            if ($collectGroups) { $totalSteps++ }           # Groups
            if ($collectComputers) { $totalSteps++ }        # Computers
            if ($collectOUs) { $totalSteps++ }              # OUs
            if ($collectContainers) { $totalSteps++ }       # Containers
            if ($collectGPOs) { $totalSteps++ }             # GPOs
            if ($collectADCS) { $totalSteps += 6 }          # 6 ADCS object types
            $totalSteps++                                    # Writing JSON
            $currentStep = 0
            $Script:CollectedParts = [System.Collections.Generic.List[string]]::new()

            # Progress display: two dynamic lines
            # Line 1: "Collected: 1 domain, 30 users, 76 groups" (grows with each step)
            # Line 2: "Collecting: Computers...  [4/14]" (active step, overwritten)
            $Script:ProgressPadWidth = 100

            # ANSI escape character (PowerShell 5.1 compatible - `e only works in PS7+)
            $esc = [char]0x1B
            $Script:CursorUp = "$esc[1A"
            $Script:CursorDown = "$esc[1B"

            # Helper function (defined in Script scope for catch block access)
            $Script:WriteCollectionStatus = {
                param([string]$Status, [int]$Step, [int]$Total, [switch]$Complete, [switch]$Init)
                $pw = $Script:ProgressPadWidth
                $up = $Script:CursorUp
                $dn = $Script:CursorDown
                if ($Init) {
                    # Print initial two lines (collected + active)
                    Write-Host "Collected: (starting...)".PadRight($pw) -NoNewline -ForegroundColor DarkGray
                    Write-Host ""
                    Write-Host "Collecting: $Status".PadRight($pw) -NoNewline
                } elseif ($Complete) {
                    # Clear both lines: clear active line, move up, clear collected line
                    Write-Host "`r$(' ' * $pw)" -NoNewline
                    Write-Host "$up`r$(' ' * $pw)$dn`r" -NoNewline
                    # Move cursor back up to the collected line for final output
                    Write-Host "$up`r" -NoNewline
                } else {
                    # Update both lines: move up to collected line, update it, move down, update active
                    $collectedLine = if ($Script:CollectedParts.Count -gt 0) {
                        "Collected: $($Script:CollectedParts -join ', ')"
                    } else {
                        "Collected: (starting...)"
                    }
                    $activeLine = "Collecting: $Status  [$Step/$Total]"
                    Write-Host "$up`r$($collectedLine.PadRight($pw))" -NoNewline -ForegroundColor DarkGray
                    Write-Host "$dn`r$($activeLine.PadRight($pw))" -NoNewline
                }
            }

            # Local wrapper functions
            function Write-CollectionStatus {
                param([string]$Status, [switch]$Complete, [switch]$Init)
                & $Script:WriteCollectionStatus -Status $Status -Step $currentStep -Total $totalSteps -Complete:$Complete -Init:$Init
            }
            function Add-CollectedPart {
                param([string]$Label, [int]$Count)
                if ($Count -gt 0) { $Script:CollectedParts.Add("$Count $Label") }
            }

            # Build caches for SPN resolution, DN-to-identity mapping, and ADCS template mapping
            Write-CollectionStatus -Init "Building caches..."
            Build-ComputerHostnameCache -ConnectionParams $connectionParams
            Build-DNIdentityCache -ConnectionParams $connectionParams
            if ($collectADCS) {
                Build-TemplateCNToOIDCache -ConnectionParams $connectionParams
            }

            # ----- Collect Domain -----
            if ($collectDomains) {
                $currentStep++
                Write-CollectionStatus "Domain..."
                $collectedData.Domains = @(Collect-BHDomain -DomainDN $domainDN -DomainSID $domainSID @connectionParams)
                Add-CollectedPart -Label "domains" -Count @($collectedData.Domains).Count
            }

            # ----- Collect Users -----
            if ($collectUsers) {
                $currentStep++
                Write-CollectionStatus "Users..."
                $collectedData.Users = @(Collect-BHUsers -DomainSID $domainSID -CollectACLs:$collectACLs @connectionParams)
                Add-CollectedPart -Label "users" -Count @($collectedData.Users).Count
            }

            # ----- Collect Groups -----
            if ($collectGroups) {
                $currentStep++
                Write-CollectionStatus "Groups..."
                $collectedData.Groups = @(Collect-BHGroups -DomainSID $domainSID -CollectACLs:$collectACLs @connectionParams)
                Add-CollectedPart -Label "groups" -Count @($collectedData.Groups).Count
            }

            # ----- Collect Computers -----
            if ($collectComputers) {
                $currentStep++
                Write-CollectionStatus "Computers..."
                $collectedData.Computers = @(Collect-BHComputers -DomainSID $domainSID -CollectACLs:$collectACLs @connectionParams)
                Add-CollectedPart -Label "computers" -Count @($collectedData.Computers).Count
            }

            # ----- Collect OUs -----
            if ($collectOUs) {
                $currentStep++
                Write-CollectionStatus "OUs..."
                $collectedData.OUs = @(Collect-BHOUs -DomainSID $domainSID -CollectACLs:$collectACLs @connectionParams)
                Add-CollectedPart -Label "OUs" -Count @($collectedData.OUs).Count
            }

            # ----- Collect Containers -----
            if ($collectContainers) {
                $currentStep++
                Write-CollectionStatus "Containers..."
                $collectedData.Containers = @(Collect-BHContainers -DomainSID $domainSID -CollectACLs:$collectACLs @connectionParams)
                Add-CollectedPart -Label "containers" -Count @($collectedData.Containers).Count
            }

            # ----- Collect GPOs -----
            if ($collectGPOs) {
                $currentStep++
                Write-CollectionStatus "GPOs..."
                $collectedData.GPOs = @(Collect-BHGPOs -DomainSID $domainSID -CollectACLs:$collectACLs @connectionParams)
                Add-CollectedPart -Label "GPOs" -Count @($collectedData.GPOs).Count
            }

            # ----- Collect ADCS Objects -----
            if ($collectADCS) {
                $currentStep++
                Write-CollectionStatus "Certificate Templates..."
                $collectedData.CertTemplates = @(Collect-BHCertTemplates -DomainSID $domainSID -CollectACLs:$collectACLs @connectionParams)

                $currentStep++
                Write-CollectionStatus "Enterprise CAs..."
                $collectedData.EnterpriseCAs = @(Collect-BHEnterpriseCAs -DomainSID $domainSID -CollectACLs:$collectACLs @connectionParams)

                $currentStep++
                Write-CollectionStatus "Root CAs..."
                $collectedData.RootCAs = @(Collect-BHRootCAs -DomainSID $domainSID -CollectACLs:$collectACLs @connectionParams)

                $currentStep++
                Write-CollectionStatus "AIA CAs..."
                $collectedData.AIACAs = @(Collect-BHAIACAs -DomainSID $domainSID -CollectACLs:$collectACLs @connectionParams)

                $currentStep++
                Write-CollectionStatus "NTAuth Stores..."
                $collectedData.NTAuthStores = @(Collect-BHNTAuthStores -DomainSID $domainSID -CollectACLs:$collectACLs @connectionParams)

                $currentStep++
                Write-CollectionStatus "Issuance Policies..."
                $collectedData.IssuancePolicies = @(Collect-BHIssuancePolicies -DomainSID $domainSID -CollectACLs:$collectACLs @connectionParams)

                # Add combined ADCS count
                $adcsTotal = @($collectedData.CertTemplates).Count + @($collectedData.EnterpriseCAs).Count +
                             @($collectedData.RootCAs).Count + @($collectedData.AIACAs).Count +
                             @($collectedData.NTAuthStores).Count + @($collectedData.IssuancePolicies).Count
                Add-CollectedPart -Label "ADCS objects" -Count $adcsTotal
            }

            # ----- Write JSON -----
            $currentStep++
            Write-CollectionStatus "Writing JSON..."

            # Write JSON Files

            $jsonFiles = @()

            if (@($collectedData.Users).Count -gt 0) {
                $usersFile = Join-Path $tempDir "$($Script:CollectionTimestamp)_users.json"
                Write-BHJsonFile -Data $collectedData.Users -Type "users" -FilePath $usersFile -PrettyPrint:$PrettyPrint
                $jsonFiles += $usersFile
            }

            if (@($collectedData.Groups).Count -gt 0) {
                $groupsFile = Join-Path $tempDir "$($Script:CollectionTimestamp)_groups.json"
                Write-BHJsonFile -Data $collectedData.Groups -Type "groups" -FilePath $groupsFile -PrettyPrint:$PrettyPrint
                $jsonFiles += $groupsFile
            }

            if (@($collectedData.Computers).Count -gt 0) {
                $computersFile = Join-Path $tempDir "$($Script:CollectionTimestamp)_computers.json"
                Write-BHJsonFile -Data $collectedData.Computers -Type "computers" -FilePath $computersFile -PrettyPrint:$PrettyPrint
                $jsonFiles += $computersFile
            }

            if (@($collectedData.Domains).Count -gt 0) {
                $domainsFile = Join-Path $tempDir "$($Script:CollectionTimestamp)_domains.json"
                Write-BHJsonFile -Data $collectedData.Domains -Type "domains" -FilePath $domainsFile -PrettyPrint:$PrettyPrint
                $jsonFiles += $domainsFile
            }

            if (@($collectedData.OUs).Count -gt 0) {
                $ousFile = Join-Path $tempDir "$($Script:CollectionTimestamp)_ous.json"
                Write-BHJsonFile -Data $collectedData.OUs -Type "ous" -FilePath $ousFile -PrettyPrint:$PrettyPrint
                $jsonFiles += $ousFile
            }

            if (@($collectedData.Containers).Count -gt 0) {
                $containersFile = Join-Path $tempDir "$($Script:CollectionTimestamp)_containers.json"
                Write-BHJsonFile -Data $collectedData.Containers -Type "containers" -FilePath $containersFile -PrettyPrint:$PrettyPrint
                $jsonFiles += $containersFile
            }

            if (@($collectedData.GPOs).Count -gt 0) {
                $gposFile = Join-Path $tempDir "$($Script:CollectionTimestamp)_gpos.json"
                Write-BHJsonFile -Data $collectedData.GPOs -Type "gpos" -FilePath $gposFile -PrettyPrint:$PrettyPrint
                $jsonFiles += $gposFile
            }

            if (@($collectedData.CertTemplates).Count -gt 0) {
                $certTemplatesFile = Join-Path $tempDir "$($Script:CollectionTimestamp)_certtemplates.json"
                Write-BHJsonFile -Data $collectedData.CertTemplates -Type "certtemplates" -FilePath $certTemplatesFile -PrettyPrint:$PrettyPrint
                $jsonFiles += $certTemplatesFile
            }

            if (@($collectedData.EnterpriseCAs).Count -gt 0) {
                $enterpriseCAsFile = Join-Path $tempDir "$($Script:CollectionTimestamp)_enterprisecas.json"
                Write-BHJsonFile -Data $collectedData.EnterpriseCAs -Type "enterprisecas" -FilePath $enterpriseCAsFile -PrettyPrint:$PrettyPrint
                $jsonFiles += $enterpriseCAsFile
            }

            if (@($collectedData.RootCAs).Count -gt 0) {
                $rootCAsFile = Join-Path $tempDir "$($Script:CollectionTimestamp)_rootcas.json"
                Write-BHJsonFile -Data $collectedData.RootCAs -Type "rootcas" -FilePath $rootCAsFile -PrettyPrint:$PrettyPrint
                $jsonFiles += $rootCAsFile
            }

            if (@($collectedData.AIACAs).Count -gt 0) {
                $aiaCAsFile = Join-Path $tempDir "$($Script:CollectionTimestamp)_aiacas.json"
                Write-BHJsonFile -Data $collectedData.AIACAs -Type "aiacas" -FilePath $aiaCAsFile -PrettyPrint:$PrettyPrint
                $jsonFiles += $aiaCAsFile
            }

            if (@($collectedData.NTAuthStores).Count -gt 0) {
                $ntAuthStoresFile = Join-Path $tempDir "$($Script:CollectionTimestamp)_ntauthstores.json"
                Write-BHJsonFile -Data $collectedData.NTAuthStores -Type "ntauthstores" -FilePath $ntAuthStoresFile -PrettyPrint:$PrettyPrint
                $jsonFiles += $ntAuthStoresFile
            }

            if (@($collectedData.IssuancePolicies).Count -gt 0) {
                $issuancePoliciesFile = Join-Path $tempDir "$($Script:CollectionTimestamp)_issuancepolicies.json"
                Write-BHJsonFile -Data $collectedData.IssuancePolicies -Type "issuancepolicies" -FilePath $issuancePoliciesFile -PrettyPrint:$PrettyPrint
                $jsonFiles += $issuancePoliciesFile
            }

            # Clear the active status line
            Write-CollectionStatus -Complete

            # Create ZIP or Copy Files
            if ($NoZip) {
                $outputDir = Split-Path $OutputPath -Parent
                if ([string]::IsNullOrEmpty($outputDir)) {
                    $outputDir = Get-Location
                }
                foreach ($file in $jsonFiles) {
                    Copy-Item -Path $file -Destination $outputDir -Force
                }
            }
            else {
                if (Test-Path $OutputPath -PathType Leaf) {
                    # Only delete if it's a file, not a directory
                    Remove-Item $OutputPath -Force
                }
                elseif (Test-Path $OutputPath -PathType Container) {
                    Write-Warning "OutputPath '$OutputPath' is a directory. Adding default filename."
                    $OutputPath = Join-Path $OutputPath "$($Script:CollectionTimestamp)_BloodHound.zip"
                }

                # Ensure output directory exists
                $outputDir = Split-Path $OutputPath -Parent
                if (-not [string]::IsNullOrEmpty($outputDir) -and -not (Test-Path $outputDir)) {
                    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
                }

                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir, $OutputPath)
            }

            # Cleanup temp directory
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue

            $totalObjects = @($collectedData.Users).Count + @($collectedData.Groups).Count + @($collectedData.Computers).Count +
                           @($collectedData.OUs).Count + @($collectedData.Containers).Count + @($collectedData.GPOs).Count +
                           @($collectedData.CertTemplates).Count + @($collectedData.EnterpriseCAs).Count +
                           @($collectedData.RootCAs).Count + @($collectedData.AIACAs).Count +
                           @($collectedData.NTAuthStores).Count + @($collectedData.IssuancePolicies).Count

            $summaryString = $Script:CollectedParts -join ", "

            Show-Line "Collected $totalObjects objects from $domainName`: $summaryString" -Class Hint -FindingId 'BLOODHOUND_COLLECTION_COMPLETE'

            if ($NoZip) {
                Show-Line "Output: $outputDir (JSON files)" -Class Note
            }
            else {
                $outputFileName = Split-Path $OutputPath -Leaf
                Show-Line "Output: $outputFileName" -Class Note
            }
        }
        catch {
            Write-Log "[Invoke-adPEASCollector] Collection failed: $_" -Level Error
            Write-Log $_.ScriptStackTrace
            # Clear the inline progress lines using Script-scope function
            if ($Script:WriteCollectionStatus) {
                & $Script:WriteCollectionStatus -Complete -Step 0 -Total 0
            }
            Write-Warning "[Invoke-adPEASCollector] BloodHound collection failed: $_"
        }
    }
    end {
        # Clean up caches to free memory
        $Script:DNToIdentityCache = $null
        $Script:ParentDNToChildren = $null
        $Script:ComputerHostnameCache = $null
        $Script:TemplateCNToOID = $null
        Write-Log "[Invoke-adPEASCollector] Collection completed"
    }
}

<#
.SYNOPSIS
    Safely gets an integer value from an AD property that might be an array or single value.
#>
function Get-SafeInt {
    param(
        $Value,
        [int]$Default = 0
    )

    if ($null -eq $Value) {
        return $Default
    }

    # If it's an array, take the first element
    if ($Value -is [array]) {
        $Value = $Value[0]
    }

    try {
        return [int]$Value
    }
    catch {
        Write-Log "[Get-SafeInt] Failed to convert value to int: $_" -Level Debug
        return $Default
    }
}


<#
.SYNOPSIS
    Converts various SID input formats to string representation.
.DESCRIPTION
    Handles SID input as byte array, string (SID format S-1-...), or SecurityIdentifier object.
#>
function Convert-SidToString {
    param(
        [Parameter(Mandatory=$true)]
        $SidInput
    )

    try {
        # Already a string in SID format
        if ($SidInput -is [string]) {
            if ($SidInput -match '^S-1-') {
                return $SidInput
            }
            # Try to parse as SecurityIdentifier from string
            return (New-Object System.Security.Principal.SecurityIdentifier($SidInput)).Value
        }

        # Byte array
        if ($SidInput -is [byte[]]) {
            return (New-Object System.Security.Principal.SecurityIdentifier($SidInput, 0)).Value
        }

        # SecurityIdentifier object
        if ($SidInput -is [System.Security.Principal.SecurityIdentifier]) {
            return $SidInput.Value
        }

        # Array of bytes (sometimes returned as object[])
        if ($SidInput -is [array]) {
            $bytes = [byte[]]$SidInput
            return (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value
        }

        # Fallback: try direct conversion
        return (New-Object System.Security.Principal.SecurityIdentifier($SidInput, 0)).Value
    }
    catch {
        Write-Log "[Convert-SidToString] Failed to convert SID: $_"
        return $null
    }
}


<#
.SYNOPSIS
    Converts PKI period byte array (FILETIME interval) to ISO 8601 duration string.
.DESCRIPTION
    PKI attributes like pKIExpirationPeriod and pKIOverlapPeriod are stored as 8-byte
    negative FILETIME intervals (100-nanosecond units). This function converts them to
    ISO 8601 duration strings for BloodHound CE (e.g., "P2Y", "P90D", "PT6H").
#>
function ConvertTo-ISODuration {
    param([byte[]]$PeriodBytes)

    if (-not $PeriodBytes -or $PeriodBytes.Length -ne 8) { return "P0D" }

    try {
        $int64Value = [BitConverter]::ToInt64($PeriodBytes, 0)
        $seconds = [Math]::Abs($int64Value) / 10000000

        if ($seconds -ge 31536000) {
            $years = [Math]::Floor($seconds / 31536000)
            return "P${years}Y"
        }
        elseif ($seconds -ge 86400) {
            $days = [Math]::Floor($seconds / 86400)
            return "P${days}D"
        }
        elseif ($seconds -ge 3600) {
            $hours = [Math]::Floor($seconds / 3600)
            return "PT${hours}H"
        }
        else {
            $minutes = [Math]::Floor($seconds / 60)
            if ($minutes -le 0) { $minutes = 1 }
            return "PT${minutes}M"
        }
    }
    catch {
        Write-Log "[ConvertTo-ISODuration] Error converting period bytes: $_" -Level Debug
        return "P0D"
    }
}


<#
.SYNOPSIS
    Parses X509 certificate properties from DER-encoded byte array.
.DESCRIPTION
    Extracts thumbprint, subject name, basic constraints and path length from a
    DER-encoded certificate (cACertificate attribute).
#>
function Get-CertificateProperties {
    param([byte[]]$CertificateBytes)

    $defaultResult = @{ Thumbprint = ""; Name = ""; HasBasicConstraints = $false; PathLength = 0 }

    if (-not $CertificateBytes -or $CertificateBytes.Length -eq 0) {
        return $defaultResult
    }

    try {
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$CertificateBytes)
        $thumbprint = $cert.Thumbprint
        $subject = $cert.Subject

        # Parse basic constraints extension
        $hasBC = $false
        $pathLen = 0
        foreach ($ext in $cert.Extensions) {
            if ($ext.Oid.Value -eq '2.5.29.19') {
                $hasBC = $true
                $bcExt = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]$ext
                if ($bcExt.HasPathLengthConstraint) {
                    $pathLen = $bcExt.PathLengthConstraint
                }
                break
            }
        }

        return @{
            Thumbprint          = $thumbprint
            Name                = $subject
            HasBasicConstraints = $hasBC
            PathLength          = $pathLen
        }
    }
    catch {
        Write-Log "[Get-CertificateProperties] Error parsing certificate: $_" -Level Debug
        return $defaultResult
    }
}


<#
.SYNOPSIS
    Builds a hostname-to-SID cache from all computer objects for efficient SPN resolution.
.DESCRIPTION
    Queries all domain computers once and caches dNSHostName/sAMAccountName to SID mappings.
    Used by Resolve-SPNToTarget for AllowedToDelegate and SPNTargets resolution.
#>
function Build-ComputerHostnameCache {
    param([hashtable]$ConnectionParams = @{})

    if ($Script:ComputerHostnameCache) { return }
    $Script:ComputerHostnameCache = @{}

    $computers = Get-DomainComputer -Properties sAMAccountName,dNSHostName,objectSid @ConnectionParams

    foreach ($comp in @($computers)) {
        if ($comp.objectSid) {
            $sid = Convert-SidToString -SidInput $comp.objectSid
            if ($sid) {
                if ($comp.dNSHostName) {
                    $Script:ComputerHostnameCache[$comp.dNSHostName.ToLower()] = $sid
                }
                if ($comp.sAMAccountName) {
                    $shortName = $comp.sAMAccountName.TrimEnd('$').ToLower()
                    $Script:ComputerHostnameCache[$shortName] = $sid
                }
            }
        }
    }

    Write-Log "[Build-ComputerHostnameCache] Cached $($Script:ComputerHostnameCache.Count) hostname-to-SID mappings"
}


<#
.SYNOPSIS
    Pre-builds DN-to-identity and parent-to-children caches for all domain objects.
.DESCRIPTION
    Performs a single bulk LDAP query to fetch all security-relevant objects with minimal
    properties and builds two lookup hashtables:
    - DNToIdentityCache: Maps DN to {ObjectIdentifier, ObjectType} for group member resolution
    - ParentDNToChildren: Maps parent DN to list of direct child identities for OU/Container child objects

    This eliminates the N+1 query anti-pattern where each OU/Container issued 4 separate
    subtree queries, and each group member required an individual LDAP lookup.
#>
function Build-DNIdentityCache {
    param([hashtable]$ConnectionParams = @{})

    if ($Script:DNToIdentityCache) { return }
    $Script:DNToIdentityCache = @{}
    $Script:ParentDNToChildren = @{}

    # Single bulk query: all security-relevant objects with minimal properties
    # objectClass=user also matches computers (AD class hierarchy: computer inherits from user)
    # Get-BHObjectType distinguishes via $ObjectClass[-1] (most specific class)
    $allObjects = Get-DomainObject -LDAPFilter "(|(objectClass=user)(objectClass=group)(objectClass=organizationalUnit)(objectClass=container)(objectClass=groupPolicyContainer))" `
        -Properties 'distinguishedName','objectSid','objectGuid','objectClass','name' @ConnectionParams

    foreach ($obj in @($allObjects)) {
        $dn = $obj.distinguishedName
        if (-not $dn) { continue }

        $objType = Get-BHObjectType -ObjectClass $obj.objectClass
        $objId = $null
        if ($obj.objectSid) {
            $objId = Convert-SidToString -SidInput $obj.objectSid
        } elseif ($obj.objectGuid) {
            $objId = $obj.objectGuid.ToString().ToUpper()
        }
        if (-not $objId) { continue }

        # DN -> Identity mapping (for group member resolution)
        $Script:DNToIdentityCache[$dn] = @{
            ObjectIdentifier = $objId
            ObjectType       = $objType
        }

        # Parent DN -> Children mapping (for OU/Container/Domain child objects)
        $parentDN = $dn -replace '^[^,]+,', ''
        if (-not $Script:ParentDNToChildren.ContainsKey($parentDN)) {
            $Script:ParentDNToChildren[$parentDN] = [System.Collections.Generic.List[hashtable]]::new()
        }
        $Script:ParentDNToChildren[$parentDN].Add(@{
            ObjectIdentifier = $objId
            ObjectType       = $objType
        })
    }

    Write-Log "[Build-DNIdentityCache] Cached $($Script:DNToIdentityCache.Count) objects, $($Script:ParentDNToChildren.Count) parent groups"
}


# Helper: Convert objectGUID (byte[] or Guid) to uppercase GUID string
function ConvertTo-BHGuid {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    try {
        if ($Value -is [byte[]] -and $Value.Length -eq 16) { return ([Guid]$Value).ToString().ToUpper() }
        if ($Value -is [array] -and $Value.Count -eq 16) { return ([Guid][byte[]]$Value).ToString().ToUpper() }
        return $Value.ToString().ToUpper()
    } catch { return "" }
}

# Helper: Convert AD negative 100-ns interval to human-readable string
# 0 or near-MaxValue = "Forever"
function Convert-ADIntervalToString {
    param([object]$Value)
    if ($null -eq $Value) { return "Forever" }
    try {
        $int64Val = [Int64]$Value
        if ($int64Val -eq 0) { return "Forever" }
        if ([Math]::Abs($int64Val) -ge 9223372036854775000) { return "Forever" }
        $seconds = [Math]::Abs($int64Val) / 10000000
        $ts = [TimeSpan]::FromSeconds($seconds)
        if ($ts.TotalDays -ge 1) {
            $d = [int]$ts.TotalDays
            return "$d day$(if ($d -ne 1) {'s'})"
        } elseif ($ts.TotalHours -ge 1) {
            $h = [int]$ts.TotalHours
            return "$h hour$(if ($h -ne 1) {'s'})"
        } else {
            $m = [int]$ts.TotalMinutes
            return "$m minute$(if ($m -ne 1) {'s'})"
        }
    } catch { return "Forever" }
}

# Helper: Convert ADCS certificate name flag integer to string (BH CE expects string, not int)
function Convert-CertNameFlagToString {
    param([int]$Value)
    return [string]$Value
}

# Helper: Convert ADCS enrollment flag integer to string (BH CE expects string, not int)
function Convert-EnrollFlagToString {
    param([int]$Value)
    return [string]$Value
}

# Helper: Convert CA flag integer to string (BH CE expects string, not int)
function Convert-CAFlagToString {
    param([int]$Value)
    return [string]$Value
}


# Helper: Get ContainedBy for objects in the Configuration partition
# Looks up the parent container's GUID via LDAP (one lookup per unique parent)
function Get-BHContainedByConfig {
    param([string]$DistinguishedName)
    if (-not $DistinguishedName) { return $null }
    if ($DistinguishedName -notmatch '^[^,]+,(.+)$') { return $null }
    $parentDN = $Matches[1]
    # Use a script-level cache to avoid repeated LDAP lookups
    if (-not $Script:ConfigContainerGuidCache) { $Script:ConfigContainerGuidCache = @{} }
    if ($Script:ConfigContainerGuidCache.ContainsKey($parentDN)) {
        $cachedGuid = $Script:ConfigContainerGuidCache[$parentDN]
        if ($cachedGuid) { return @{ ObjectIdentifier = $cachedGuid; ObjectType = 'Container' } }
        return $null
    }
    try {
        $parentObj = @(Invoke-LDAPSearch -Filter "(distinguishedName=$parentDN)" -SearchBase $parentDN -Properties objectGUID -Scope Base)[0]
        if ($parentObj -and $parentObj.objectGUID) {
            $guid = ConvertTo-BHGuid -Value $parentObj.objectGUID
            $Script:ConfigContainerGuidCache[$parentDN] = $guid
            if ($guid) { return @{ ObjectIdentifier = $guid; ObjectType = 'Container' } }
        }
    } catch { Write-Log "[Get-BHContainedByConfig] LDAP lookup failed for '$parentDN': $_" -Level Debug }
    $Script:ConfigContainerGuidCache[$parentDN] = ""
    return $null
}


<#
.SYNOPSIS
    Resolves an SPN to a computer SID using the pre-built hostname cache.
.DESCRIPTION
    Extracts the hostname from an SPN (format: service/hostname or service/hostname:port)
    and looks it up in the ComputerHostnameCache to find the computer SID.
#>
function Resolve-SPNToTarget {
    param([string]$SPN)

    if (-not $SPN -or -not $Script:ComputerHostnameCache) { return $null }

    # Extract hostname from SPN (service/hostname or service/hostname:port)
    if ($SPN -match '^[^/]+/([^:/]+)') {
        $hostname = $Matches[1].ToLower()

        # Try exact match on dNSHostName first
        if ($Script:ComputerHostnameCache.ContainsKey($hostname)) {
            return @{ ObjectIdentifier = $Script:ComputerHostnameCache[$hostname]; ObjectType = 'Computer' }
        }

        # Try short hostname (before first dot)
        $shortHost = ($hostname -split '\.')[0].ToLower()
        if ($Script:ComputerHostnameCache.ContainsKey($shortHost)) {
            return @{ ObjectIdentifier = $Script:ComputerHostnameCache[$shortHost]; ObjectType = 'Computer' }
        }
    }

    return $null
}


<#
.SYNOPSIS
    Builds a cache mapping certificate template CN names to their OID identifiers.
.DESCRIPTION
    BloodHound CE identifies certificate templates by their msPKI-Cert-Template-OID,
    while Enterprise CAs store published templates as CN names. This cache enables
    the CN-to-OID lookup needed for the EnabledCertTemplates relationship.
#>
function Build-TemplateCNToOIDCache {
    param([hashtable]$ConnectionParams = @{})

    $Script:TemplateCNToOID = @{}
    $configNC = $Script:LDAPContext.ConfigurationNamingContext

    if (-not $configNC) {
        Write-Log "[Build-TemplateCNToOIDCache] No Configuration NC available" -Level Debug
        return
    }

    $searchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

    try {
        $templates = Invoke-LDAPSearch -Filter "(objectClass=pKICertificateTemplate)" -SearchBase $searchBase -Properties cn,'msPKI-Cert-Template-OID' -Raw

        foreach ($t in @($templates)) {
            $cn = $null
            $oid = $null

            if ($t.cn) { $cn = if ($t.cn -is [array]) { $t.cn[0] } else { $t.cn } }
            if ($t.'msPKI-Cert-Template-OID') {
                $oid = if ($t.'msPKI-Cert-Template-OID' -is [array]) { $t.'msPKI-Cert-Template-OID'[0] } else { $t.'msPKI-Cert-Template-OID' }
            }

            if ($cn -and $oid) {
                # Raw byte arrays need string conversion
                if ($oid -is [byte[]]) {
                    $oid = [System.Text.Encoding]::UTF8.GetString($oid)
                }
                if ($cn -is [byte[]]) {
                    $cn = [System.Text.Encoding]::UTF8.GetString($cn)
                }
                $Script:TemplateCNToOID[$cn] = $oid
            }
        }
    }
    catch {
        Write-Log "[Build-TemplateCNToOIDCache] Error building cache: $_" -Level Debug
    }

    Write-Log "[Build-TemplateCNToOIDCache] Cached $($Script:TemplateCNToOID.Count) template CN-to-OID mappings"
}


<#
.SYNOPSIS
    Writes BloodHound-compatible JSON file.
#>
function Write-BHJsonFile {
    param(
        [array]$Data,
        [string]$Type,
        [string]$FilePath,
        [switch]$PrettyPrint
    )

    # Calculate meta.methods bitmask per entity type (SharpHound v6 collection method flags)
    $methodsBitmask = switch ($Type) {
        'users'            { 1 -bor 64 -bor 512 -bor 1024 }  # Group + ACL + ObjectProps + SPNTargets
        'groups'           { 1 -bor 64 -bor 512 }             # Group + ACL + ObjectProps
        'computers'        { 1 -bor 64 -bor 512 }             # Group + ACL + ObjectProps
        'domains'          { 32 -bor 64 -bor 128 -bor 512 }   # Trusts + ACL + Container + ObjectProps
        'ous'              { 64 -bor 128 }                     # ACL + Container
        'containers'       { 128 }                             # Container
        'gpos'             { 64 -bor 128 }                     # ACL + Container
        'certtemplates'    { 64 -bor 262144 }                  # ACL + CertServices
        'enterprisecas'    { 64 -bor 262144 }                  # ACL + CertServices
        'rootcas'          { 64 -bor 262144 }                  # ACL + CertServices
        'aiacas'           { 64 -bor 262144 }                  # ACL + CertServices
        'ntauthstores'     { 64 -bor 262144 }                  # ACL + CertServices
        'issuancepolicies' { 64 -bor 262144 }                  # ACL + CertServices
        default            { 0 }
    }

    $jsonObject = @{
        data = $Data
        meta = @{
            type    = $Type
            count   = @($Data).Count
            version = $Script:JsonVersion
            methods = $methodsBitmask
        }
    }

    # Use central Export-adPEASFile helper for consistent file handling
    # Default: compact JSON (smaller files, BH CE compatible); PrettyPrint is opt-in
    if ($PrettyPrint) {
        $exportResult = Export-adPEASFile -Path $FilePath -Content $jsonObject -Type Json -JsonDepth 20 -Force
    } else {
        $exportResult = Export-adPEASFile -Path $FilePath -Content $jsonObject -Type Json -JsonDepth 20 -Force -Compress
    }

    if (-not $exportResult.Success) {
        Write-Error "[Export-BloodHoundJson] Failed to export: $($exportResult.Message)"
    }
}


<#
.SYNOPSIS
    Converts Windows FILETIME to Unix timestamp.
#>
function ConvertTo-UnixTimestamp {
    param($FileTime)

    if ($null -eq $FileTime -or $FileTime -eq 0 -or $FileTime -eq 9223372036854775807) {
        return -1
    }

    try {
        # Handle DateTime objects directly
        if ($FileTime -is [DateTime]) {
            return [int64]($FileTime.ToUniversalTime() - [DateTime]::UnixEpoch).TotalSeconds
        }
        # Handle LDAP Generalized Time strings ("20220412123456.0Z")
        if ($FileTime -is [string] -and $FileTime.Length -ge 14) {
            $dt = [DateTime]::ParseExact($FileTime.Substring(0, 14), 'yyyyMMddHHmmss', [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
            return [int64]($dt.ToUniversalTime() - [DateTime]::UnixEpoch).TotalSeconds
        }
        # Handle Windows FILETIME (int64)
        $date = [DateTime]::FromFileTimeUtc($FileTime)
        return [int64]($date - [DateTime]::UnixEpoch).TotalSeconds
    }
    catch {
        Write-Log "[ConvertTo-UnixTimestamp] Failed to convert FileTime: $_" -Level Debug
        return -1
    }
}


<#
.SYNOPSIS
    Gets the BloodHound object type string from an AD object.
#>
function Get-BHObjectType {
    param($ObjectClass)

    if ($ObjectClass -is [array]) {
        $ObjectClass = $ObjectClass[-1]  # Last element is most specific
    }

    switch -Regex ($ObjectClass) {
        'user'                  { return 'User' }
        'computer'              { return 'Computer' }
        'group'                 { return 'Group' }
        'organizationalUnit'    { return 'OU' }
        'container'             { return 'Container' }
        'groupPolicyContainer'  { return 'GPO' }
        'domain'                { return 'Domain' }
        'trustedDomain'         { return 'Domain' }
        default                 { return 'Base' }
    }
}


<#
.SYNOPSIS
    Converts ACEs to BloodHound format with full DCOnly edge support.
.DESCRIPTION
    Parses nTSecurityDescriptor and extracts all BloodHound-compatible edges:
    - Owns (Owner has implicit GenericAll)
    - GenericAll, GenericWrite, WriteDacl, WriteOwner
    - DCSync rights (GetChanges, GetChangesAll, GetChangesInFilteredSet)
    - ForceChangePassword, AddMember, AddSelf
    - WriteSPN (servicePrincipalName write)
    - AddKeyCredentialLink (msDS-KeyCredentialLink write)
    - AllowedToAct (msDS-AllowedToActOnBehalfOfOtherIdentity write)
    - ReadLAPSPassword (ms-Mcs-AdmPwd read)
    - ReadGMSAPassword (msDS-GroupMSAMembership read)
    - AllExtendedRights
    - WriteAccountRestrictions (userAccountControl write)
#>
function ConvertTo-BHAces {
    param(
        [string]$DistinguishedName,
        [string]$ObjectType = 'Base',
        [hashtable]$ConnectionParams = @{}
    )

    $bhAces = @()

    # Initialize BloodHound GUID mappings (only once per session)
    if (-not $Script:BHPropertyGUIDs) {
        # Well-known property GUIDs for WriteProperty edges
        $Script:BHPropertyGUIDs = @{
            # WriteSPN - servicePrincipalName
            'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'WriteSPN'
            # AddKeyCredentialLink - msDS-KeyCredentialLink
            '5b47d60f-6090-40b2-9f37-2a4de88f3063' = 'AddKeyCredentialLink'
            # AllowedToAct - msDS-AllowedToActOnBehalfOfOtherIdentity
            '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' = 'AddAllowedToAct'
            # WriteAccountRestrictions - userAccountControl
            '4c164200-20c0-11d0-a768-00aa006e0529' = 'WriteAccountRestrictions'
            # Member (group membership)
            'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'AddMember'
            # GPLink
            'f30e3bbe-9ff0-11d1-b603-0000f80367c1' = 'WriteGPLink'
            # ADCS: msPKI-Enrollment-Flag write
            'd15ef7d8-f226-46db-ae79-b34e560bd12c' = 'WritePKIEnrollmentFlag'
            # ADCS: msPKI-Certificate-Name-Flag write
            'ea1dddc4-60ff-416e-8cc0-17cee534bce7' = 'WritePKINameFlag'
        }

        # Extended rights GUIDs
        $Script:BHExtendedRightGUIDs = @{
            # DCSync rights
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'GetChanges'
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'GetChangesAll'
            '89e95b76-444d-4c62-991a-0facbeda640c' = 'GetChangesInFilteredSet'
            # User password reset
            '00299570-246d-11d0-a768-00aa006e0529' = 'ForceChangePassword'
            # LAPS password read
            'e362ed86-b728-0842-b27d-2dea7a9df218' = 'ReadLAPSPassword'
            # All extended rights
            '00000000-0000-0000-0000-000000000000' = 'AllExtendedRights'
            # ADCS: Certificate-Enrollment
            '0e10c968-78fb-11d2-90d4-00c04f79dc55' = 'Enroll'
            # ADCS: Certificate-AutoEnrollment
            'a05b8cc2-17bc-4802-a710-e7c15ab866a2' = 'AutoEnroll'
            # ADCS: ManageCA (CA admin right)
            'ee138f32-c3ec-11d1-bbc5-0080c76670c0' = 'ManageCA'
            # ADCS: ManageCertificates (CA officer right)
            '98291c0c-7fd7-11d2-9917-00c04fc2d4cf' = 'ManageCertificates'
        }

        # GMSA password read - special handling via GenericAll on msDS-GroupManagedServiceAccount
        $Script:BHGMSAReadGUID = '5b47d60f-6090-40b2-9f37-2a4de88f3063'
    }

    try {
        # Get the object with nTSecurityDescriptor and GMSA membership attribute
        # IMPORTANT: Use -Raw to get nTSecurityDescriptor as byte[] instead of converted ACL
        # Escape DN for LDAP filter to prevent injection (RFC 4515)
        $escapedDN = Escape-LDAPFilterDN -DistinguishedName $DistinguishedName
        $adObject = @(Get-DomainObject -LDAPFilter "(distinguishedName=$escapedDN)" -Properties nTSecurityDescriptor,objectClass,'msDS-GroupMSAMembership' -Raw @ConnectionParams)[0]

        if (-not $adObject -or -not $adObject.nTSecurityDescriptor) {
            return $bhAces
        }

        # ===== GMSA PASSWORD READ EDGE =====
        # msDS-GroupMSAMembership contains a security descriptor that defines who can read the password
        if ($adObject.'msDS-GroupMSAMembership') {
            try {
                $gmsaSD = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $gmsaSD.SetSecurityDescriptorBinaryForm($adObject.'msDS-GroupMSAMembership')
                $gmsaDACL = $gmsaSD.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

                foreach ($gmsaAce in $gmsaDACL) {
                    if ($gmsaAce.AccessControlType -eq 'Allow') {
                        $gmsaTrusteeSID = $gmsaAce.IdentityReference.Value

                        # Skip system principals
                        if ($gmsaTrusteeSID -notin @('S-1-5-18', 'S-1-3-0', 'S-1-5-10')) {
                            $bhAces += @{
                                PrincipalSID  = $gmsaTrusteeSID
                                PrincipalType = Get-BHPrincipalType -SID $gmsaTrusteeSID
                                RightName     = 'ReadGMSAPassword'
                                IsInherited   = $false
                            }
                        }
                    }
                }
            }
            catch {
                Write-Log "[ConvertTo-BHAces] Error parsing GMSA membership for $DistinguishedName : $_"
            }
        }

        # Parse security descriptor
        $RawSD = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $RawSD.SetSecurityDescriptorBinaryForm($adObject.nTSecurityDescriptor)

        # ===== OWNS EDGE =====
        # Owner has implicit GenericAll equivalent
        $ownerSID = $RawSD.GetOwner([System.Security.Principal.SecurityIdentifier]).Value

        # Skip only non-actionable system owners
        # Domain Admins/Enterprise Admins ownership IS valuable for attack path analysis
        $skipOwners = @(
            'S-1-5-18',          # SYSTEM (not user-controllable)
            'S-1-3-0',           # Creator Owner (placeholder)
            'S-1-5-10'           # Self (placeholder)
        )

        if ($ownerSID -and $ownerSID -notin $skipOwners) {
            $bhAces += @{
                PrincipalSID  = $ownerSID
                PrincipalType = Get-BHPrincipalType -SID $ownerSID
                RightName     = 'Owns'
                IsInherited   = $false
            }
        }

        # ===== DACL EDGES =====
        $DACL = $RawSD.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        foreach ($ace in $DACL) {
            # Only process Allow ACEs
            if ($ace.AccessControlType -ne 'Allow') { continue }

            $trusteeSID = $ace.IdentityReference.Value

            # Filter principals that create noise without attack value
            $skipPrincipals = @(
                'S-1-3-0',       # Creator Owner (placeholder, not actionable)
                'S-1-5-10',      # Self (placeholder, not actionable)
                'S-1-5-18'       # SYSTEM (not user-controllable, no attack path)
            )
            if ($trusteeSID -in $skipPrincipals) { continue }

            $principalType = Get-BHPrincipalType -SID $trusteeSID
            $adRights = $ace.ActiveDirectoryRights
            $objectTypeGuid = if ($ace.ObjectType -and $ace.ObjectType -ne [System.Guid]::Empty) {
                $ace.ObjectType.ToString().ToLower()
            } else { $null }

            $isInherited = $ace.IsInherited

            # ----- GenericAll -----
            if (($adRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) {
                $bhAces += @{
                    PrincipalSID  = $trusteeSID
                    PrincipalType = $principalType
                    RightName     = 'GenericAll'
                    IsInherited   = $isInherited
                }
                continue  # GenericAll encompasses everything, skip other checks
            }

            # ----- GenericWrite -----
            if (($adRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -eq [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) {
                $bhAces += @{
                    PrincipalSID  = $trusteeSID
                    PrincipalType = $principalType
                    RightName     = 'GenericWrite'
                    IsInherited   = $isInherited
                }
            }

            # ----- WriteDacl -----
            if (($adRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) {
                $bhAces += @{
                    PrincipalSID  = $trusteeSID
                    PrincipalType = $principalType
                    RightName     = 'WriteDacl'
                    IsInherited   = $isInherited
                }
            }

            # ----- WriteOwner -----
            if (($adRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) {
                $bhAces += @{
                    PrincipalSID  = $trusteeSID
                    PrincipalType = $principalType
                    RightName     = 'WriteOwner'
                    IsInherited   = $isInherited
                }
            }

            # ----- WriteProperty (property-specific edges) -----
            if (($adRights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -eq [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) {
                if ($objectTypeGuid) {
                    # Check for known property GUIDs
                    if ($Script:BHPropertyGUIDs.ContainsKey($objectTypeGuid)) {
                        $rightName = $Script:BHPropertyGUIDs[$objectTypeGuid]
                        $bhAces += @{
                            PrincipalSID  = $trusteeSID
                            PrincipalType = $principalType
                            RightName     = $rightName
                            IsInherited   = $isInherited
                        }
                    }
                }
                else {
                    # WriteProperty with no ObjectType = write all properties
                    # This is similar to GenericWrite for attack purposes
                    # Add specific edges based on object type
                    if ($ObjectType -eq 'User') {
                        $bhAces += @{ PrincipalSID = $trusteeSID; PrincipalType = $principalType; RightName = 'WriteSPN'; IsInherited = $isInherited }
                        $bhAces += @{ PrincipalSID = $trusteeSID; PrincipalType = $principalType; RightName = 'AddKeyCredentialLink'; IsInherited = $isInherited }
                    }
                    elseif ($ObjectType -eq 'Computer') {
                        $bhAces += @{ PrincipalSID = $trusteeSID; PrincipalType = $principalType; RightName = 'AddAllowedToAct'; IsInherited = $isInherited }
                        $bhAces += @{ PrincipalSID = $trusteeSID; PrincipalType = $principalType; RightName = 'AddKeyCredentialLink'; IsInherited = $isInherited }
                    }
                    elseif ($ObjectType -eq 'Group') {
                        $bhAces += @{ PrincipalSID = $trusteeSID; PrincipalType = $principalType; RightName = 'AddMember'; IsInherited = $isInherited }
                    }
                }
            }

            # ----- Self (AddSelf for groups) -----
            if (($adRights -band [System.DirectoryServices.ActiveDirectoryRights]::Self) -eq [System.DirectoryServices.ActiveDirectoryRights]::Self) {
                if ($ObjectType -eq 'Group') {
                    $bhAces += @{
                        PrincipalSID  = $trusteeSID
                        PrincipalType = $principalType
                        RightName     = 'AddSelf'
                        IsInherited   = $isInherited
                    }
                }
            }

            # ----- ExtendedRight -----
            if (($adRights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -eq [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
                if ($objectTypeGuid) {
                    # Check for known extended rights
                    if ($Script:BHExtendedRightGUIDs.ContainsKey($objectTypeGuid)) {
                        $rightName = $Script:BHExtendedRightGUIDs[$objectTypeGuid]
                        $bhAces += @{
                            PrincipalSID  = $trusteeSID
                            PrincipalType = $principalType
                            RightName     = $rightName
                            IsInherited   = $isInherited
                        }
                    }
                }
                else {
                    # ExtendedRight with no ObjectType = AllExtendedRights
                    $bhAces += @{
                        PrincipalSID  = $trusteeSID
                        PrincipalType = $principalType
                        RightName     = 'AllExtendedRights'
                        IsInherited   = $isInherited
                    }
                }
            }

            # ----- ReadProperty for LAPS -----
            if (($adRights -band [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty) -eq [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty) {
                if ($objectTypeGuid -eq 'e362ed86-b728-0842-b27d-2dea7a9df218') {
                    $bhAces += @{
                        PrincipalSID  = $trusteeSID
                        PrincipalType = $principalType
                        RightName     = 'ReadLAPSPassword'
                        IsInherited   = $isInherited
                    }
                }
            }
        }
    }
    catch {
        Write-Log "[ConvertTo-BHAces] Error processing ACLs for $DistinguishedName : $_"
    }

    # Remove duplicates
    $uniqueAces = @()
    $seen = @{}
    foreach ($ace in $bhAces) {
        $key = "$($ace.PrincipalSID)|$($ace.RightName)"
        if (-not $seen.ContainsKey($key)) {
            $seen[$key] = $true
            $uniqueAces += $ace
        }
    }

    return $uniqueAces
}


<#
.SYNOPSIS
    Determines the BloodHound principal type from a SID.
#>
function Get-BHPrincipalType {
    param([string]$SID)

    if (-not $SID) { return 'Base' }

    # Well-known group SIDs
    if ($SID -match '^S-1-5-32-') { return 'Group' }  # Builtin groups

    # Domain SID patterns
    if ($SID -match '-5\d{2}$') {
        # RIDs 500-599 are typically users/computers
        $rid = [int]($SID -split '-')[-1]
        if ($rid -eq 500 -or $rid -eq 501 -or $rid -eq 502) {
            return 'User'  # Administrator, Guest, krbtgt
        }
        elseif ($rid -ge 512 -and $rid -le 527) {
            return 'Group'  # Domain groups (DA, DU, DC, etc.)
        }
    }

    # Computer accounts end with $ in name, but we check RID pattern
    # RID >= 1000 and ends with even number often computer, odd often user
    # This is a heuristic - not 100% accurate without LDAP lookup
    if ($SID -match '-\d{4,}$') {
        $rid = [int]($SID -split '-')[-1]
        if ($rid -ge 1000) {
            # Could be user, computer, or group - default to Base
            return 'Base'
        }
    }

    return 'Base'
}


<#
.SYNOPSIS
    Collects domain information in BloodHound format.
#>
function Collect-BHDomain {
    param(
        [string]$DomainDN,
        [string]$DomainSID,
        [string]$Domain,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionParams = @{}
    if ($Domain) { $connectionParams['Domain'] = $Domain }
    if ($Server) { $connectionParams['Server'] = $Server }
    if ($Credential) { $connectionParams['Credential'] = $Credential }

    # Escape DN for LDAP filter to prevent injection (RFC 4515)
    $escapedDomainDN = Escape-LDAPFilterDN -DistinguishedName $DomainDN
    $domainObj = @(Get-DomainObject -LDAPFilter "(distinguishedName=$escapedDomainDN)" @connectionParams)[0]

    if (-not $domainObj) { return @() }

    $domainName = $Script:LDAPContext.Domain.ToUpper()

    # Get functional level
    # Note: Windows Server 2019 does not have its own functional level (uses 2016 level = 7)
    $functionalLevel = switch ($domainObj.'msDS-Behavior-Version') {
        0       { '2000' }
        1       { '2003 Interim' }
        2       { '2003' }
        3       { '2008' }
        4       { '2008 R2' }
        5       { '2012' }
        6       { '2012 R2' }
        7       { '2016' }
        10      { '2025' }
        default { 'Unknown' }
    }

    # Query NetBIOS name from Partitions container
    $netbiosName = ""
    $configNC = $Script:LDAPContext.ConfigurationNamingContext
    if ($configNC) {
        try {
            $partitionsBase = "CN=Partitions,$configNC"
            $crossRef = @(Invoke-LDAPSearch -Filter "(&(objectClass=crossRef)(nCName=$DomainDN))" -SearchBase $partitionsBase -Properties nETBIOSName -Scope OneLevel @connectionParams)[0]
            if ($crossRef -and $crossRef.nETBIOSName) { $netbiosName = $crossRef.nETBIOSName }
        } catch { Write-Log "[Collect-BHDomain] NetBIOS name lookup failed: $_" -Level Debug }
    }

    # Get trusts
    $trusts = @()
    $trustObjects = Get-DomainObject -LDAPFilter "(objectClass=trustedDomain)" @connectionParams

    foreach ($trust in $trustObjects) {
        # trustDirection, trustType and trustAttributes are pre-decoded by Invoke-LDAPSearch
        # Reverse-map strings back to integers for BloodHound CE JSON format
        $trustDirInt = switch ($trust.trustDirection) {
            'Disabled'      { 0 }
            'Inbound'       { 1 }
            'Outbound'      { 2 }
            'Bidirectional' { 3 }
            default         { 0 }
        }

        $trustTypeInt = switch ($trust.trustType) {
            'Windows NT (Downlevel)'      { 1 }
            'Active Directory (Uplevel)'  { 2 }
            'MIT Kerberos Realm'          { 3 }
            'DCE'                         { 4 }
            default                       { 2 }
        }

        # trustAttributes is a string array of flag names
        $attrFlags = @($trust.trustAttributes)

        $trusts += @{
            TargetDomainSid     = if ($trust.securityIdentifier) { Convert-SidToString -SidInput $trust.securityIdentifier } else { "" }
            TargetDomainName    = if ($trust.name) { $trust.name.ToUpper() } else { "" }
            IsTransitive        = ($attrFlags -notcontains 'NON_TRANSITIVE')
            TrustDirection      = $trustDirInt
            TrustType           = $trustTypeInt
            SidFilteringEnabled = ($attrFlags -contains 'QUARANTINED_DOMAIN')
        }
    }

    # Get child objects from pre-built DN identity cache (O(1) lookup)
    $childObjects = @()
    if ($Script:ParentDNToChildren -and $Script:ParentDNToChildren.ContainsKey($DomainDN)) {
        $childObjects = @($Script:ParentDNToChildren[$DomainDN])
    }

    # Get GPO links
    $gpoLinks = @()
    if ($domainObj.gPLink) {
        $gpLinkString = $domainObj.gPLink
        $linkMatches = [regex]::Matches($gpLinkString, '\[LDAP://([^\]]+);(\d)\]')
        foreach ($match in $linkMatches) {
            $gpoDN = $match.Groups[1].Value
            $enforced = $match.Groups[2].Value -eq '2'

            # Get GPO GUID
            if ($gpoDN -match '\{([A-Fa-f0-9-]+)\}') {
                $gpoGuid = $Matches[1].ToUpper()
                $gpoLinks += @{
                    GUID       = $gpoGuid
                    IsEnforced = $enforced
                }
            }
        }
    }

    return @{
        ObjectIdentifier     = $DomainSID
        ForestRootIdentifier = $DomainSID
        Properties           = @{
            name                                    = $domainName
            domain                                  = $domainName
            domainsid                               = $DomainSID
            distinguishedname                       = $DomainDN
            description                             = if ($domainObj.description) { $domainObj.description } else { $null }
            functionallevel                         = $functionalLevel
            highvalue                               = $true
            whencreated                             = ConvertTo-UnixTimestamp $domainObj.whenCreated
            objectguid                              = ConvertTo-BHGuid -Value $domainObj.objectGUID
            isaclprotected                          = $false
            doesanyacegrantownerrights              = $false
            doesanyinheritedacegrantownerrights     = $false
            collected                               = $true
            netbios                                 = $netbiosName
            dsheuristics                            = if ($domainObj.dSHeuristics) { $domainObj.dSHeuristics } else { $null }
            expirepasswordsonsmartcardonlyaccounts  = if ($domainObj.'msDS-ExpirePasswordsOnSmartCardOnlyAccounts') { [bool]$domainObj.'msDS-ExpirePasswordsOnSmartCardOnlyAccounts' } else { $false }
            machineaccountquota                     = Get-SafeInt -Value $domainObj.'ms-DS-MachineAccountQuota' -Default 10
            lockoutthreshold                        = Get-SafeInt -Value $domainObj.lockoutThreshold -Default 0
            minpwdlength                            = Get-SafeInt -Value $domainObj.minPwdLength -Default 0
            pwdhistorylength                        = Get-SafeInt -Value $domainObj.pwdHistoryLength -Default 0
            pwdproperties                           = Get-SafeInt -Value $domainObj.pwdProperties -Default 0
            lockoutduration                         = Convert-ADIntervalToString -Value $domainObj.lockoutDuration
            lockoutobservationwindow                = if ($domainObj.lockOutObservationWindow) { [Int64]$domainObj.lockOutObservationWindow } else { 0 }
            maxpwdage                               = Convert-ADIntervalToString -Value $domainObj.maxPwdAge
            minpwdage                               = Convert-ADIntervalToString -Value $domainObj.minPwdAge
        }
        Trusts           = $trusts
        ChildObjects     = $childObjects
        Links            = $gpoLinks
        Aces             = @(ConvertTo-BHAces -DistinguishedName $DomainDN -ObjectType 'Domain' @connectionParams)
        IsDeleted        = $false
    }
}


<#
.SYNOPSIS
    Collects user objects in BloodHound format.
#>
function Collect-BHUsers {
    param(
        [string]$DomainSID,
        [switch]$CollectACLs,
        [string]$Domain,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionParams = @{}
    if ($Domain) { $connectionParams['Domain'] = $Domain }
    if ($Server) { $connectionParams['Server'] = $Server }
    if ($Credential) { $connectionParams['Credential'] = $Credential }

    $domainName = $Script:LDAPContext.Domain.ToUpper()
    $users = Get-DomainUser @connectionParams

    $bhUsers = @()

    foreach ($user in $users) {
        $sid = $null
        if ($user.objectSid) {
            $sid = Convert-SidToString -SidInput $user.objectSid
            if (-not $sid) {
                Write-Log "[Collect-BHUsers] Failed to parse SID for $($user.sAMAccountName)"
                continue
            }
        }
        else {
            continue
        }

        $uac = Get-SafeInt -Value $user.userAccountControl -Default 0

        # Parse SPNs
        $spns = @()
        if ($user.servicePrincipalName) {
            if ($user.servicePrincipalName -is [array]) {
                $spns = $user.servicePrincipalName
            }
            else {
                $spns = @($user.servicePrincipalName)
            }
        }

        # Parse SID history
        $sidHistory = @()
        if ($user.sIDHistory) {
            $historyItems = if ($user.sIDHistory -is [array]) { $user.sIDHistory } else { @($user.sIDHistory) }
            foreach ($histSid in $historyItems) {
                $convertedSid = Convert-SidToString -SidInput $histSid
                if ($convertedSid) {
                    $sidHistory += $convertedSid
                }
            }
        }
        # HasSIDHistory is a TypedPrincipal array (BH CE expects []ein.TypedPrincipal, not bool)
        $sidHistoryTyped = @($sidHistory | ForEach-Object { @{ ObjectIdentifier = $_; ObjectType = 'User' } })

        # Parse allowed to delegate (resolve SPNs to computer SIDs)
        $allowedToDelegate = @()
        if ($user.'msDS-AllowedToDelegateTo') {
            $delegateTargets = $user.'msDS-AllowedToDelegateTo'
            if ($delegateTargets -isnot [array]) { $delegateTargets = @($delegateTargets) }
            foreach ($target in $delegateTargets) {
                $resolved = Resolve-SPNToTarget -SPN $target
                if ($resolved) {
                    $allowedToDelegate += $resolved
                } else {
                    $allowedToDelegate += @{ ObjectIdentifier = $target; ObjectType = 'Computer' }
                }
            }
        }

        # Parse SPNTargets (resolve user SPNs to target computers)
        $spnTargets = @()
        foreach ($spn in $spns) {
            $resolved = Resolve-SPNToTarget -SPN $spn
            if ($resolved) {
                $port = 0
                if ($spn -match ':(\d+)') { $port = [int]$Matches[1] }
                $spnTargets += @{
                    ObjectIdentifier = $resolved.ObjectIdentifier
                    ObjectType       = $resolved.ObjectType
                    Port             = $port
                }
            }
        }

        # Get primary group SID
        $primaryGroupRid = Get-SafeInt -Value $user.primaryGroupID -Default 513
        $primaryGroupSID = "$DomainSID-$primaryGroupRid"

        $bhUser = @{
            ObjectIdentifier   = $sid
            Properties         = @{
                name                    = "$($user.sAMAccountName)@$domainName"
                domain                  = $domainName
                domainsid               = $DomainSID
                distinguishedname       = $user.distinguishedName
                highvalue               = $false
                samaccountname          = $user.sAMAccountName
                description             = if ($user.description) { $user.description } else { $null }
                whencreated             = ConvertTo-UnixTimestamp $user.whenCreated
                sensitive               = ($uac -band 0x100000) -ne 0  # NOT_DELEGATED
                dontreqpreauth          = ($uac -band 0x400000) -ne 0  # DONT_REQ_PREAUTH
                passwordnotreqd         = ($uac -band 0x20) -ne 0     # PASSWD_NOTREQD
                unconstraineddelegation = ($uac -band 0x80000) -ne 0  # TRUSTED_FOR_DELEGATION
                pwdneverexpires         = ($uac -band 0x10000) -ne 0  # DONT_EXPIRE_PASSWORD
                enabled                 = ($uac -band 0x2) -eq 0      # ACCOUNTDISABLE
                trustedtoauth           = ($uac -band 0x1000000) -ne 0 # TRUSTED_TO_AUTH_FOR_DELEGATION
                lastlogon               = ConvertTo-UnixTimestamp $user.lastLogon
                lastlogontimestamp      = ConvertTo-UnixTimestamp $user.lastLogonTimestamp
                pwdlastset              = ConvertTo-UnixTimestamp $user.pwdLastSet
                serviceprincipalnames   = $spns
                hasspn                  = @($spns).Count -gt 0
                displayname             = $user.displayName
                email                   = $user.mail
                title                   = $user.title
                homedirectory           = $user.homeDirectory
                userpassword            = $null
                unixpassword            = $null
                unicodepassword         = $null
                sfupassword             = $null
                logonscript                         = $user.scriptPath
                admincount                          = (Get-SafeInt -Value $user.adminCount) -gt 0
                sidhistory                          = $sidHistory
                objectguid                          = ConvertTo-BHGuid -Value $user.objectGUID
                isaclprotected                      = $false
                doesanyacegrantownerrights          = $false
                doesanyinheritedacegrantownerrights = $false
                encryptedtextpwdallowed             = ($uac -band 0x80) -ne 0
                logonscriptenabled                  = ($uac -band 0x1) -ne 0
                usedeskeyonly                       = ($uac -band 0x200000) -ne 0
                profilepath                         = if ($user.profilePath) { $user.profilePath } else { $null }
                supportedencryptiontypes            = $null
            }
            PrimaryGroupSID    = $primaryGroupSID
            AllowedToDelegate  = $allowedToDelegate
            HasSIDHistory           = $sidHistoryTyped
            SPNTargets         = $spnTargets
            Aces               = @()
            IsDeleted          = $false
        }

        # Collect ACLs if requested
        if ($CollectACLs) {
            $bhUser.Aces = @(ConvertTo-BHAces -DistinguishedName $user.distinguishedName -ObjectType 'User' @connectionParams)
        }

        $bhUsers += $bhUser
    }

    return $bhUsers
}


<#
.SYNOPSIS
    Collects group objects in BloodHound format.
#>
function Collect-BHGroups {
    param(
        [string]$DomainSID,
        [switch]$CollectACLs,
        [string]$Domain,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionParams = @{}
    if ($Domain) { $connectionParams['Domain'] = $Domain }
    if ($Server) { $connectionParams['Server'] = $Server }
    if ($Credential) { $connectionParams['Credential'] = $Credential }

    $domainName = $Script:LDAPContext.Domain.ToUpper()
    $groups = Get-DomainGroup @connectionParams

    $bhGroups = @()

    foreach ($group in $groups) {
        $sid = $null
        if ($group.objectSid) {
            $sid = Convert-SidToString -SidInput $group.objectSid
            if (-not $sid) {
                Write-Log "[Collect-BHGroups] Failed to parse SID for $($group.sAMAccountName)"
                continue
            }
        }
        else {
            continue
        }

        # High-value groups
        $highValueRids = @('-512', '-519', '-518', '-516', '-498', '-500')
        $highValue = $false
        foreach ($rid in $highValueRids) {
            if ($sid.EndsWith($rid)) {
                $highValue = $true
                break
            }
        }

        # Parse members using DN identity cache (O(1) per member)
        $members = @()
        if ($group.member) {
            $memberDNs = if ($group.member -is [array]) { $group.member } else { @($group.member) }

            foreach ($memberDN in $memberDNs) {
                if ($Script:DNToIdentityCache -and $Script:DNToIdentityCache.ContainsKey($memberDN)) {
                    $members += $Script:DNToIdentityCache[$memberDN]
                } else {
                    # Fallback for cache misses (cross-domain members, deleted objects)
                    $escapedMemberDN = Escape-LDAPFilterDN -DistinguishedName $memberDN
                    $memberObj = @(Get-DomainObject -LDAPFilter "(distinguishedName=$escapedMemberDN)" -Properties objectSid,objectClass @connectionParams)[0]

                    if ($memberObj -and $memberObj.objectSid) {
                        $memberSID = Convert-SidToString -SidInput $memberObj.objectSid
                        if ($memberSID) {
                            $members += @{
                                ObjectIdentifier = $memberSID
                                ObjectType       = Get-BHObjectType -ObjectClass $memberObj.objectClass
                            }
                        }
                    }
                }
            }
        }

        $bhGroup = @{
            ObjectIdentifier = $sid
            Properties       = @{
                name              = "$($group.sAMAccountName)@$domainName"
                domain            = $domainName
                domainsid         = $DomainSID
                distinguishedname = $group.distinguishedName
                highvalue         = $highValue
                samaccountname    = $group.sAMAccountName
                description       = if ($group.description) { $group.description } else { $null }
                whencreated                         = ConvertTo-UnixTimestamp $group.whenCreated
                admincount                          = (Get-SafeInt -Value $group.adminCount) -gt 0
                objectguid                          = ConvertTo-BHGuid -Value $group.objectGUID
                isaclprotected                      = $false
                doesanyacegrantownerrights          = $false
                doesanyinheritedacegrantownerrights = $false
            }
            Members          = $members
            Aces             = @()
            IsDeleted        = $false
        }

        # Collect ACLs if requested
        if ($CollectACLs) {
            $bhGroup.Aces = @(ConvertTo-BHAces -DistinguishedName $group.distinguishedName -ObjectType 'Group' @connectionParams)
        }

        $bhGroups += $bhGroup
    }

    return $bhGroups
}


<#
.SYNOPSIS
    Collects computer objects in BloodHound format.
#>
function Collect-BHComputers {
    param(
        [string]$DomainSID,
        [switch]$CollectACLs,
        [string]$Domain,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionParams = @{}
    if ($Domain) { $connectionParams['Domain'] = $Domain }
    if ($Server) { $connectionParams['Server'] = $Server }
    if ($Credential) { $connectionParams['Credential'] = $Credential }

    $domainName = $Script:LDAPContext.Domain.ToUpper()

    $computers = Get-DomainComputer @connectionParams

    $bhComputers = @()

    foreach ($computer in $computers) {
        $sid = $null
        if ($computer.objectSid) {
            $sid = Convert-SidToString -SidInput $computer.objectSid
            if (-not $sid) {
                Write-Log "[Collect-BHComputers] Failed to parse SID for $($computer.name)"
                continue
            }
        }
        else {
            continue
        }

        $uac = Get-SafeInt -Value $computer.userAccountControl -Default 0
        $isDC = ($uac -band 0x2000) -ne 0  # SERVER_TRUST_ACCOUNT

        # Get primary group SID
        $primaryGroupRid = Get-SafeInt -Value $computer.primaryGroupID -Default 515
        $primaryGroupSID = "$DomainSID-$primaryGroupRid"

        # Parse allowed to delegate (resolve SPNs to computer SIDs)
        $allowedToDelegate = @()
        if ($computer.'msDS-AllowedToDelegateTo') {
            $delegateTargets = $computer.'msDS-AllowedToDelegateTo'
            if ($delegateTargets -isnot [array]) { $delegateTargets = @($delegateTargets) }
            foreach ($target in $delegateTargets) {
                $resolved = Resolve-SPNToTarget -SPN $target
                if ($resolved) {
                    $allowedToDelegate += $resolved
                } else {
                    $allowedToDelegate += @{ ObjectIdentifier = $target; ObjectType = 'Computer' }
                }
            }
        }

        # Parse allowed to act (RBCD)
        $allowedToAct = @()
        if ($computer.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
            try {
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                $sd.SetSecurityDescriptorBinaryForm($computer.'msDS-AllowedToActOnBehalfOfOtherIdentity')
                foreach ($ace in $sd.Access) {
                    # Get SID - IdentityReference may be SecurityIdentifier or NTAccount
                    $sidValue = $null
                    $identRef = $ace.IdentityReference
                    if ($identRef -is [System.Security.Principal.SecurityIdentifier]) {
                        $sidValue = $identRef.Value
                    } else {
                        # NTAccount - use ConvertTo-SID for cross-domain support
                        $sidValue = ConvertTo-SID -Identity $identRef.Value
                    }
                    if ($sidValue) {
                        $allowedToAct += @{
                            ObjectIdentifier = $sidValue
                            ObjectType       = 'Unknown'
                        }
                    }
                }
            }
            catch {
                Write-Log "[Collect-BHComputers] Error parsing RBCD for $($computer.name): $_" -Level Debug
            }
        }

        # SID History
        $sidHistory = @()
        if ($computer.sIDHistory) {
            $historyItems = if ($computer.sIDHistory -is [array]) { $computer.sIDHistory } else { @($computer.sIDHistory) }
            foreach ($histSid in $historyItems) {
                $convertedSid = Convert-SidToString -SidInput $histSid
                if ($convertedSid) {
                    $sidHistory += $convertedSid
                }
            }
        }
        # HasSIDHistory is a TypedPrincipal array (BH CE expects []ein.TypedPrincipal, not bool)
        $sidHistoryTyped = @($sidHistory | ForEach-Object { @{ ObjectIdentifier = $_; ObjectType = 'Computer' } })

        $bhComputer = @{
            ObjectIdentifier    = $sid
            Properties          = @{
                name                    = "$($computer.dNSHostName)".ToUpper()
                domain                  = $domainName
                domainsid               = $DomainSID
                distinguishedname       = $computer.distinguishedName
                highvalue               = $isDC
                samaccountname          = $computer.sAMAccountName
                description             = if ($computer.description) { $computer.description } else { $null }
                whencreated             = ConvertTo-UnixTimestamp $computer.whenCreated
                operatingsystem         = $computer.operatingSystem
                enabled                 = ($uac -band 0x2) -eq 0
                unconstraineddelegation = ($uac -band 0x80000) -ne 0
                trustedtoauth           = ($uac -band 0x1000000) -ne 0
                lastlogon               = ConvertTo-UnixTimestamp $computer.lastLogon
                lastlogontimestamp      = ConvertTo-UnixTimestamp $computer.lastLogonTimestamp
                pwdlastset              = ConvertTo-UnixTimestamp $computer.pwdLastSet
                serviceprincipalnames   = @(
                    if ($computer.servicePrincipalName -and $computer.servicePrincipalName -isnot [hashtable]) {
                        $computer.servicePrincipalName
                    }
                )
                haslaps                             = ($null -ne $computer.'ms-Mcs-AdmPwdExpirationTime') -or ($null -ne $computer.'msLAPS-PasswordExpirationTime')
                sidhistory                          = $sidHistory
                isdc                               = $isDC
                objectguid                          = ConvertTo-BHGuid -Value $computer.objectGUID
                doesanyacegrantownerrights          = $false
                doesanyinheritedacegrantownerrights = $false
                encryptedtextpwdallowed             = ($uac -band 0x80) -ne 0
                logonscriptenabled                  = ($uac -band 0x1) -ne 0
                email                               = if ($computer.mail) { $computer.mail } else { $null }
                usedeskeyonly                       = ($uac -band 0x200000) -ne 0
                supportedencryptiontypes            = $null
            }
            PrimaryGroupSID     = $primaryGroupSID
            AllowedToDelegate   = $allowedToDelegate
            AllowedToAct        = $allowedToAct
            HasSIDHistory           = $sidHistoryTyped
            # Phase 1: No session/local group collection
            Sessions            = @{
                Collected     = $false
                FailureReason = "Not collected in Phase 1 (LDAP-only)"
                Results       = @()
            }
            PrivilegedSessions  = @{
                Collected     = $false
                FailureReason = "Not collected in Phase 1 (LDAP-only)"
                Results       = @()
            }
            RegistrySessions    = @{
                Collected     = $false
                FailureReason = "Not collected in Phase 1 (LDAP-only)"
                Results       = @()
            }
            # SharpHound v2.12.0: LocalAdmins/RemoteDesktopUsers/DcomUsers/PSRemoteUsers replaced by:
            LocalGroups         = @()
            UserRights          = @()
            DumpSMSAPassword    = @()
            DCRegistryData          = $null
            IsWebClientRunning      = $null
            NTLMRegistryData        = $null
            NtlmSessions            = $null
            SmbInfo                 = $null
            Aces                    = @()
            IsDeleted               = $false
        }

        # Collect ACLs if requested
        if ($CollectACLs) {
            $bhComputer.Aces = @(ConvertTo-BHAces -DistinguishedName $computer.distinguishedName -ObjectType 'Computer' @connectionParams)
        }

        $bhComputers += $bhComputer
    }

    return $bhComputers
}


<#
.SYNOPSIS
    Collects OU objects in BloodHound format.
#>
function Collect-BHOUs {
    param(
        [string]$DomainSID,
        [switch]$CollectACLs,
        [string]$Domain,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionParams = @{}
    if ($Domain) { $connectionParams['Domain'] = $Domain }
    if ($Server) { $connectionParams['Server'] = $Server }
    if ($Credential) { $connectionParams['Credential'] = $Credential }

    $domainName = $Script:LDAPContext.Domain.ToUpper()
    $domainDN = $Script:LDAPContext.DomainDN

    $ous = Get-DomainObject -LDAPFilter "(objectClass=organizationalUnit)" @connectionParams

    $bhOUs = @()

    foreach ($ou in $ous) {
        $ouGuid = ConvertTo-BHGuid -Value $ou.objectGuid

        # Get child objects from pre-built DN identity cache (O(1) lookup)
        $childObjects = @()
        $ouDN = $ou.distinguishedName
        if ($Script:ParentDNToChildren.ContainsKey($ouDN)) {
            $childObjects = @($Script:ParentDNToChildren[$ouDN])
        }

        # GPO links
        $gpoLinks = @()
        if ($ou.gPLink) {
            $gpLinkString = $ou.gPLink
            $linkMatches = [regex]::Matches($gpLinkString, '\[LDAP://([^\]]+);(\d)\]')
            foreach ($match in $linkMatches) {
                $gpoDN = $match.Groups[1].Value
                $enforced = $match.Groups[2].Value -eq '2'

                if ($gpoDN -match '\{([A-Fa-f0-9-]+)\}') {
                    $gpoGuid = $Matches[1].ToUpper()
                    $gpoLinks += @{
                        GUID       = $gpoGuid
                        IsEnforced = $enforced
                    }
                }
            }
        }

        $bhOU = @{
            ObjectIdentifier   = $ouGuid
            Properties         = @{
                name                                = "$($ou.name)@$domainName"
                domain                              = $domainName
                domainsid                           = $DomainSID
                distinguishedname                   = $ou.distinguishedName
                highvalue                           = $false
                description                         = if ($ou.description) { $ou.description } else { $null }
                whencreated                         = ConvertTo-UnixTimestamp $ou.whenCreated
                blocksinheritance                   = ((Get-SafeInt -Value $ou.gPOptions) -band 1) -ne 0
                objectguid                          = $ouGuid
                isaclprotected                      = $false
                doesanyacegrantownerrights          = $false
                doesanyinheritedacegrantownerrights = $false
            }
            ChildObjects       = $childObjects
            Links              = $gpoLinks
            GPOChanges         = @{
                LocalAdmins        = @()
                RemoteDesktopUsers = @()
                DcomUsers          = @()
                PSRemoteUsers      = @()
                AffectedComputers  = @()
            }
            Aces               = @()
            IsDeleted          = $false
        }

        # Collect ACLs if requested
        if ($CollectACLs) {
            $bhOU.Aces = @(ConvertTo-BHAces -DistinguishedName $ou.distinguishedName -ObjectType 'OU' @connectionParams)
        }

        $bhOUs += $bhOU
    }

    return $bhOUs
}


<#
.SYNOPSIS
    Collects container objects in BloodHound format.
#>
function Collect-BHContainers {
    param(
        [string]$DomainSID,
        [switch]$CollectACLs,
        [string]$Domain,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionParams = @{}
    if ($Domain) { $connectionParams['Domain'] = $Domain }
    if ($Server) { $connectionParams['Server'] = $Server }
    if ($Credential) { $connectionParams['Credential'] = $Credential }

    $domainName = $Script:LDAPContext.Domain.ToUpper()

    # Get standard containers
    $containers = Get-DomainObject -LDAPFilter "(&(objectClass=container)(!(objectClass=groupPolicyContainer)))" @connectionParams

    $bhContainers = @()

    foreach ($container in $containers) {
        $containerGuid = ConvertTo-BHGuid -Value $container.objectGuid
        $containerDN = $container.distinguishedName

        # Get child objects from pre-built DN identity cache (O(1) lookup)
        $childObjects = @()
        if ($Script:ParentDNToChildren.ContainsKey($containerDN)) {
            $childObjects = @($Script:ParentDNToChildren[$containerDN])
        }

        $bhContainer = @{
            ObjectIdentifier = $containerGuid
            Properties       = @{
                name                                = "$($container.name)@$domainName"
                domain                              = $domainName
                domainsid                           = $DomainSID
                distinguishedname                   = $containerDN
                highvalue                           = $false
                objectguid                          = $containerGuid
                description                         = if ($container.description) { $container.description } else { $null }
                isaclprotected                      = $false
                doesanyacegrantownerrights          = $false
                doesanyinheritedacegrantownerrights = $false
                whencreated                         = ConvertTo-UnixTimestamp $container.whenCreated
            }
            ChildObjects     = $childObjects
            Aces             = @()
            IsDeleted        = $false
        }

        if ($CollectACLs) {
            $bhContainer.Aces = @(ConvertTo-BHAces -DistinguishedName $containerDN -ObjectType 'Container' @connectionParams)
        }

        $bhContainers += $bhContainer
    }

    return $bhContainers
}


<#
.SYNOPSIS
    Collects GPO objects in BloodHound format.
#>
function Collect-BHGPOs {
    param(
        [string]$DomainSID,
        [switch]$CollectACLs,
        [string]$Domain,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionParams = @{}
    if ($Domain) { $connectionParams['Domain'] = $Domain }
    if ($Server) { $connectionParams['Server'] = $Server }
    if ($Credential) { $connectionParams['Credential'] = $Credential }

    $domainName = $Script:LDAPContext.Domain.ToUpper()

    $gpos = Get-DomainGPO @connectionParams

    $bhGPOs = @()

    foreach ($gpo in $gpos) {
        # GPO GUID from name attribute (CN={GUID})
        $gpoGuid = ""
        if ($gpo.name -match '\{([A-Fa-f0-9-]+)\}') {
            $gpoGuid = $Matches[1].ToUpper()
        }
        else {
            continue
        }

        $bhGPO = @{
            ObjectIdentifier = $gpoGuid
            Properties       = @{
                name                                = "$($gpo.displayName)@$domainName"
                domain                              = $domainName
                domainsid                           = $DomainSID
                distinguishedname                   = $gpo.distinguishedName
                highvalue                           = $false
                description                         = if ($gpo.description) { $gpo.description } else { $null }
                whencreated                         = ConvertTo-UnixTimestamp $gpo.whenCreated
                gpcpath                             = $gpo.gPCFileSysPath
                objectguid                          = $gpoGuid
                isaclprotected                      = $false
                doesanyacegrantownerrights          = $false
                doesanyinheritedacegrantownerrights = $false
                gpostatus                           = "0"
            }
            Aces             = @()
            IsDeleted        = $false
        }

        # Collect ACLs if requested
        if ($CollectACLs) {
            $bhGPO.Aces = @(ConvertTo-BHAces -DistinguishedName $gpo.distinguishedName -ObjectType 'GPO' @connectionParams)
        }

        $bhGPOs += $bhGPO
    }

    return $bhGPOs
}


<#
.SYNOPSIS
    Collects certificate template objects in BloodHound format.
.DESCRIPTION
    Queries pKICertificateTemplate objects from the Configuration partition and converts
    them to BloodHound CE v6 format. Uses Invoke-LDAPSearch -Raw for raw integer flags
    rather than Get-CertificateTemplate (which converts flags to human-readable strings).
#>
function Collect-BHCertTemplates {
    param(
        [string]$DomainSID,
        [switch]$CollectACLs,
        [string]$Domain,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionParams = @{}
    if ($Domain) { $connectionParams['Domain'] = $Domain }
    if ($Server) { $connectionParams['Server'] = $Server }
    if ($Credential) { $connectionParams['Credential'] = $Credential }

    $domainName = $Script:LDAPContext.Domain.ToUpper()
    $configNC = $Script:LDAPContext.ConfigurationNamingContext

    if (-not $configNC) {
        Write-Log "[Collect-BHCertTemplates] No Configuration NC available"
        return @()
    }

    $searchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

    $templateProps = @(
        'cn', 'distinguishedName', 'objectGUID', 'displayName', 'whenCreated',
        'msPKI-Cert-Template-OID',
        'pKIExpirationPeriod', 'pKIOverlapPeriod',
        'msPKI-Template-Schema-Version',
        'msPKI-Enrollment-Flag', 'msPKI-Certificate-Name-Flag',
        'pKIExtendedKeyUsage', 'msPKI-Certificate-Application-Policy',
        'msPKI-RA-Signature', 'msPKI-RA-Application-Policies', 'msPKI-RA-Policies',
        'nTSecurityDescriptor'
    )

    $templates = Invoke-LDAPSearch -Filter "(objectClass=pKICertificateTemplate)" -SearchBase $searchBase -Properties $templateProps -Raw

    $bhTemplates = @()

    # OIDs that enable authentication
    $authOIDs = @('1.3.6.1.5.5.7.3.2', '1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.2.3.4', '2.5.29.37.0')

    foreach ($template in @($templates)) {
        # Extract CN (may be byte[] from -Raw)
        $cn = $template.cn
        if ($cn -is [byte[]]) { $cn = [System.Text.Encoding]::UTF8.GetString($cn) }
        if ($cn -is [array]) { $cn = $cn[0] }

        # ObjectIdentifier = OID (NOT objectGuid)
        $oid = $template.'msPKI-Cert-Template-OID'
        if ($oid -is [byte[]]) { $oid = [System.Text.Encoding]::UTF8.GetString($oid) }
        if ($oid -is [array]) { $oid = $oid[0] }
        if (-not $oid) { continue }

        $dn = $template.distinguishedName
        if ($dn -is [byte[]]) { $dn = [System.Text.Encoding]::UTF8.GetString($dn) }
        if ($dn -is [array]) { $dn = $dn[0] }

        # Parse integer flags
        $enrollmentFlag = Get-SafeInt -Value $template.'msPKI-Enrollment-Flag'
        $certNameFlag = Get-SafeInt -Value $template.'msPKI-Certificate-Name-Flag'
        $schemaVersion = Get-SafeInt -Value $template.'msPKI-Template-Schema-Version'
        $raSignature = Get-SafeInt -Value $template.'msPKI-RA-Signature'

        # Parse displayName
        $templateDisplayName = $template.displayName
        if ($templateDisplayName -is [byte[]]) { $templateDisplayName = [System.Text.Encoding]::UTF8.GetString($templateDisplayName) }
        if ($templateDisplayName -is [array]) { $templateDisplayName = $templateDisplayName[0] }

        # Parse whenCreated (raw Generalized Time string in -Raw mode)
        $rawWhenCreated = $template.whenCreated
        if ($rawWhenCreated -is [byte[]]) { $rawWhenCreated = [System.Text.Encoding]::ASCII.GetString($rawWhenCreated) }
        if ($rawWhenCreated -is [array]) { $rawWhenCreated = $rawWhenCreated[0] }
        $templateWhenCreated = ConvertTo-UnixTimestamp $rawWhenCreated

        # Parse objectGUID
        $templateGuid = ""
        if ($template.objectGUID) {
            $rawGuid = $template.objectGUID
            if ($rawGuid -is [array] -and $rawGuid.Count -gt 0) { $rawGuid = $rawGuid[0] }
            $templateGuid = ConvertTo-BHGuid -Value $rawGuid
        }

        # Parse EKU arrays
        $ekus = @()
        if ($template.pKIExtendedKeyUsage) {
            $rawEkus = if ($template.pKIExtendedKeyUsage -is [array]) { $template.pKIExtendedKeyUsage } else { @($template.pKIExtendedKeyUsage) }
            foreach ($eku in $rawEkus) {
                if ($eku -is [byte[]]) { $eku = [System.Text.Encoding]::UTF8.GetString($eku) }
                if ($eku) { $ekus += $eku }
            }
        }

        $certAppPolicy = @()
        if ($template.'msPKI-Certificate-Application-Policy') {
            $rawCap = if ($template.'msPKI-Certificate-Application-Policy' -is [array]) { $template.'msPKI-Certificate-Application-Policy' } else { @($template.'msPKI-Certificate-Application-Policy') }
            foreach ($cap in $rawCap) {
                if ($cap -is [byte[]]) { $cap = [System.Text.Encoding]::UTF8.GetString($cap) }
                if ($cap) { $certAppPolicy += $cap }
            }
        }

        $appPolicies = @()
        if ($template.'msPKI-RA-Application-Policies') {
            $rawAp = if ($template.'msPKI-RA-Application-Policies' -is [array]) { $template.'msPKI-RA-Application-Policies' } else { @($template.'msPKI-RA-Application-Policies') }
            foreach ($ap in $rawAp) {
                if ($ap -is [byte[]]) { $ap = [System.Text.Encoding]::UTF8.GetString($ap) }
                if ($ap) { $appPolicies += $ap }
            }
        }

        $issuancePolicies = @()
        if ($template.'msPKI-RA-Policies') {
            $rawIp = if ($template.'msPKI-RA-Policies' -is [array]) { $template.'msPKI-RA-Policies' } else { @($template.'msPKI-RA-Policies') }
            foreach ($ip in $rawIp) {
                if ($ip -is [byte[]]) { $ip = [System.Text.Encoding]::UTF8.GetString($ip) }
                if ($ip) { $issuancePolicies += $ip }
            }
        }

        # Effective EKUs = union of pKIExtendedKeyUsage + msPKI-Certificate-Application-Policy
        $effectiveEkus = @($ekus) + @($certAppPolicy) | Where-Object { $_ } | Select-Object -Unique

        # Authentication enabled: true if any auth OID present, or if no EKUs defined (any purpose)
        $authEnabled = (@($effectiveEkus).Count -eq 0) -or ($effectiveEkus | Where-Object { $_ -in $authOIDs })
        $authEnabled = [bool]$authEnabled

        # Validity/renewal periods from raw byte arrays
        $validityPeriod = "P0D"
        $renewalPeriod = "P0D"
        if ($template.pKIExpirationPeriod -is [byte[]]) {
            $validityPeriod = ConvertTo-ISODuration -PeriodBytes $template.pKIExpirationPeriod
        }
        if ($template.pKIOverlapPeriod -is [byte[]]) {
            $renewalPeriod = ConvertTo-ISODuration -PeriodBytes $template.pKIOverlapPeriod
        }

        $bhTemplate = @{
            ObjectIdentifier = $oid
            Properties       = @{
                name                                = "$cn@$domainName"
                domain                              = $domainName
                domainsid                           = $DomainSID
                distinguishedname                   = $dn
                highvalue                           = $false
                validityperiod                      = $validityPeriod
                renewalperiod                       = $renewalPeriod
                schemaversion                       = $schemaVersion
                enrollmentflag                      = Convert-EnrollFlagToString -Value $enrollmentFlag
                certificatenameflag                 = Convert-CertNameFlagToString -Value $certNameFlag
                oid                                 = $oid
                requiresmanagerapproval             = ($enrollmentFlag -band 0x2) -ne 0
                enrolleesuppliessubject             = ($certNameFlag -band 0x1) -ne 0
                subjectaltrequireupn                = ($certNameFlag -band 0x2000000) -ne 0
                subjectaltrequiredns                = ($certNameFlag -band 0x8000000) -ne 0
                subjectaltrequiredomaindns          = ($certNameFlag -band 0x400000) -ne 0
                subjectaltrequireemail              = ($certNameFlag -band 0x4000000) -ne 0
                subjectaltrequirespn                = ($certNameFlag -band 0x800) -ne 0
                nosecurityextension                 = ($enrollmentFlag -band 0x80000) -ne 0
                ekus                                = $ekus
                certificateapplicationpolicy        = $certAppPolicy
                authorizedsignatures                = $raSignature
                applicationpolicies                 = $appPolicies
                issuancepolicies                    = $issuancePolicies
                effectiveekus                       = @($effectiveEkus)
                authenticationenabled               = $authEnabled
                objectguid                          = $templateGuid
                displayname                         = if ($templateDisplayName) { $templateDisplayName } else { $null }
                isaclprotected                      = $false
                doesanyacegrantownerrights          = $false
                doesanyinheritedacegrantownerrights = $false
                schannelauthenticationenabled       = $false
                subjectrequireemail                 = ($certNameFlag -band 0x20000000) -ne 0
                whencreated                         = $templateWhenCreated
                certificatepolicy                   = @()
            }
            ContainedBy      = Get-BHContainedByConfig -DistinguishedName $dn
            Aces             = @()
            IsDeleted        = $false
        }

        if ($CollectACLs -and $dn) {
            $bhTemplate.Aces = @(ConvertTo-BHAces -DistinguishedName $dn -ObjectType 'CertTemplate' @connectionParams)
        }

        $bhTemplates += $bhTemplate
    }

    return $bhTemplates
}


<#
.SYNOPSIS
    Collects Enterprise CA objects in BloodHound format.
.DESCRIPTION
    Reuses Get-CertificateAuthority (Core) to query pKIEnrollmentService objects,
    then transforms them to BloodHound CE v6 format with EnabledCertTemplates and
    HostingComputer relationships.
#>
function Collect-BHEnterpriseCAs {
    param(
        [string]$DomainSID,
        [switch]$CollectACLs,
        [string]$Domain,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionParams = @{}
    if ($Domain) { $connectionParams['Domain'] = $Domain }
    if ($Server) { $connectionParams['Server'] = $Server }
    if ($Credential) { $connectionParams['Credential'] = $Credential }

    $domainName = $Script:LDAPContext.Domain.ToUpper()

    $cas = Get-CertificateAuthority @connectionParams

    $bhCAs = @()

    foreach ($ca in @($cas)) {
        # Skip error markers
        if ($ca._QueryError) { continue }
        if (-not $ca.Name) { continue }

        $caGuid = ""
        if ($ca.ObjectGUID) {
            $caGuid = $ca.ObjectGUID.ToString().ToUpper()
        } else {
            continue
        }

        # Parse CA certificate
        $certProps = @{ Thumbprint = ""; Name = ""; HasBasicConstraints = $false; PathLength = 0 }
        if ($ca.CACertificate) {
            $certBytes = if ($ca.CACertificate -is [array] -and $ca.CACertificate[0] -is [byte]) {
                [byte[]]$ca.CACertificate
            } elseif ($ca.CACertificate -is [array]) {
                $ca.CACertificate[0]
            } else {
                $ca.CACertificate
            }
            if ($certBytes -is [byte[]]) {
                $certProps = Get-CertificateProperties -CertificateBytes $certBytes
            }
        }

        # Build certchain (all cert thumbprints)
        $certChain = @()
        if ($certProps.Thumbprint) { $certChain += $certProps.Thumbprint }

        # Resolve EnabledCertTemplates: template CN -> OID
        $enabledTemplates = @()
        foreach ($templateCN in @($ca.CertificateTemplates)) {
            if ($Script:TemplateCNToOID -and $Script:TemplateCNToOID.ContainsKey($templateCN)) {
                $enabledTemplates += @{
                    ObjectIdentifier = $Script:TemplateCNToOID[$templateCN]
                    ObjectType       = 'CertTemplate'
                }
            }
        }

        # Resolve HostingComputer: dNSHostName -> computer SID
        $hostingSID = ""
        if ($ca.DNSHostName -and $Script:ComputerHostnameCache) {
            $hostKey = $ca.DNSHostName.ToLower()
            if ($Script:ComputerHostnameCache.ContainsKey($hostKey)) {
                $hostingSID = $Script:ComputerHostnameCache[$hostKey]
            }
        }

        $bhCA = @{
            ObjectIdentifier     = $caGuid
            Properties           = @{
                name                                = "$($ca.Name)@$domainName"
                domain                              = $domainName
                domainsid                           = $DomainSID
                distinguishedname                   = $ca.DistinguishedName
                highvalue                           = $false
                dnshostname                         = $ca.DNSHostName
                basicconstraintpathlength           = $certProps.PathLength
                hasbasicconstraints                 = $certProps.HasBasicConstraints
                certchain                           = $certChain
                certname                            = $certProps.Name
                certthumbprint                      = $certProps.Thumbprint
                flags                               = Convert-CAFlagToString -Value $(if ($ca.Flags) { [int]$ca.Flags } else { 0 })
                caname                              = $ca.Name
                objectguid                          = ConvertTo-BHGuid -Value $ca.ObjectGUID
                isaclprotected                      = $false
                doesanyacegrantownerrights          = $false
                doesanyinheritedacegrantownerrights = $false
                unresolvedpublishedtemplates        = @()
                whencreated                         = ConvertTo-UnixTimestamp $ca.Created
            }
            # CARegistryData must be top-level (not inside Properties) — nested dicts inside
            # Properties cause Neo4j Map{} errors when BH CE writes them as node properties.
            CARegistryData          = $null
            HttpEnrollmentEndpoints = @()
            EnabledCertTemplates    = $enabledTemplates
            HostingComputer         = $hostingSID
            ContainedBy             = Get-BHContainedByConfig -DistinguishedName $ca.DistinguishedName
            Aces                    = @()
            IsDeleted               = $false
            IsACLProtected          = $false
        }

        if ($CollectACLs -and $ca.DistinguishedName) {
            $bhCA.Aces = @(ConvertTo-BHAces -DistinguishedName $ca.DistinguishedName -ObjectType 'EnterpriseCA' @connectionParams)
        }

        $bhCAs += $bhCA
    }

    return $bhCAs
}


<#
.SYNOPSIS
    Collects Root CA objects in BloodHound format.
.DESCRIPTION
    Queries certificationAuthority objects from the Certification Authorities container
    in the Configuration partition. These are the trusted root CAs for the forest.
#>
function Collect-BHRootCAs {
    param(
        [string]$DomainSID,
        [switch]$CollectACLs,
        [string]$Domain,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionParams = @{}
    if ($Domain) { $connectionParams['Domain'] = $Domain }
    if ($Server) { $connectionParams['Server'] = $Server }
    if ($Credential) { $connectionParams['Credential'] = $Credential }

    $domainName = $Script:LDAPContext.Domain.ToUpper()
    $configNC = $Script:LDAPContext.ConfigurationNamingContext

    if (-not $configNC) {
        Write-Log "[Collect-BHRootCAs] No Configuration NC available"
        return @()
    }

    $searchBase = "CN=Certification Authorities,CN=Public Key Services,CN=Services,$configNC"

    $rootCAs = Invoke-LDAPSearch -Filter "(objectClass=certificationAuthority)" -SearchBase $searchBase -Properties cn,distinguishedName,objectGUID,cACertificate,whenCreated -Raw -Scope OneLevel

    $bhRootCAs = @()

    foreach ($rootCA in @($rootCAs)) {
        $cn = $rootCA.cn
        if ($cn -is [byte[]]) { $cn = [System.Text.Encoding]::UTF8.GetString($cn) }
        if ($cn -is [array]) { $cn = $cn[0] }

        $dn = $rootCA.distinguishedName
        if ($dn -is [byte[]]) { $dn = [System.Text.Encoding]::UTF8.GetString($dn) }
        if ($dn -is [array]) { $dn = $dn[0] }

        $guid = ""
        if ($rootCA.objectGUID) {
            if ($rootCA.objectGUID -is [byte[]]) {
                $guid = ([Guid]$rootCA.objectGUID).ToString().ToUpper()
            } else {
                $guid = $rootCA.objectGUID.ToString().ToUpper()
            }
        }
        if (-not $guid) { continue }

        # Parse whenCreated
        $rawWhenCreated = $rootCA.whenCreated
        if ($rawWhenCreated -is [byte[]]) { $rawWhenCreated = [System.Text.Encoding]::ASCII.GetString($rawWhenCreated) }
        if ($rawWhenCreated -is [array]) { $rawWhenCreated = $rawWhenCreated[0] }
        $rootCAWhenCreated = ConvertTo-UnixTimestamp $rawWhenCreated

        # Parse certificate
        $certProps = @{ Thumbprint = ""; Name = ""; HasBasicConstraints = $false; PathLength = 0 }
        if ($rootCA.cACertificate) {
            $certBytes = $rootCA.cACertificate
            if ($certBytes -is [array] -and $certBytes[0] -isnot [byte]) { $certBytes = $certBytes[0] }
            if ($certBytes -is [byte[]]) {
                $certProps = Get-CertificateProperties -CertificateBytes $certBytes
            }
        }

        $bhRootCA = @{
            ObjectIdentifier = $guid
            Properties       = @{
                name                                = "$cn@$domainName"
                domain                              = $domainName
                domainsid                           = $DomainSID
                distinguishedname                   = $dn
                highvalue                           = $false
                certname                            = $certProps.Name
                certthumbprint                      = $certProps.Thumbprint
                hasbasicconstraints                 = $certProps.HasBasicConstraints
                basicconstraintpathlength           = $certProps.PathLength
                objectguid                          = $guid
                isaclprotected                      = $false
                doesanyacegrantownerrights          = $false
                doesanyinheritedacegrantownerrights = $false
                certchain                           = @($certProps.Thumbprint | Where-Object { $_ })
                whencreated                         = $rootCAWhenCreated
            }
            DomainSID        = $DomainSID
            ContainedBy      = Get-BHContainedByConfig -DistinguishedName $dn
            Aces             = @()
            IsDeleted        = $false
        }

        if ($CollectACLs -and $dn) {
            $bhRootCA.Aces = @(ConvertTo-BHAces -DistinguishedName $dn -ObjectType 'RootCA' @connectionParams)
        }

        $bhRootCAs += $bhRootCA
    }

    return $bhRootCAs
}


<#
.SYNOPSIS
    Collects AIA CA objects in BloodHound format.
.DESCRIPTION
    Queries certificationAuthority objects from the AIA (Authority Information Access)
    container in the Configuration partition.
#>
function Collect-BHAIACAs {
    param(
        [string]$DomainSID,
        [switch]$CollectACLs,
        [string]$Domain,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionParams = @{}
    if ($Domain) { $connectionParams['Domain'] = $Domain }
    if ($Server) { $connectionParams['Server'] = $Server }
    if ($Credential) { $connectionParams['Credential'] = $Credential }

    $domainName = $Script:LDAPContext.Domain.ToUpper()
    $configNC = $Script:LDAPContext.ConfigurationNamingContext

    if (-not $configNC) {
        Write-Log "[Collect-BHAIACAs] No Configuration NC available"
        return @()
    }

    $searchBase = "CN=AIA,CN=Public Key Services,CN=Services,$configNC"

    $aiaCAs = Invoke-LDAPSearch -Filter "(objectClass=certificationAuthority)" -SearchBase $searchBase -Properties cn,distinguishedName,objectGUID,cACertificate,crossCertificatePair,whenCreated -Raw -Scope OneLevel

    $bhAIACAs = @()

    foreach ($aiaCA in @($aiaCAs)) {
        $cn = $aiaCA.cn
        if ($cn -is [byte[]]) { $cn = [System.Text.Encoding]::UTF8.GetString($cn) }
        if ($cn -is [array]) { $cn = $cn[0] }

        $dn = $aiaCA.distinguishedName
        if ($dn -is [byte[]]) { $dn = [System.Text.Encoding]::UTF8.GetString($dn) }
        if ($dn -is [array]) { $dn = $dn[0] }

        $guid = ""
        if ($aiaCA.objectGUID) {
            if ($aiaCA.objectGUID -is [byte[]]) {
                $guid = ([Guid]$aiaCA.objectGUID).ToString().ToUpper()
            } else {
                $guid = $aiaCA.objectGUID.ToString().ToUpper()
            }
        }
        if (-not $guid) { continue }

        # Parse whenCreated
        $rawWhenCreated = $aiaCA.whenCreated
        if ($rawWhenCreated -is [byte[]]) { $rawWhenCreated = [System.Text.Encoding]::ASCII.GetString($rawWhenCreated) }
        if ($rawWhenCreated -is [array]) { $rawWhenCreated = $rawWhenCreated[0] }
        $aiaCAWhenCreated = ConvertTo-UnixTimestamp $rawWhenCreated

        # Parse certificate
        $certProps = @{ Thumbprint = ""; Name = ""; HasBasicConstraints = $false; PathLength = 0 }
        if ($aiaCA.cACertificate) {
            $certBytes = $aiaCA.cACertificate
            if ($certBytes -is [array] -and $certBytes[0] -isnot [byte]) { $certBytes = $certBytes[0] }
            if ($certBytes -is [byte[]]) {
                $certProps = Get-CertificateProperties -CertificateBytes $certBytes
            }
        }

        # Check for CRL Distribution Points extension (hascrl)
        $hasCRL = $false
        if ($aiaCA.cACertificate) {
            try {
                $certBytesForCRL = $aiaCA.cACertificate
                if ($certBytesForCRL -is [array] -and $certBytesForCRL[0] -isnot [byte]) { $certBytesForCRL = $certBytesForCRL[0] }
                if ($certBytesForCRL -is [byte[]]) {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certBytesForCRL)
                    foreach ($ext in $cert.Extensions) {
                        if ($ext.Oid.Value -eq '2.5.29.31') { $hasCRL = $true; break }
                    }
                }
            }
            catch { Write-Log "[Collect-BHAIACAs] CRL extension check failed for '$cn': $_" -Level Debug }
        }

        $bhAIACA = @{
            ObjectIdentifier = $guid
            Properties       = @{
                name                                = "$cn@$domainName"
                domain                              = $domainName
                domainsid                           = $DomainSID
                distinguishedname                   = $dn
                highvalue                           = $false
                certname                            = $certProps.Name
                certthumbprint                      = $certProps.Thumbprint
                hascrl                              = $hasCRL
                crosscertificatepair                = @()
                objectguid                          = $guid
                isaclprotected                      = $false
                doesanyacegrantownerrights          = $false
                doesanyinheritedacegrantownerrights = $false
                hasbasicconstraints                 = $certProps.HasBasicConstraints
                basicconstraintpathlength           = $certProps.PathLength
                hascrosscertificatepair             = $false
                certchain                           = @($certProps.Thumbprint | Where-Object { $_ })
                whencreated                         = $aiaCAWhenCreated
            }
            ContainedBy      = Get-BHContainedByConfig -DistinguishedName $dn
            Aces             = @()
            IsDeleted        = $false
        }

        if ($CollectACLs -and $dn) {
            $bhAIACA.Aces = @(ConvertTo-BHAces -DistinguishedName $dn -ObjectType 'AIACA' @connectionParams)
        }

        $bhAIACAs += $bhAIACA
    }

    return $bhAIACAs
}


<#
.SYNOPSIS
    Collects NTAuth Store objects in BloodHound format.
.DESCRIPTION
    Queries the NTAuthCertificates object from the Public Key Services container.
    The NTAuth store defines which CAs are trusted for smart card / certificate-based logon.
#>
function Collect-BHNTAuthStores {
    param(
        [string]$DomainSID,
        [switch]$CollectACLs,
        [string]$Domain,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionParams = @{}
    if ($Domain) { $connectionParams['Domain'] = $Domain }
    if ($Server) { $connectionParams['Server'] = $Server }
    if ($Credential) { $connectionParams['Credential'] = $Credential }

    $domainName = $Script:LDAPContext.Domain.ToUpper()
    $configNC = $Script:LDAPContext.ConfigurationNamingContext

    if (-not $configNC) {
        Write-Log "[Collect-BHNTAuthStores] No Configuration NC available"
        return @()
    }

    $searchBase = "CN=Public Key Services,CN=Services,$configNC"

    $ntAuth = Invoke-LDAPSearch -Filter "(cn=NTAuthCertificates)" -SearchBase $searchBase -Properties cn,distinguishedName,objectGUID,cACertificate,whenCreated -Raw -Scope OneLevel

    $bhNTAuthStores = @()

    foreach ($ntAuthObj in @($ntAuth)) {
        $cn = $ntAuthObj.cn
        if ($cn -is [byte[]]) { $cn = [System.Text.Encoding]::UTF8.GetString($cn) }
        if ($cn -is [array]) { $cn = $cn[0] }

        $dn = $ntAuthObj.distinguishedName
        if ($dn -is [byte[]]) { $dn = [System.Text.Encoding]::UTF8.GetString($dn) }
        if ($dn -is [array]) { $dn = $dn[0] }

        $guid = ""
        if ($ntAuthObj.objectGUID) {
            if ($ntAuthObj.objectGUID -is [byte[]]) {
                $guid = ([Guid]$ntAuthObj.objectGUID).ToString().ToUpper()
            } else {
                $guid = $ntAuthObj.objectGUID.ToString().ToUpper()
            }
        }
        if (-not $guid) { continue }

        # Parse whenCreated
        $rawWhenCreated = $ntAuthObj.whenCreated
        if ($rawWhenCreated -is [byte[]]) { $rawWhenCreated = [System.Text.Encoding]::ASCII.GetString($rawWhenCreated) }
        if ($rawWhenCreated -is [array]) { $rawWhenCreated = $rawWhenCreated[0] }
        $ntAuthWhenCreated = ConvertTo-UnixTimestamp $rawWhenCreated

        # Parse all certificates to extract thumbprints
        $certThumbprints = @()
        if ($ntAuthObj.cACertificate) {
            $rawCerts = $ntAuthObj.cACertificate
            # cACertificate may be multi-valued (array of byte arrays) or single byte array
            if ($rawCerts -is [byte[]]) {
                $props = Get-CertificateProperties -CertificateBytes $rawCerts
                if ($props.Thumbprint) { $certThumbprints += $props.Thumbprint }
            }
            elseif ($rawCerts -is [array]) {
                foreach ($certBytes in $rawCerts) {
                    if ($certBytes -is [byte[]]) {
                        $props = Get-CertificateProperties -CertificateBytes $certBytes
                        if ($props.Thumbprint) { $certThumbprints += $props.Thumbprint }
                    }
                }
            }
        }

        $bhNTAuthStore = @{
            ObjectIdentifier = $guid
            Properties       = @{
                name                                = "$cn@$domainName"
                domain                              = $domainName
                domainsid                           = $DomainSID
                distinguishedname                   = $dn
                highvalue                           = $false
                certthumbprints                     = $certThumbprints
                objectguid                          = $guid
                isaclprotected                      = $false
                doesanyacegrantownerrights          = $false
                doesanyinheritedacegrantownerrights = $false
                whencreated                         = $ntAuthWhenCreated
            }
            DomainSID        = $DomainSID
            ContainedBy      = Get-BHContainedByConfig -DistinguishedName $dn
            Aces             = @()
            IsDeleted        = $false
        }

        if ($CollectACLs -and $dn) {
            $bhNTAuthStore.Aces = @(ConvertTo-BHAces -DistinguishedName $dn -ObjectType 'NTAuthStore' @connectionParams)
        }

        $bhNTAuthStores += $bhNTAuthStore
    }

    return $bhNTAuthStores
}


<#
.SYNOPSIS
    Collects Issuance Policy objects in BloodHound format.
.DESCRIPTION
    Queries msPKI-Enterprise-Oid objects from the OID container in the Configuration
    partition. Issuance policies can be linked to groups via msDS-OIDToGroupLink,
    enabling certificate-based group membership attacks.
#>
function Collect-BHIssuancePolicies {
    param(
        [string]$DomainSID,
        [switch]$CollectACLs,
        [string]$Domain,
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential
    )

    $connectionParams = @{}
    if ($Domain) { $connectionParams['Domain'] = $Domain }
    if ($Server) { $connectionParams['Server'] = $Server }
    if ($Credential) { $connectionParams['Credential'] = $Credential }

    $domainName = $Script:LDAPContext.Domain.ToUpper()
    $configNC = $Script:LDAPContext.ConfigurationNamingContext

    if (-not $configNC) {
        Write-Log "[Collect-BHIssuancePolicies] No Configuration NC available"
        return @()
    }

    $searchBase = "CN=OID,CN=Public Key Services,CN=Services,$configNC"

    $oidObjects = Invoke-LDAPSearch -Filter "(objectClass=msPKI-Enterprise-Oid)" -SearchBase $searchBase -Properties cn,displayName,distinguishedName,objectGUID,'msPKI-Cert-Template-OID','msDS-OIDToGroupLink',whenCreated -Raw

    $bhPolicies = @()

    foreach ($oidObj in @($oidObjects)) {
        # Only include objects with an OID (issuance policies)
        $oid = $oidObj.'msPKI-Cert-Template-OID'
        if ($oid -is [byte[]]) { $oid = [System.Text.Encoding]::UTF8.GetString($oid) }
        if ($oid -is [array]) { $oid = $oid[0] }
        if (-not $oid) { continue }

        $cn = $oidObj.cn
        if ($cn -is [byte[]]) { $cn = [System.Text.Encoding]::UTF8.GetString($cn) }
        if ($cn -is [array]) { $cn = $cn[0] }

        $displayName = $oidObj.displayName
        if ($displayName -is [byte[]]) { $displayName = [System.Text.Encoding]::UTF8.GetString($displayName) }
        if ($displayName -is [array]) { $displayName = $displayName[0] }

        $dn = $oidObj.distinguishedName
        if ($dn -is [byte[]]) { $dn = [System.Text.Encoding]::UTF8.GetString($dn) }
        if ($dn -is [array]) { $dn = $dn[0] }

        $name = if ($displayName) { $displayName } else { $cn }

        # Parse objectGUID
        $policyGuid = ""
        if ($oidObj.objectGUID) {
            $rawGuid = $oidObj.objectGUID
            if ($rawGuid -is [array] -and $rawGuid.Count -gt 0) { $rawGuid = $rawGuid[0] }
            $policyGuid = ConvertTo-BHGuid -Value $rawGuid
        }

        # Parse whenCreated
        $rawWhenCreated = $oidObj.whenCreated
        if ($rawWhenCreated -is [byte[]]) { $rawWhenCreated = [System.Text.Encoding]::ASCII.GetString($rawWhenCreated) }
        if ($rawWhenCreated -is [array]) { $rawWhenCreated = $rawWhenCreated[0] }
        $policyWhenCreated = ConvertTo-UnixTimestamp $rawWhenCreated

        # Resolve GroupLink: msDS-OIDToGroupLink DN -> group SID
        $groupLink = @{ ObjectIdentifier = $null; ObjectType = 'Base' }
        if ($oidObj.'msDS-OIDToGroupLink') {
            $groupLinkDN = $oidObj.'msDS-OIDToGroupLink'
            if ($groupLinkDN -is [byte[]]) { $groupLinkDN = [System.Text.Encoding]::UTF8.GetString($groupLinkDN) }
            if ($groupLinkDN -is [array]) { $groupLinkDN = $groupLinkDN[0] }

            if ($groupLinkDN) {
                try {
                    $escapedDN = Escape-LDAPFilterDN -DistinguishedName $groupLinkDN
                    $groupObj = @(Get-DomainObject -LDAPFilter "(distinguishedName=$escapedDN)" -Properties objectSid @connectionParams)[0]
                    if ($groupObj -and $groupObj.objectSid) {
                        $resolvedSid = Convert-SidToString -SidInput $groupObj.objectSid
                        if ($resolvedSid) {
                            $groupLink = @{ ObjectIdentifier = $resolvedSid; ObjectType = 'Group' }
                        }
                    }
                }
                catch {
                    Write-Log "[Collect-BHIssuancePolicies] Error resolving GroupLink DN: $_" -Level Debug
                }
            }
        }

        $bhPolicy = @{
            ObjectIdentifier = $oid
            Properties       = @{
                name                                = "$name@$domainName"
                domain                              = $domainName
                domainsid                           = $DomainSID
                distinguishedname                   = $dn
                highvalue                           = $false
                certtemplateoid                     = $oid
                objectguid                          = $policyGuid
                displayname                         = if ($displayName) { $displayName } else { $null }
                isaclprotected                      = $false
                doesanyacegrantownerrights          = $false
                doesanyinheritedacegrantownerrights = $false
                whencreated                         = $policyWhenCreated
            }
            GroupLink        = $groupLink
            ContainedBy      = Get-BHContainedByConfig -DistinguishedName $dn
            Aces             = @()
            IsDeleted        = $false
        }

        if ($CollectACLs -and $dn) {
            $bhPolicy.Aces = @(ConvertTo-BHAces -DistinguishedName $dn -ObjectType 'IssuancePolicy' @connectionParams)
        }

        $bhPolicies += $bhPolicy
    }

    return $bhPolicies
}
