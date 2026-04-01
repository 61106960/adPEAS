function Get-SMBSigningStatus {
    <#
    .SYNOPSIS
    Checks SMB Signing configuration status via GPO analysis.

    .DESCRIPTION
    Analyzes SMB Signing configuration by examining GPOs in SYSVOL and calculating coverage across all computer accounts.
    SMB Signing protects against SMB Relay and NTLM Relay attacks.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-SMBSigningStatus

    .EXAMPLE
    Get-SMBSigningStatus -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Domain
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

    begin {
        Write-Log "[Get-SMBSigningStatus] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Analyzing SMB Signing configuration via GPO (SYSVOL)..." -ObjectType "SMBSigning"

            $domainFQDN = $Script:LDAPContext.Domain
            $dcServer = $Script:LDAPContext.Server

            $allGPOs = Get-DomainGPO @PSBoundParameters

            if (-not $allGPOs -or @($allGPOs).Count -eq 0) {
                Show-Line "No GPOs found" -Class Note
                return
            }

            # Use Invoke-SMBAccess for SYSVOL access (handles SimpleBind credentials)
            $Script:smbGpoFindings = @()
            $Script:sysvolAccessible = $false

            Invoke-SMBAccess -Description "Scanning SYSVOL for SMB Signing GPOs" -ScriptBlock {
                $sysvolPath = "\\$dcServer\SYSVOL\$domainFQDN\Policies"

                if (-not (Test-Path $sysvolPath)) {
                    Write-Log "[Get-SMBSigningStatus] SYSVOL path not accessible: $sysvolPath"
                    return
                }

                $Script:sysvolAccessible = $true

                # Parse GPOs for SMB Signing settings
                $totalGPOs = @($allGPOs).Count
                $currentGPOIndex = 0
                foreach ($gpo in $allGPOs) {
                    $currentGPOIndex++
                    if ($totalGPOs -gt $Script:ProgressThreshold) {
                        Show-Progress -Activity "Scanning SMB signing GPO settings" -Current $currentGPOIndex -Total $totalGPOs -ObjectName $gpo.DisplayName
                    }
                    $gpoGUID = $gpo.Name

                    $gptTmplPath = Join-Path $sysvolPath "$gpoGUID\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

                    $content = Get-CachedSYSVOLContent -Path $gptTmplPath
                    if ($content) {
                        # Look for SMB Signing settings in [Registry Values] section
                        if ($content -match '(?s)\[Registry Values\](.*?)(\[|$)') {
                            $registrySection = $Matches[1]

                            $serverRequire = $null
                            $serverEnable = $null
                            $clientRequire = $null
                            $clientEnable = $null

                            # Server Settings
                            if ($registrySection -match 'MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature.*?=.*?4,(\d+)') {
                                $serverRequire = [int]$Matches[1]
                            }
                            if ($registrySection -match 'MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\EnableSecuritySignature.*?=.*?4,(\d+)') {
                                $serverEnable = [int]$Matches[1]
                            }

                            # Client Settings
                            if ($registrySection -match 'MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature.*?=.*?4,(\d+)') {
                                $clientRequire = [int]$Matches[1]
                            }
                            if ($registrySection -match 'MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\EnableSecuritySignature.*?=.*?4,(\d+)') {
                                $clientEnable = [int]$Matches[1]
                            }

                            # If any SMB Signing settings found, add to findings
                            if ($null -ne $serverRequire -or $null -ne $serverEnable -or
                                $null -ne $clientRequire -or $null -ne $clientEnable) {

                                # Determine Server Status
                                $serverStatus = if ($null -eq $serverRequire -and $null -eq $serverEnable) {
                                    "Not configured"
                                } elseif ($serverRequire -eq 1) {
                                    "Required"
                                } elseif ($serverEnable -eq 1) {
                                    "Optional"
                                } elseif ($serverRequire -eq 0 -or $serverEnable -eq 0) {
                                    "Disabled"
                                } else {
                                    "Not configured"
                                }

                                # Determine Client Status
                                $clientStatus = if ($null -eq $clientRequire -and $null -eq $clientEnable) {
                                    "Not configured"
                                } elseif ($clientRequire -eq 1) {
                                    "Required"
                                } elseif ($clientEnable -eq 1) {
                                    "Optional"
                                } elseif ($clientRequire -eq 0 -or $clientEnable -eq 0) {
                                    "Disabled"
                                } else {
                                    "Not configured"
                                }

                                # Get GPO linkage
                                $gpoLinkage = Get-GPOLinkage
                                # Normalize GUID to uppercase for hashtable lookup (Get-GPOLinkage uses uppercase keys)
                                $gpoGUIDUpper = $gpoGUID.ToUpper()
                                $links = $gpoLinkage[$gpoGUIDUpper]
                                $activeLinks = @()
                                $isDomainWide = $false

                                if ($links) {
                                    $activeLinks = @($links | Where-Object { $_.LinkStatus -ne "Disabled" })
                                    $domainWide = $activeLinks | Where-Object { $_.Scope -eq "Domain" }
                                    $isDomainWide = ($null -ne $domainWide)
                                }

                                # Enrich the native GPO object with SMB Signing attributes
                                $gpo | Add-Member -NotePropertyName "ServerSigning" -NotePropertyValue $serverStatus -Force
                                $gpo | Add-Member -NotePropertyName "ClientSigning" -NotePropertyValue $clientStatus -Force
                                $gpo | Add-Member -NotePropertyName "IsDomainWide" -NotePropertyValue $isDomainWide -Force

                                # Add LinkedOUs for display (shows where GPO applies)
                                if (@($activeLinks).Count -gt 0) {
                                    $linkedOUsDisplay = @($activeLinks | ForEach-Object { $_.DistinguishedName })
                                    $gpo | Add-Member -NotePropertyName "LinkedOUs" -NotePropertyValue $linkedOUsDisplay -Force

                                    # Determine Scope for display
                                    $scopeInfo = if ($isDomainWide) {
                                        "Domain-wide ($(@($activeLinks).Count) link(s))"
                                    } else {
                                        "$(@($activeLinks).Count) OU(s)"
                                    }
                                    $gpo | Add-Member -NotePropertyName "Scope" -NotePropertyValue $scopeInfo -Force
                                } else {
                                    $gpo | Add-Member -NotePropertyName "Scope" -NotePropertyValue "NOT LINKED" -Force
                                }

                                $Script:smbGpoFindings += $gpo
                            }
                        }
                    }
                }
                if ($totalGPOs -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Scanning SMB signing GPO settings" -Completed
                }
            }

            $gpoFindings = $Script:smbGpoFindings
            $Script:smbGpoFindings = $null
            $sysvolAccessible = $Script:sysvolAccessible
            $Script:sysvolAccessible = $null

            # Check if SYSVOL was accessible
            if (-not $sysvolAccessible) {
                if ((Test-SysvolAccessible) -eq $false) {
                    Show-Line "Skipped - SYSVOL not accessible" -Class Hint
                } else {
                    Show-Line "SYSVOL access failed - cannot analyze GPO configuration for SMB Signing - SMB access failed (authentication/network issue)" -Class Finding
                }
                return
            }

            if ($gpoFindings -and @($gpoFindings).Count -gt 0) {
                Show-Line "Found SMB Signing configuration in $(@($gpoFindings).Count) GPO(s):" -Class Hint
                foreach ($gpoFinding in $gpoFindings) {
                    $gpoFinding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'SMBSigning' -Force
                    Show-Object $gpoFinding
                }

                # Check if SMB Signing is only configured for Domain Controllers
                # This means member servers and clients rely on OS defaults (which vary by version)
                $gpoLinkage = Get-GPOLinkage
                $dcOnlyGPOs = @($gpoFindings | Where-Object {
                    # Normalize GUID to uppercase for hashtable lookup
                    $links = $gpoLinkage[$_.Name.ToUpper()]
                    if (-not $links) { return $false }

                    $activeLinks = @($links | Where-Object { $_.LinkStatus -ne "Disabled" })
                    if ($activeLinks.Count -eq 0) { return $false }

                    # Check if ALL active links are to Domain Controllers OU only
                    $allLinksToDCOU = $true
                    foreach ($link in $activeLinks) {
                        if ($link.DistinguishedName -notmatch 'OU=Domain Controllers') {
                            $allLinksToDCOU = $false
                            break
                        }
                    }
                    return $allLinksToDCOU
                })

                # If ALL SMB Signing GPOs are DC-only, warn about member servers
                if (@($dcOnlyGPOs).Count -eq @($gpoFindings).Count) {
                    Show-Line "SMB Signing only configured for Domain Controllers - Member Servers and Clients rely on OS defaults (varies by version)" -Class Finding
                }

                # Check for insecure configurations and report findings
                $insecureGPOs = @()
                foreach ($gpoFinding in $gpoFindings) {
                    # Server: Disabled or Optional is insecure (allows relay attacks)
                    if ($gpoFinding.ServerSigning -eq "Disabled" -or $gpoFinding.ServerSigning -eq "Optional") {
                        $insecureGPOs += $gpoFinding.DisplayName
                    }
                    # Client: Only flag as insecure if explicitly Disabled
                    elseif ($gpoFinding.ClientSigning -eq "Disabled") {
                        $insecureGPOs += $gpoFinding.DisplayName
                    }
                }

                if ($insecureGPOs.Count -gt 0) {
                    Show-Line "$($insecureGPOs.Count) GPO(s) with insecure SMB Signing configuration" -Class Finding
                }

            } else {
                Show-Line "No SMB Signing configuration found in any GPO - computers rely on OS defaults (varies by Windows version)" -Class Finding
            }

        } catch {
            Write-Log "[Get-SMBSigningStatus] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-SMBSigningStatus] Check completed"
    }
}
