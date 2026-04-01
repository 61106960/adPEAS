function Get-LDAPConfiguration {
    <#
    .SYNOPSIS
    Checks LDAP Security Configuration (Signing + Channel Binding + Anonymous Binding).

    .DESCRIPTION
    Analyzes LDAP security configuration on Domain Controllers:

    1. LDAP Signing: Protects against LDAP Relay attacks
       - None (0): Insecure
       - Optional (1): Partially Secure
       - Required (2): Secure

    2. LDAP Channel Binding: Protection against Man-in-the-Middle
       - Never (0): Insecure
       - When Supported (1): Partially Secure
       - Always (2): Secure

    3. Anonymous LDAP Binding: Prevents unauthenticated AD enumeration
       - Allowed: Insecure
       - Restricted: Secure

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-LDAPConfiguration

    .EXAMPLE
    Get-LDAPConfiguration -Domain "contoso.com" -Credential (Get-Credential)

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
        Write-Log "[Get-LDAPConfiguration] Starting check"
    }

    process {
        try {
            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Analyzing LDAP Signing/Channel Binding via GPO (SYSVOL)..." -ObjectType "LDAPConfigGPO"

            $domainFQDN = $Script:LDAPContext.Domain
            $dcServer = $Script:LDAPContext.Server

            $allGPOs = Get-DomainGPO @PSBoundParameters

            if (-not $allGPOs) {
                Show-Line "No GPOs found" -Class Hint
                return
            }

            # Get Domain Controllers
            $domainControllers = @(Get-DomainComputer -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" @PSBoundParameters)

            $dcCount = $domainControllers.Count

            # Use Invoke-SMBAccess for SYSVOL access (handles SimpleBind credentials)
            $Script:gpoFindings = @()
            $Script:sysvolAccessible = $false

            Invoke-SMBAccess -Description "Scanning SYSVOL for LDAP configuration GPOs" -ScriptBlock {
                $sysvolPath = "\\$dcServer\SYSVOL\$domainFQDN\Policies"

                # Test SYSVOL access
                if (-not (Test-Path $sysvolPath)) {
                    Write-Log "[Get-LDAPConfiguration] SYSVOL path not accessible: $sysvolPath"
                    return
                }

                $Script:sysvolAccessible = $true

                # Parse GPOs for LDAP Security settings
                $totalGPOs = @($allGPOs).Count
                $currentGPOIndex = 0
                foreach ($gpo in $allGPOs) {
                    $currentGPOIndex++
                    if ($totalGPOs -gt $Script:ProgressThreshold) {
                        Show-Progress -Activity "Scanning LDAP configuration GPO settings" -Current $currentGPOIndex -Total $totalGPOs -ObjectName $gpo.DisplayName
                    }
                    $gptTmplPath = Join-Path $sysvolPath "$($gpo.Name)\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

                    $content = Get-CachedSYSVOLContent -Path $gptTmplPath
                    if ($content) {
                        # Initialize values
                        $ldapSigningValue = $null
                        $ldapChannelBindingValue = $null
                        $restrictAnonymous = $null
                        $lsaAnonymousNameLookup = $null

                        # Parse Registry Values section
                        if ($content -match '(?s)\[Registry Values\](.*?)(\[|$)') {
                            $registrySection = $Matches[1]

                            # GptTmpl.inf format: MACHINE\...\LDAPServerIntegrity=4,<value> (4 = REG_DWORD)
                            if ($registrySection -match 'MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LDAPServerIntegrity.*?=.*?4,(\d+)') {
                                $ldapSigningValue = [int]$Matches[1]
                            }
                            if ($registrySection -match 'MACHINE\\System\\CurrentControlSet\\Services\\NTDS\\Parameters\\LdapEnforceChannelBinding.*?=.*?4,(\d+)') {
                                $ldapChannelBindingValue = [int]$Matches[1]
                            }
                            if ($registrySection -match 'MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous.*?=.*?4,(\d+)') {
                                $restrictAnonymous = [int]$Matches[1]
                            }
                        }

                        # Parse System Access section
                        if ($content -match '(?s)\[System Access\](.*?)(\[|$)') {
                            $systemAccessSection = $Matches[1]
                            if ($systemAccessSection -match 'LSAAnonymousNameLookup\s*=\s*(\d+)') {
                                $lsaAnonymousNameLookup = [int]$Matches[1]
                            }
                        }

                        # If any LDAP security settings found
                        if ($null -ne $ldapSigningValue -or $null -ne $ldapChannelBindingValue -or
                            $null -ne $restrictAnonymous -or $null -ne $lsaAnonymousNameLookup) {

                            $signingLevel = if ($null -ne $ldapSigningValue) {
                                switch ($ldapSigningValue) {
                                    0 { "None" }
                                    1 { "Optional" }
                                    2 { "Required" }
                                    default { "Unknown" }
                                }
                            } else { "Not Configured" }

                            $channelBindingLevel = if ($null -ne $ldapChannelBindingValue) {
                                switch ($ldapChannelBindingValue) {
                                    0 { "Never" }
                                    1 { "When Supported" }
                                    2 { "Always" }
                                    default { "Unknown" }
                                }
                            } else { "Not Configured" }

                            $anonymousBindingStatus = "Not Configured"
                            if ($null -ne $restrictAnonymous) {
                                $anonymousBindingStatus = if ($restrictAnonymous -eq 0) { "Allowed" } else { "Restricted" }
                            } elseif ($null -ne $lsaAnonymousNameLookup) {
                                $anonymousBindingStatus = if ($lsaAnonymousNameLookup -eq 1) { "Allowed" } else { "Restricted" }
                            }

                            # Get GPO linkage
                            $gpoLinkage = Get-GPOLinkage
                            # Normalize GUID to uppercase for hashtable lookup (Get-GPOLinkage uses uppercase keys)
                            $gpoNameUpper = $gpo.Name.ToUpper()
                            $links = $gpoLinkage[$gpoNameUpper]
                            $activeLinks = @()
                            $isDomainWide = $false
                            $coversDCs = $false

                            if ($links) {
                                $activeLinks = @($links | Where-Object { $_.LinkStatus -ne "Disabled" })
                                $domainWide = $activeLinks | Where-Object { $_.Scope -eq "Domain" }
                                $isDomainWide = ($null -ne $domainWide)

                                # Check if Domain Controllers OU is covered
                                if ($isDomainWide) {
                                    $coversDCs = $true
                                } else {
                                    foreach ($dc in $domainControllers) {
                                        if ($dc.distinguishedName -match '^CN=[^,]+,(.+)$') {
                                            $dcParentDN = $Matches[1]
                                            foreach ($link in $activeLinks) {
                                                # Check if the GPO link DN is an ancestor of the DC's parent OU
                                                # The link DN should be at the end of (or equal to) the DC's parent DN
                                                if ($dcParentDN -like "*$($link.DistinguishedName)" -or $dcParentDN -eq $link.DistinguishedName) {
                                                    $coversDCs = $true
                                                    break
                                                }
                                            }
                                        }
                                        if ($coversDCs) { break }
                                    }
                                }
                            }

                            # Enrich the native GPO object with LDAP security attributes
                            $gpo | Add-Member -NotePropertyName "LDAPSigning" -NotePropertyValue $signingLevel -Force
                            $gpo | Add-Member -NotePropertyName "ChannelBinding" -NotePropertyValue $channelBindingLevel -Force
                            $gpo | Add-Member -NotePropertyName "AnonymousBinding" -NotePropertyValue $anonymousBindingStatus -Force
                            $gpo | Add-Member -NotePropertyName "CoversDCs" -NotePropertyValue $coversDCs -Force

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

                            $Script:gpoFindings += $gpo
                        }
                    }
                }
                if ($totalGPOs -gt $Script:ProgressThreshold) {
                    Show-Progress -Activity "Scanning LDAP configuration GPO settings" -Completed
                }
            }

            # Copy findings from script scope
            $gpoFindings = $Script:gpoFindings
            $Script:gpoFindings = $null
            $sysvolAccessible = $Script:sysvolAccessible
            $Script:sysvolAccessible = $null

            # Check if SYSVOL was accessible
            if (-not $sysvolAccessible) {
                if ((Test-SysvolAccessible) -eq $false) {
                    Show-Line "Skipped - SYSVOL not accessible" -Class Hint
                } else {
                    Show-Line "SYSVOL access failed - cannot analyze GPO configuration for LDAP Security - SMB access failed (authentication/network issue)" -Class Finding
                }
                return
            }

            if ($gpoFindings -and $gpoFindings.Count -gt 0) {
                # Show Found message BEFORE data
                Show-Line "Found LDAP security configuration in $($gpoFindings.Count) GPO(s):" -Class Hint
                foreach ($gpoFinding in $gpoFindings) {
                    $gpoFinding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LDAPConfigGPO' -Force
                    Show-Object $gpoFinding
                }

                # ============================================================
                # EFFECTIVE SETTINGS SUMMARY (PoC)
                # ============================================================
                # Calculate effective settings based on GPO priority
                # Priority: OU GPOs > Domain GPOs (Last Writer Wins)
                # For DCs: Domain Controllers OU GPO > Domain GPO
                # ============================================================

                # Get GPO linkage for priority calculation
                $gpoLinkage = Get-GPOLinkage

                # Separate GPOs by scope (for DC-focused effective calculation)
                $dcOuGPOs = @()
                $domainGPOs = @()

                foreach ($gpoFinding in $gpoFindings) {
                    # Normalize GUID to uppercase for hashtable lookup
                    $links = $gpoLinkage[$gpoFinding.Name.ToUpper()]
                    if ($links) {
                        $activeLinks = @($links | Where-Object { $_.LinkStatus -ne "Disabled" })

                        # Check if linked to Domain Controllers OU
                        $dcOuLink = $activeLinks | Where-Object {
                            $_.DistinguishedName -match 'OU=Domain Controllers'
                        }

                        # Check if linked to Domain root
                        $domainLink = $activeLinks | Where-Object { $_.Scope -eq "Domain" }

                        if ($dcOuLink) {
                            $dcOuGPOs += $gpoFinding
                        } elseif ($domainLink) {
                            $domainGPOs += $gpoFinding
                        }
                    }
                }

                # Calculate effective values (OU GPO wins over Domain GPO)
                $effectiveSigning = "Not Configured"
                $effectiveChannelBinding = "Not Configured"
                $effectiveAnonymous = "Not Configured"

                # First apply Domain-level GPOs (lower priority)
                foreach ($gpo in $domainGPOs) {
                    if ($gpo.LDAPSigning -ne "Not Configured") {
                        $effectiveSigning = $gpo.LDAPSigning
                    }
                    if ($gpo.ChannelBinding -ne "Not Configured") {
                        $effectiveChannelBinding = $gpo.ChannelBinding
                    }
                    if ($gpo.AnonymousBinding -ne "Not Configured") {
                        $effectiveAnonymous = $gpo.AnonymousBinding
                    }
                }

                # Then apply DC OU GPOs (higher priority, overwrites Domain)
                foreach ($gpo in $dcOuGPOs) {
                    if ($gpo.LDAPSigning -ne "Not Configured") {
                        $effectiveSigning = $gpo.LDAPSigning
                    }
                    if ($gpo.ChannelBinding -ne "Not Configured") {
                        $effectiveChannelBinding = $gpo.ChannelBinding
                    }
                    if ($gpo.AnonymousBinding -ne "Not Configured") {
                        $effectiveAnonymous = $gpo.AnonymousBinding
                    }
                }

                # Determine severity for each setting
                # Note: "Not Configured" = Windows default (Negotiate Signing) = Hint, not Finding
                $signingClass = switch ($effectiveSigning) {
                    "Required" { "Secure" }
                    "Optional" { "Hint" }
                    "None" { "Finding" }
                    "Not Configured" { "Hint" }  # Default is "Negotiate Signing" (Optional)
                    default { "Hint" }
                }

                $channelBindingClass = switch ($effectiveChannelBinding) {
                    "Always" { "Secure" }
                    "When Supported" { "Hint" }
                    "Never" { "Finding" }
                    "Not Configured" { "Hint" }  # Default depends on Windows version
                    default { "Hint" }
                }

                $anonymousClass = switch ($effectiveAnonymous) {
                    "Restricted" { "Secure" }
                    "Allowed" { "Finding" }
                    "Not Configured" { "Hint" }  # Default is restricted in modern Windows
                    default { "Hint" }
                }

                # Display effective settings summary as object
                # Determine overall severity based on worst setting
                $overallClass = "Hint"
                if ($signingClass -eq "Finding" -or $channelBindingClass -eq "Finding" -or $anonymousClass -eq "Finding") {
                    $overallClass = "Finding"
                } elseif ($signingClass -eq "Secure" -and $channelBindingClass -eq "Secure" -and $anonymousClass -eq "Secure") {
                    $overallClass = "Secure"
                }

                $effectiveConfigObj = [PSCustomObject]@{
                    LDAPSigning = $effectiveSigning
                    ChannelBinding = $effectiveChannelBinding
                    AnonymousBinding = $effectiveAnonymous
                }

                Show-Line "Effective LDAP Security Configuration for Domain Controllers:" -Class $overallClass
                $effectiveConfigObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'LDAPConfigEffective' -Force
                Show-Object $effectiveConfigObj

            } else {
                Show-Line "No LDAP Security configuration found in any GPO - all $dcCount DC(s) potentially vulnerable" -Class Finding
            }

        } catch {
            Write-Log "[Get-LDAPConfiguration] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-LDAPConfiguration] Check completed"
    }
}
