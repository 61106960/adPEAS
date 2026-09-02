# =============================================================================
# Point and Print policy keys deployed via Group Policy
# =============================================================================
# Registry roots. The hive prefix is NOT part of these paths - it comes from the
# SYSVOL location (Machine\Registry.pol -> HKLM, User\Registry.pol -> HKCU) or is
# read explicitly from Registry.xml.
$Script:PointAndPrintKeyRoot        = 'Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
$Script:PackagePointAndPrintKeyRoot = 'Software\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint'
$Script:PackagePointAndPrintServers = 'Software\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint\ListofServers'
$Script:PrintersPolicyKeyRoot       = 'Software\Policies\Microsoft\Windows NT\Printers'

# Values read from each root. Everything else in these keys is ignored.
$Script:PointAndPrintValues        = @(
    'Restricted', 'TrustedServers', 'ServerList', 'InForest',
    'NoWarningNoElevationOnInstall', 'UpdatePromptSettings',
    'RestrictDriverInstallationToAdministrators'
)
$Script:PackagePointAndPrintValues = @('PackagePointAndPrintOnly', 'PackagePointAndPrintServerList')
$Script:PrintersPolicyValues       = @(
    'RegisterSpoolerRemoteRpcEndPoint', 'CopyFilesPolicy',
    'DisableWebPnPDownload', 'DisableHTTPPrinting'
)

# "Devices: Prevent users from installing printer drivers" is a Security Option, not an
# Administrative Template. It ships in GptTmpl.inf, not Registry.pol. Declared in
# %WINDIR%\inf\sceregvl.inf as REG_DWORD (type 4). Note the two literal spaces in
# "LanMan Print Services" - the key name must not be whitespace-normalized.
$Script:AddPrinterDriversGptTmplPattern =
    'MACHINE\\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers\\AddPrinterDrivers\s*=\s*4\s*,\s*(\d+)'

function Get-GPOPointAndPrint {
    <#
    .SYNOPSIS
    Analyzes the Point and Print printer driver policies deployed via Group Policy.

    .DESCRIPTION
    Reports the complete Point and Print configuration of every GPO that deploys one, and
    derives from it whether a non-administrator can install a printer driver (which is code
    running as SYSTEM) on the machines in scope.

    Unlike Get-GPORegistrySettings, which flags single dangerous values, this check evaluates
    the combination, because no single Point and Print value decides exploitability:

      1. RestrictDriverInstallationToAdministrators is 1 or absent -> the install is blocked
         and nothing else matters. Since the 2021-08-10 update this is the default, so a GPO
         suppressing the elevation prompt is inert on patched machines and must not be
         reported as an exploitable finding on its own.
      2. RestrictDriverInstallationToAdministrators = 0 re-opens the install, and then
         NoWarningNoElevationOnInstall = 1 or UpdatePromptSettings = 2 removes the elevation
         prompt. That combination is PrintNightmare-style privilege escalation.
      3. Approved-server restrictions (TrustedServers/ServerList, InForest, Package Point and
         Print) never compensate for a suppressed prompt. They are reported as the driver
         source, never as a mitigation of an exploitable configuration.

    Also reported, when the GPO sets them, are the related printer hardening values:
    RegisterSpoolerRemoteRpcEndPoint (remote spooler RPC endpoint), CopyFilesPolicy
    (queue-specific files, CVE-2021-36958), DisableWebPnPDownload and DisableHTTPPrinting
    (driver delivery over HTTP), and the Security Option "Devices: Prevent users from
    installing printer drivers" (AddPrinterDrivers) read from GptTmpl.inf.

    Settings found in User Configuration are reported separately and never scored as
    exploitable: Windows ignores Point and Print Restrictions in the user policy context
    (KB2307161), so a user-scope policy is a false sense of security, not a control.

    Only values a GPO actually sets are reported. An absent value means this GPO does not
    configure it, which is not the same as the domain being insecure - and since the Windows
    default is the secure one, absence is never reported as a finding.

    Requires SMB access to \\domain\SYSVOL.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-GPOPointAndPrint

    .EXAMPLE
    Get-GPOPointAndPrint -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: GPO
    Author: Alexander Sturz (@_61106960_)
    References:
    - https://itm4n.github.io/printnightmare-exploitation/
    - https://support.microsoft.com/en-us/topic/kb5005652-873642bf-2634-49c5-a23b-6d8e9a302872
    - https://learn.microsoft.com/en-US/troubleshoot/windows-client/group-policy/point-print-restrictions-policies-ignored
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
        Write-Log "[Get-GPOPointAndPrint] Starting check"
    }

    process {
        try {
            if (-not (Ensure-LDAPConnection @PSBoundParameters)) {
                return
            }

            Show-SubHeader "Analyzing Point and Print printer driver policies..." -ObjectType "PointAndPrintPolicy"

            $gpos = Get-DomainGPO @PSBoundParameters

            if (-not $gpos) {
                Show-Line "No GPOs found in domain" -Class Note
                return
            }

            $gpoNameMap = @{}
            foreach ($gpo in $gpos) {
                if ($gpo.Name) { $gpoNameMap[([string]$gpo.Name).ToUpper()] = $gpo.DisplayName }
            }

            $gpoLinkage = Get-GPOLinkage

            # Both Script-scoped variables below are written inside the Invoke-SMBAccess
            # scriptblock and cleared inline right after it - they are the documented
            # exception to the Clear-SessionState rule (same pattern as Get-GPORegistrySettings).
            $Script:_pnpConfigs = @{}
            $Script:sysvolAccessible = $false

            Invoke-SMBAccess -Description "Scanning GPO files for Point and Print settings" -ScriptBlock {
                $sysvolPath = "\\$($Script:LDAPContext.Server)\SYSVOL\$($Script:LDAPContext.Domain)\Policies"

                if (-not (Test-Path $sysvolPath)) {
                    return
                }

                $Script:sysvolAccessible = $true

                # One cached SYSVOL walk covers all three delivery mechanisms
                $files = @(Get-CachedSYSVOLFiles -Filter @("Registry.pol", "Registry.xml", "GptTmpl.inf"))

                if ($files.Count -eq 0) {
                    Write-Log "[Get-GPOPointAndPrint] No policy files found in SYSVOL"
                    return
                }

                Write-Log "[Get-GPOPointAndPrint] Found $($files.Count) policy file(s)"

                $totalFiles = $files.Count
                $currentIndex = 0
                foreach ($file in $files) {
                    $currentIndex++
                    if ($totalFiles -gt $Script:ProgressThreshold) {
                        Show-Progress -Activity "Scanning Point and Print policies" -Current $currentIndex -Total $totalFiles -ObjectName $file.Name
                    }

                    # Extract GPO GUID from path: ...\Policies\{GUID}\...
                    if ($file.FullName -notmatch '\\Policies\\(\{[^}]+\})\\') { continue }
                    $gpoGUID = $Matches[1].ToUpper()

                    try {
                        if ($file.Name -ieq 'GptTmpl.inf') {
                            Read-PrintSecurityOption -FilePath $file.FullName -GPOGUID $gpoGUID
                            continue
                        }

                        $records = @()
                        $source = $null
                        if ($file.Name -ieq 'Registry.pol') {
                            # Machine\Registry.pol -> HKLM, User\Registry.pol -> HKCU
                            $hive = if ($file.FullName -match '\\Machine\\') { 'HKLM' } else { 'HKCU' }
                            $records = @(Parse-PRegRecords -PolFilePath $file.FullName -Hive $hive)
                            $source = 'Registry.pol'
                        } else {
                            $records = @(Parse-RegistryXml -XmlFilePath $file.FullName)
                            $source = 'Registry.xml'
                        }

                        Add-PointAndPrintRecords -Records $records -GPOGUID $gpoGUID -Source $source
                    } catch {
                        Write-Log "[Get-GPOPointAndPrint] Error parsing $($file.FullName): $_"
                    }
                }
                if ($totalFiles -gt $Script:ProgressThreshold) { Show-Progress -Activity "Scanning Point and Print policies" -Completed }
            }

            # Retrieve results and clean up Script-scoped temp variables
            $configs = $Script:_pnpConfigs
            $sysvolAccessible = $Script:sysvolAccessible
            $Script:_pnpConfigs = $null
            $Script:sysvolAccessible = $null

            if (-not $sysvolAccessible) {
                if ((Test-SysvolAccessible) -eq $false) {
                    Show-Line "Skipped - SYSVOL not accessible" -Class Hint
                } else {
                    Show-Line "SYSVOL access failed - cannot analyze Point and Print policies - SMB access failed (authentication/network issue)" -Class Finding
                }
                return
            }

            if ($configs.Count -eq 0) {
                Show-Line "No GPO configures Point and Print or printer driver policies - the secure Windows default applies" -Class Secure
                return
            }

            # Build one display object per GPO and scope
            $objects = @()
            foreach ($bucketKey in $configs.Keys) {
                $config = $configs[$bucketKey]
                $config['GPOName'] = if ($gpoNameMap.ContainsKey($config['GPOGUID'])) { $gpoNameMap[$config['GPOGUID']] } else { $config['GPOGUID'] }
                $objects += New-PointAndPrintObject -Config $config -GPOLinkage $gpoLinkage
            }

            # Most severe first, then alphabetically - exploitable GPOs must not be buried
            $severityRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4 }
            $objects = @($objects | Sort-Object -Property `
                @{ Expression = { if ($severityRank.ContainsKey($_.Severity)) { $severityRank[$_.Severity] } else { 9 } } }, `
                @{ Expression = { $_.GPOName } })

            $exploitable = @($objects | Where-Object { $_.Exploitability -like 'Exploitable*' })

            Show-Line "Found $($objects.Count) GPO configuration(s) with Point and Print or printer driver settings" -Class Hint

            if ($exploitable.Count -gt 0) {
                Show-Line "$($exploitable.Count) GPO configuration(s) let non-administrators install printer drivers without an elevation prompt" -Class Finding
            }

            foreach ($object in $objects) {
                Show-Object $object
            }

        } catch {
            Write-Log "[Get-GPOPointAndPrint] Error: $_" -Level Error
        }
    }

    end {
        Write-Log "[Get-GPOPointAndPrint] Check completed"
    }
}

# =============================================================================
# Helper: Get (or create) the per-GPO, per-scope configuration bucket
# =============================================================================
function Get-PointAndPrintBucket {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$GPOGUID,

        [Parameter(Mandatory=$true)]
        [ValidateSet('HKLM', 'HKCU')]
        [string]$Hive
    )

    $bucketKey = "$GPOGUID|$Hive"

    if (-not $Script:_pnpConfigs.ContainsKey($bucketKey)) {
        $Script:_pnpConfigs[$bucketKey] = @{
            GPOGUID        = $GPOGUID
            Hive           = $Hive
            Values         = @{}
            PackageServers = @()
            Sources        = @{}
        }
    }

    return $Script:_pnpConfigs[$bucketKey]
}

# =============================================================================
# Helper: Pick the Point and Print values out of one file's registry records
# =============================================================================
function Add-PointAndPrintRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [array]$Records,

        [Parameter(Mandatory=$true)]
        [string]$GPOGUID,

        [Parameter(Mandatory=$true)]
        [string]$Source
    )

    foreach ($record in $Records) {
        $hive = [string]$record.Hive
        if ($hive -ne 'HKLM' -and $hive -ne 'HKCU') { continue }

        $valueName = [string]$record.ValueName

        # Registry.pol carries delete instructions as pseudo-values (**del.<name>,
        # **delvals., **DeleteValues). A policy set to Disabled writes them alongside its
        # disabledValue, so treating them as configured values would report a deliberately
        # disabled policy as a configured one.
        if ($valueName.StartsWith('**')) { continue }

        $key = ([string]$record.Key -replace '^\\+', '').TrimEnd('\')

        $matchedRoot = $null
        if ($key -ieq $Script:PointAndPrintKeyRoot -and $valueName -in $Script:PointAndPrintValues) {
            $matchedRoot = 'PointAndPrint'
        } elseif ($key -ieq $Script:PackagePointAndPrintKeyRoot -and $valueName -in $Script:PackagePointAndPrintValues) {
            $matchedRoot = 'PackagePointAndPrint'
        } elseif ($key -ieq $Script:PackagePointAndPrintServers) {
            $matchedRoot = 'ListofServers'
        } elseif ($key -ieq $Script:PrintersPolicyKeyRoot -and $valueName -in $Script:PrintersPolicyValues) {
            $matchedRoot = 'Printers'
        }

        if (-not $matchedRoot) { continue }

        $bucket = Get-PointAndPrintBucket -GPOGUID $GPOGUID -Hive $hive
        $bucket['Sources'][$Source] = $true

        if ($matchedRoot -eq 'ListofServers') {
            # In this key the value NAME is the server: the ADMX list element has no
            # valuePrefix, so entries are "prn01.contoso.com"="prn01.contoso.com",
            # not numbered 1,2,3.
            if ($valueName) { $bucket['PackageServers'] += $valueName }
            continue
        }

        # A DWORD lands in ValueInt, a REG_SZ in ValueString. Never collapse either via
        # truthiness: 0 and the empty string are both configured values here.
        if ($null -ne $record.ValueInt) {
            $bucket['Values'][$valueName] = [int64]$record.ValueInt
        } elseif ($null -ne $record.ValueString) {
            $bucket['Values'][$valueName] = [string]$record.ValueString
        }
    }
}

# =============================================================================
# Helper: Read the AddPrinterDrivers Security Option from GptTmpl.inf
# =============================================================================
function Read-PrintSecurityOption {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [string]$GPOGUID
    )

    try {
        $content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
        if (-not $content) { return }

        if ($content -notmatch '(?s)\[Registry Values\](.*?)(\[|$)') { return }
        $registrySection = $Matches[1]

        if ($registrySection -match $Script:AddPrinterDriversGptTmplPattern) {
            # GptTmpl.inf Security Options are always machine scope
            $bucket = Get-PointAndPrintBucket -GPOGUID $GPOGUID -Hive 'HKLM'
            $bucket['Sources']['GptTmpl.inf'] = $true
            $bucket['Values']['AddPrinterDrivers'] = [int64]$Matches[1]
        }
    } catch {
        Write-Log "[Read-PrintSecurityOption] Error parsing $FilePath : $_"
    }
}

# =============================================================================
# Helper: Read one configured value, or $null when this GPO does not set it
# =============================================================================
function Get-PointAndPrintValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Values,

        [Parameter(Mandatory=$true)]
        [string]$Name
    )

    if (-not $Values.ContainsKey($Name)) { return $null }
    return $Values[$Name]
}

<#
.SYNOPSIS
    Evaluates whether the Point and Print configuration of one GPO lets a non-administrator
    install a printer driver.

.DESCRIPTION
    Implements the gate order the print spooler applies since the 2021-08-10 update:
    RestrictDriverInstallationToAdministrators decides first, and the prompt settings only
    matter once it is explicitly 0. Approved-server restrictions are deliberately NOT part of
    this evaluation - they cannot compensate for a suppressed elevation prompt.

.PARAMETER Values
    Configured value name -> value for one GPO and scope.

.PARAMETER Hive
    'HKLM' for Computer Configuration, 'HKCU' for User Configuration.

.OUTPUTS
    Hashtable @{ Exploitability = <string>; Severity = <string> }

.NOTES
    Internal helper function
#>
function Get-PointAndPrintAssessment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Values,

        [Parameter(Mandatory=$true)]
        [ValidateSet('HKLM', 'HKCU')]
        [string]$Hive
    )

    # User Configuration is never enforced for Point and Print (KB2307161), so it is
    # reported but never assessed as exploitable - in either direction.
    if ($Hive -eq 'HKCU') {
        return @{
            Exploitability = 'Not assessed - Windows ignores Point and Print Restrictions set in User Configuration'
            Severity       = 'Low'
        }
    }

    $restrictToAdmins = Get-PointAndPrintValue -Values $Values -Name 'RestrictDriverInstallationToAdministrators'
    $noWarnOnInstall  = Get-PointAndPrintValue -Values $Values -Name 'NoWarningNoElevationOnInstall'
    $updatePrompt     = Get-PointAndPrintValue -Values $Values -Name 'UpdatePromptSettings'
    $restricted       = Get-PointAndPrintValue -Values $Values -Name 'Restricted'

    $driverInstallOpen = ($null -ne $restrictToAdmins -and [int64]$restrictToAdmins -eq 0)
    $promptSuppressed  = (($null -ne $noWarnOnInstall -and [int64]$noWarnOnInstall -eq 1) -or
                          ($null -ne $updatePrompt -and [int64]$updatePrompt -eq 2))
    $policyDisabled    = ($null -ne $restricted -and [int64]$restricted -eq 0)

    if ($driverInstallOpen -and $promptSuppressed) {
        return @{
            Exploitability = 'Exploitable - non-administrators install printer drivers with no elevation prompt (PrintNightmare)'
            Severity       = 'Critical'
        }
    }

    if ($driverInstallOpen -and $policyDisabled) {
        return @{
            Exploitability = 'Exploitable - driver installation is open to non-administrators and the Point and Print Restrictions policy is disabled'
            Severity       = 'High'
        }
    }

    if ($driverInstallOpen) {
        return @{
            Exploitability = 'Weakened - non-administrators may install printer drivers, an elevation prompt is still shown'
            Severity       = 'Medium'
        }
    }

    # Checked before the prompt settings on purpose: an explicit 1 blocks the install, so any
    # prompt suppression in the same GPO is dead configuration rather than a latent risk. The
    # Latent verdict below is reserved for the case where the block rests on the default.
    if ($null -ne $restrictToAdmins -and [int64]$restrictToAdmins -eq 1) {
        return @{
            Exploitability = 'Hardened - driver installation is limited to Administrators, which overrides every Point and Print prompt setting'
            Severity       = 'Info'
        }
    }

    if ($promptSuppressed -or $policyDisabled) {
        return @{
            Exploitability = 'Latent - elevation prompts are suppressed, currently blocked by the RestrictDriverInstallationToAdministrators default'
            Severity       = 'Medium'
        }
    }

    return @{
        Exploitability = 'Not applicable - this GPO configures no printer driver installation control'
        Severity       = 'Info'
    }
}

<#
.SYNOPSIS
    Describes the approved driver source configured by one GPO.

.DESCRIPTION
    Package Point and Print is the only restriction that actually holds: an approved-server
    list alone is bypassable, because a client falls back to a non-package connection whenever
    the package connection fails, including when this policy blocks it. The legacy
    TrustedServers/InForest restrictions are reported but never as a mitigation - they are
    irrelevant once the elevation prompt is suppressed.

.PARAMETER Values
    Configured value name -> value for one GPO and scope.

.PARAMETER PackageServers
    Server names collected from the PackagePointAndPrint\ListofServers key.

.OUTPUTS
    Hashtable @{ Source = <string>; Servers = <string[]> }

.NOTES
    Internal helper function
#>
function Get-PointAndPrintDriverSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Values,

        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [array]$PackageServers
    )

    $packageOnly = Get-PointAndPrintValue -Values $Values -Name 'PackagePointAndPrintOnly'
    $packageList = Get-PointAndPrintValue -Values $Values -Name 'PackagePointAndPrintServerList'
    $trustedOn   = Get-PointAndPrintValue -Values $Values -Name 'TrustedServers'
    $trustedList = Get-PointAndPrintValue -Values $Values -Name 'ServerList'
    $inForest    = Get-PointAndPrintValue -Values $Values -Name 'InForest'

    $isPackageOnly = ($null -ne $packageOnly -and [int64]$packageOnly -eq 1)
    $servers       = @($PackageServers | Where-Object { $_ } | Sort-Object -Unique)
    $isPackageList = ($null -ne $packageList -and [int64]$packageList -eq 1 -and $servers.Count -gt 0)

    if ($isPackageOnly -and $isPackageList) {
        return @{ Source = 'Approved package servers only (Package Point and Print enforced)'; Servers = $servers }
    }

    if ($isPackageList) {
        return @{ Source = 'Approved server list set, but bypassable - Package Point and Print is not enforced'; Servers = $servers }
    }

    if ($isPackageOnly) {
        return @{ Source = 'Package Point and Print enforced, but no approved server list - any server may supply drivers'; Servers = @() }
    }

    # The legacy list is one REG_SZ holding semicolon-separated server names
    $legacyServers = @()
    if ($null -ne $trustedList -and -not [string]::IsNullOrWhiteSpace([string]$trustedList)) {
        $legacyServers = @(([string]$trustedList).Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    if ($null -ne $trustedOn -and [int64]$trustedOn -eq 1 -and $legacyServers.Count -gt 0) {
        return @{ Source = 'Trusted servers only (legacy Point and Print list)'; Servers = $legacyServers }
    }

    if ($null -ne $inForest -and [int64]$inForest -eq 1) {
        return @{ Source = 'Forest computers only (legacy Point and Print restriction)'; Servers = @() }
    }

    return @{ Source = 'Not restricted in this GPO - drivers may come from any print server'; Servers = $legacyServers }
}

<#
.SYNOPSIS
    Builds the display object for the Point and Print settings of one GPO and scope.

.DESCRIPTION
    Converts the collected raw values into human-readable strings so the finding triggers in
    adPEAS-FindingDefinitions.ps1 can colour them and attach tooltips. Only values the GPO
    actually sets become attributes - an absent value means this GPO does not configure it,
    which is not the same as it being set to 0.

.PARAMETER Config
    One per-GPO, per-scope bucket (GPOGUID, GPOName, Hive, Values, PackageServers, Sources).

.PARAMETER GPOLinkage
    Hashtable from Get-GPOLinkage (GPO GUID -> linked OUs), used to show where it applies.

.OUTPUTS
    PSCustomObject tagged as ObjectType 'PointAndPrintPolicy'.

.NOTES
    Internal helper function
#>
function New-PointAndPrintObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Config,

        [Parameter(Mandatory=$false)]
        [AllowNull()]
        [hashtable]$GPOLinkage
    )

    $values = $Config['Values']
    $hive   = $Config['Hive']

    $assessment = Get-PointAndPrintAssessment -Values $values -Hive $hive

    $obj = [PSCustomObject][ordered]@{
        GPOName = $Config['GPOName']
        Scope   = $(if ($hive -eq 'HKLM') { 'Computer Configuration' } else { 'User Configuration' })
        Source  = (@($Config['Sources'].Keys | Sort-Object) -join ', ')
    }

    $obj | Add-Member -NotePropertyName 'Exploitability' -NotePropertyValue $assessment.Exploitability -Force

    # RestrictDriverInstallationToAdministrators - the gate that decides everything else
    $restrictToAdmins = Get-PointAndPrintValue -Values $values -Name 'RestrictDriverInstallationToAdministrators'
    if ($null -ne $restrictToAdmins) {
        $text = if ([int64]$restrictToAdmins -eq 0) {
            'Open to non-administrators (RestrictDriverInstallationToAdministrators=0)'
        } else {
            'Limited to Administrators'
        }
        $obj | Add-Member -NotePropertyName 'DriverInstallRestriction' -NotePropertyValue $text -Force
    }

    # Restricted - the on/off state of the Point and Print Restrictions policy itself
    $restricted = Get-PointAndPrintValue -Values $values -Name 'Restricted'
    if ($null -ne $restricted) {
        $text = if ([int64]$restricted -eq 0) {
            'Disabled - no warning and no elevation prompt on Windows Vista and later'
        } else {
            'Enabled'
        }
        $obj | Add-Member -NotePropertyName 'PointAndPrintRestrictions' -NotePropertyValue $text -Force
    }

    # NoWarningNoElevationOnInstall - prompt shown for a NEW printer connection
    $noWarnOnInstall = Get-PointAndPrintValue -Values $values -Name 'NoWarningNoElevationOnInstall'
    if ($null -ne $noWarnOnInstall) {
        $text = if ([int64]$noWarnOnInstall -eq 1) {
            'No warning and no elevation prompt'
        } else {
            'Warning and elevation prompt'
        }
        $obj | Add-Member -NotePropertyName 'NewConnectionPrompt' -NotePropertyValue $text -Force
    }

    # UpdatePromptSettings - prompt shown when the driver of an EXISTING connection is
    # updated. 1 shows a warning but still requires elevation, only 2 is silent.
    $updatePrompt = Get-PointAndPrintValue -Values $values -Name 'UpdatePromptSettings'
    if ($null -ne $updatePrompt) {
        $text = switch ([int64]$updatePrompt) {
            0       { 'Warning and elevation prompt' }
            1       { 'Warning only, elevation still required' }
            2       { 'No warning and no elevation prompt' }
            default { "Unknown ($updatePrompt)" }
        }
        $obj | Add-Member -NotePropertyName 'DriverUpdatePrompt' -NotePropertyValue $text -Force
    }

    # Where drivers may come from - only stated for a GPO that touches Point and Print at
    # all, so the wording can never be read as a statement about the whole domain.
    $touchesPointAndPrint = $false
    foreach ($name in ($Script:PointAndPrintValues + $Script:PackagePointAndPrintValues)) {
        if ($values.ContainsKey($name)) { $touchesPointAndPrint = $true; break }
    }
    if (@($Config['PackageServers']).Count -gt 0) { $touchesPointAndPrint = $true }

    if ($touchesPointAndPrint) {
        $driverSource = Get-PointAndPrintDriverSource -Values $values -PackageServers @($Config['PackageServers'])
        $obj | Add-Member -NotePropertyName 'ApprovedDriverSource' -NotePropertyValue $driverSource.Source -Force
        if (@($driverSource.Servers).Count -gt 0) {
            $obj | Add-Member -NotePropertyName 'ApprovedServerList' -NotePropertyValue @($driverSource.Servers) -Force
        }
    }

    # RegisterSpoolerRemoteRpcEndPoint - note the inverted policy encoding: the policy
    # "Allow Print Spooler to accept client connections" writes 1 when Enabled and 2 when
    # Disabled, so 2 is the hardened state.
    $spoolerRpc = Get-PointAndPrintValue -Values $values -Name 'RegisterSpoolerRemoteRpcEndPoint'
    if ($null -ne $spoolerRpc) {
        $text = switch ([int64]$spoolerRpc) {
            1       { 'Accepted - the spooler exposes its remote RPC endpoint' }
            2       { 'Refused - the spooler does not accept remote client connections' }
            default { "Unknown ($spoolerRpc)" }
        }
        $obj | Add-Member -NotePropertyName 'SpoolerClientConnections' -NotePropertyValue $text -Force
    }

    # CopyFilesPolicy - only 2 re-opens the queue-specific file vector (CVE-2021-36958)
    $copyFiles = Get-PointAndPrintValue -Values $values -Name 'CopyFilesPolicy'
    if ($null -ne $copyFiles) {
        $text = switch ([int64]$copyFiles) {
            0       { 'Blocked - no queue-specific files are copied' }
            1       { 'Color profiles only (default)' }
            2       { 'All queue-specific files allowed - arbitrary files copied by the spooler' }
            default { "Unknown ($copyFiles)" }
        }
        $obj | Add-Member -NotePropertyName 'QueueSpecificFiles' -NotePropertyValue $text -Force
    }

    $webPnP = Get-PointAndPrintValue -Values $values -Name 'DisableWebPnPDownload'
    if ($null -ne $webPnP) {
        $text = if ([int64]$webPnP -eq 1) { 'Blocked' } else { 'Allowed - print drivers may be downloaded over HTTP' }
        $obj | Add-Member -NotePropertyName 'WebDriverDownload' -NotePropertyValue $text -Force
    }

    $httpPrint = Get-PointAndPrintValue -Values $values -Name 'DisableHTTPPrinting'
    if ($null -ne $httpPrint) {
        $text = if ([int64]$httpPrint -eq 1) { 'Blocked' } else { 'Allowed - printing over HTTP is permitted' }
        $obj | Add-Member -NotePropertyName 'HTTPPrinting' -NotePropertyValue $text -Force
    }

    # "Devices: Prevent users from installing printer drivers" - legacy Security Option. It
    # gates the local AddPrinterDriver path only and is not a substitute for
    # RestrictDriverInstallationToAdministrators, so it is reported as hardening hygiene.
    $addDrivers = Get-PointAndPrintValue -Values $values -Name 'AddPrinterDrivers'
    if ($null -ne $addDrivers) {
        $text = if ([int64]$addDrivers -eq 1) {
            'Only Administrators may install printer drivers'
        } else {
            'Any user may install printer drivers (Security Option disabled)'
        }
        $obj | Add-Member -NotePropertyName 'InstallDriversSecurityOption' -NotePropertyValue $text -Force
    }

    # GPO links - a policy that is linked nowhere applies to nothing, and a failed linkage
    # lookup must not be reported as "not linked".
    $gpoGuid = $Config['GPOGUID']
    $linkedOUs = @()
    if ($gpoGuid -and $GPOLinkage -and $GPOLinkage.ContainsKey($gpoGuid)) {
        $linkedOUs = @($GPOLinkage[$gpoGuid])
    }

    if ($linkedOUs.Count -gt 0) {
        $obj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue $linkedOUs -Force
    } elseif ($null -eq $GPOLinkage) {
        $obj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue 'Unknown - GPO linkage could not be resolved' -Force
    } else {
        $obj | Add-Member -NotePropertyName 'LinkedOUs' -NotePropertyValue 'Not linked - these settings apply nowhere' -Force
    }
    $obj | Add-Member -NotePropertyName 'LinkedOUCount' -NotePropertyValue $linkedOUs.Count -Force

    # Hidden from display (see $Script:ExcludeAttributes) - used for sorting and correlation
    $obj | Add-Member -NotePropertyName 'Severity' -NotePropertyValue $assessment.Severity -Force
    $obj | Add-Member -NotePropertyName 'GPOGUID' -NotePropertyValue $gpoGuid -Force
    $obj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PointAndPrintPolicy' -Force

    return $obj
}
