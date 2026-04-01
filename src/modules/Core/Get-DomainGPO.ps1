function Get-DomainGPO {
<#
.SYNOPSIS
    Central function for querying Group Policy Objects from Active Directory.

.DESCRIPTION
    Get-DomainGPO is a flexible helper function that unifies all GPO queries in adPEAS v2.
    It builds on Invoke-LDAPSearch and provides:

    - Search by Identity (DisplayName, DN, GUID)
    - Filter by specific criteria (Linked to OU, Disabled, etc.)
    - Flexible property selection
    - Custom LDAP filters

.PARAMETER Identity
    DisplayName, DistinguishedName, or GUID of the GPO.
    Automatically detects format:
    - GUID: {31B2F340-016D-11D2-945F-00C04FB984F9} or 31B2F340-016D-11D2-945F-00C04FB984F9
    - DN: CN={GUID},CN=Policies,CN=System,DC=domain,DC=com
    - DisplayName: "Default Domain Policy" (wildcards supported)

.PARAMETER AppliedToOU
    Returns all GPOs that are applied to the specified OU (DN format).
    Finds GPOs by querying the OU's gPLink attribute.

.PARAMETER Enabled
    Only fully enabled GPOs (flags=0).

.PARAMETER Disabled
    Only fully disabled GPOs (flags=3, all settings disabled).

.PARAMETER Domain
    Target domain for GPO search.

.PARAMETER LDAPFilter
    Custom LDAP filter for special queries.

.PARAMETER Properties
    Array of attribute names to return.
    Default: displayName, name, gPCFileSysPath, versionNumber, flags, whenCreated, whenChanged

.PARAMETER SearchBase
    Alternative SearchBase (DN). Default: CN=Policies,CN=System,DC=domain,DC=com

.PARAMETER ShowLinkedOU
    Returns only the OUs where the GPO is linked (array of DNs).
    Similar to -ShowMembers in Get-DomainGroup.
    Does not return the GPO object itself.

.PARAMETER ShowDangerousSettings
    Analyzes GPO settings for dangerous configurations (Scheduled Tasks, Scripts, etc.).
    Adds a DangerousSettings property to each GPO object.
    DEFENSIVE USE ONLY - for identifying attack surface and misconfigurations.

.PARAMETER ShowPermissions
    Analyzes GPO ACLs for dangerous permissions (non-admin users with edit rights).
    Adds a DangerousPermissions property to each GPO object.
    DEFENSIVE USE ONLY - for identifying privilege escalation paths.

.EXAMPLE
    Get-DomainGPO
    Returns all GPOs in the domain.

.EXAMPLE
    Get-DomainGPO -Identity "Default Domain Policy"
    Returns the Default Domain Policy GPO by DisplayName.

.EXAMPLE
    Get-DomainGPO -Identity "{31B2F340-016D-11D2-945F-00C04FB984F9}"
    Returns GPO by GUID (with curly braces).

.EXAMPLE
    Get-DomainGPO -Identity "31B2F340-016D-11D2-945F-00C04FB984F9"
    Returns GPO by GUID (without curly braces).

.EXAMPLE
    Get-DomainGPO -AppliedToOU "OU=Workstations,DC=contoso,DC=com"
    Returns all GPOs applied to the Workstations OU.

.EXAMPLE
    Get-DomainGPO -Enabled
    Returns only fully enabled GPOs (all settings active).

.EXAMPLE
    Get-DomainGPO -Disabled
    Returns only fully disabled GPOs (all settings disabled).

.EXAMPLE
    Get-DomainGPO -Identity "Default Domain Policy" -ShowLinkedOU
    Returns only the OUs where Default Domain Policy is linked (array of DNs).

.EXAMPLE
    Get-DomainGPO -ShowDangerousSettings
    Analyzes all GPOs for dangerous configurations like Scheduled Tasks or Scripts.

.EXAMPLE
    Get-DomainGPO -ShowPermissions
    Analyzes all GPOs for dangerous ACL permissions.

.EXAMPLE
    Get-DomainGPO -ShowLinkedOU -ShowDangerousSettings -ShowPermissions
    Complete security analysis of all GPOs.

.EXAMPLE
    Get-DomainGPO -LDAPFilter "(displayName=*Admin*)"
    Custom LDAP filter for special searches.

.OUTPUTS
    PSCustomObject with GPO attributes

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('DisplayName', 'Name', 'GPO')]
        [string]$Identity,

        [Parameter(Mandatory=$false)]
        [Alias('LinkedOU')]
        [string]$AppliedToOU,

        [Parameter(Mandatory=$false)]
        [switch]$Enabled,

        [Parameter(Mandatory=$false)]
        [switch]$Disabled,

        [Parameter(Mandatory=$false)]
        [string]$LDAPFilter,

        [Parameter(Mandatory=$false)]
        [string[]]$Properties,

        [Parameter(Mandatory=$false)]
        [switch]$ShowLinkedOU,

        [Parameter(Mandatory=$false)]
        [switch]$ShowDangerousSettings,

        [Parameter(Mandatory=$false)]
        [switch]$ShowPermissions,

        [Parameter(Mandatory=$false)]
        [string]$SearchBase,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$Raw
    )

    begin {
        Write-Log "[Get-DomainGPO] Starting GPO enumeration"
    }

    process {
        try {
            # Cache: Return cached GPOs for unfiltered calls (no Identity, no LDAPFilter, no switches)
            $isUnfilteredCall = -not $Identity -and -not $LDAPFilter -and -not $AppliedToOU -and -not $Enabled -and -not $Disabled -and -not $ShowLinkedOU -and -not $ShowDangerousSettings -and -not $ShowPermissions -and -not $Properties -and -not $SearchBase -and -not $Raw
            if ($isUnfilteredCall -and $Script:CachedAllGPOs) {
                Write-Log "[Get-DomainGPO] Returning cached GPO list ($($Script:CachedAllGPOs.Count) objects)"
                return $Script:CachedAllGPOs
            }

            # Validation: ShowLinkedOU requires Identity (ignore if not provided)
            if ($ShowLinkedOU -and -not $Identity) {
                Write-Log "[Get-DomainGPO] -ShowLinkedOU requires -Identity parameter - ignoring ShowLinkedOU switch"
                $ShowLinkedOU = $false
            }

            # Base Filter: groupPolicyContainer objects only
            $Filter = "(objectClass=groupPolicyContainer)"

            # Build Identity filter (auto-detects DisplayName, DN, or GUID)
            if ($Identity) {
                # Check if DN, GUID or DisplayName
                if ($Identity -match '^CN=.*') {
                    # Distinguished Name
                    $IdentityFilter = "(distinguishedName=$Identity)"
                    Write-Log "[Get-DomainGPO] Identity detected as DN"
                } elseif ($Identity -match '^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$') {
                    # GUID format - remove curly braces if present
                    $CleanGUID = $Identity.Trim('{}')
                    $IdentityFilter = "(name={$CleanGUID})"
                    Write-Log "[Get-DomainGPO] Identity detected as GUID: {$CleanGUID}"
                } else {
                    # DisplayName (with wildcard support)
                    $IdentityFilter = "(displayName=$Identity)"
                    Write-Log "[Get-DomainGPO] Identity detected as DisplayName"
                }

                $Filter = "(&$Filter$IdentityFilter)"
            }

            # Enabled/Disabled filter
            if ($Enabled) {
                # flags=0 means GPO is fully enabled
                $Filter = "(&$Filter(flags=0))"
                Write-Log "[Get-DomainGPO] Filtering for enabled GPOs (flags=0)"
            }

            if ($Disabled) {
                # flags=3 means all settings disabled (both Computer and User portions)
                $Filter = "(&$Filter(flags=3))"
                Write-Log "[Get-DomainGPO] Filtering for disabled GPOs (flags=3)"
            }

            # AppliedToOU filter - search for GPOs applied to specific OU
            if ($AppliedToOU) {
                Write-Log "[Get-DomainGPO] Searching for GPOs applied to OU: $AppliedToOU"

                # Query the OU for its gPLink attribute via Get-DomainObject
                $OUParams = @{
                    Identity = $AppliedToOU
                    Properties = @('gPLink')
                }

                $OU = Get-DomainObject @OUParams | Select-Object -First 1

                if ($OU -and $OU.gPLink) {
                    Write-Log "[Get-DomainGPO] gPLink: $($OU.gPLink)"

                    # Parse gPLink to extract GPO GUIDs
                    # Format: [LDAP://cn={GUID},cn=policies,cn=system,DC=domain,DC=com;0]
                    $GPOGUIDs = @()
                    $gPLinkMatches = [regex]::Matches($OU.gPLink, '\{([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}')

                    foreach ($Match in $gPLinkMatches) {
                        $GPOGUIDs += $Match.Groups[1].Value
                    }

                    if ($GPOGUIDs.Count -eq 0) {
                        Write-Log "[Get-DomainGPO] No GPOs applied to OU: $AppliedToOU"
                        return
                    }

                    Write-Log "[Get-DomainGPO] Found $($GPOGUIDs.Count) GPO(s) applied to OU"

                    # Build OR filter for all linked GPOs
                    if ($GPOGUIDs.Count -eq 1) {
                        $LinkedFilter = "(name={$($GPOGUIDs[0])})"
                    } else {
                        $LinkedFilterParts = $GPOGUIDs | ForEach-Object { "(name={$_})" }
                        $LinkedFilter = "(|$($LinkedFilterParts -join ''))"
                    }

                    $Filter = "(&$Filter$LinkedFilter)"
                } else {
                    Write-Log "[Get-DomainGPO] OU has no GPOs applied: $AppliedToOU"
                    return
                }
            }

            # Append custom LDAP filter
            if ($LDAPFilter) {
                $Filter = "(&$Filter$LDAPFilter)"
            }

            Write-Log "[Get-DomainGPO] Using filter: $Filter"

            # Build parameters for Get-DomainObject
            $GetParams = @{
                LDAPFilter = $Filter
            }

            # Do NOT pass Identity to Get-DomainObject!
            # The Identity filter is already built into $Filter above. Passing Identity would cause Get-DomainObject to override our filter.
            if ($Properties) {
                $GetParams['Properties'] = $Properties
            }

            if ($SearchBase) { $GetParams['SearchBase'] = $SearchBase }
            if ($Domain) { $GetParams['Domain'] = $Domain }
            if ($Server) { $GetParams['Server'] = $Server }
            if ($Credential) { $GetParams['Credential'] = $Credential }
            if ($Raw) { $GetParams['Raw'] = $true }

            $GPOs = @(Get-DomainObject @GetParams)

            Write-Log "[Get-DomainGPO] Found $($GPOs.Count) GPO(s)"

            # Enrich GPO objects with additional computed properties
            foreach ($GPO in $GPOs) {
                # Parse version number (high word = computer, low word = user)
                if ($GPO.versionNumber) {
                    $VersionNum = [int]$GPO.versionNumber
                    $ComputerVersion = $VersionNum -shr 16
                    $UserVersion = $VersionNum -band 0xFFFF

                    $GPO | Add-Member -NotePropertyName "ComputerVersion" -NotePropertyValue $ComputerVersion -Force
                    $GPO | Add-Member -NotePropertyName "UserVersion" -NotePropertyValue $UserVersion -Force
                }

                # Parse flags
                if ($null -ne $GPO.flags) {
                    $FlagsValue = [int]$GPO.flags
                    $Status = switch ($FlagsValue) {
                        0 { "Enabled" }
                        1 { "User portion disabled" }
                        2 { "Computer portion disabled" }
                        3 { "All settings disabled" }
                        default { "Unknown ($FlagsValue)" }
                    }

                    $GPO | Add-Member -NotePropertyName "GPOStatus" -NotePropertyValue $Status -Force
                }

                # CSE GUID to Name Mapping (Client-Side Extensions)
                $CSENames = @{
                    '{00000000-0000-0000-0000-000000000000}' = 'Core GPO Engine'
                    '{0E28E245-9368-4853-AD84-6DA3BA35BB75}' = 'Group Policy Preference Client Side Extension'
                    '{16BE69FA-4209-4250-88CB-716CF41954E0}' = 'Central Access Policy Configuration'
                    '{17D89FEC-5C44-4972-B12D-241CAEF74509}' = 'Group Policy Local Users and Groups'
                    '{1A6364EB-776B-4120-ADE1-B63A406A76B5}' = 'Group Policy Device Settings'
                    '{25537BA6-77A8-11D2-9B6C-0000F8080861}' = 'Folder Redirection'
                    '{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}' = 'Group Policy Disk Quota'
                    '{3060E8D0-7020-11D2-842D-00C04FA372D4}' = 'Remote Installation Services'
                    '{35378EAC-683F-11D2-A89A-00C04FBBCFA2}' = 'Registry'
                    '{3610EDA5-77EF-11D2-8DC5-00C04FA31A66}' = 'Disk Quota'
                    '{3A0DBA37-F8B2-4356-83DE-3E90BD5C261F}' = 'Group Policy Network Options'
                    '{426031c0-0b47-4852-b0ca-ac3d37bfcb39}' = 'QoS Packet Scheduler'
                    '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}' = 'Scripts'
                    '{4CFB60C1-FAA6-47f1-89AA-0B18730C9FD3}' = 'Internet Explorer Zonemapping'
                    '{5794DAFD-BE60-433f-88A2-1A31939AC01F}' = 'Group Policy Drive Maps'
                    '{6232C319-91AC-4931-9385-E70C2B099F0E}' = 'Group Policy Folder Options'
                    '{62C1845D-C4A6-4ACB-BBB0-C895FD090385}' = 'Microsoft Offline Files'
                    '{6A4C88C6-C502-4f74-8F60-2CB23EDC24E2}' = 'Group Policy Network Shares'
                    '{6C5A2A86-9EB3-42B9-AA83-A7371BA011B9}' = 'Windows Search Group Policy Extension'
                    '{728EE579-943C-4519-9EF7-AB56765798ED}' = 'Group Policy Data Sources'
                    '{74EE6C03-5363-4554-B161-627540339CAB}' = 'Group Policy Scheduled Tasks'
                    '{7933F41E-56F8-41d6-A31C-4148A711EE93}' = 'Windows Search Group Policy Extension'
                    '{79F92669-4224-476C-9C5C-6EFB4D87DF4A}' = 'Local Users and Groups'
                    '{7B849a69-220F-451E-B3FE-2CB811AF94AE}' = 'Internet Explorer Zonemapping'
                    '{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' = 'Security'
                    '{8A28E2C5-8D06-49A4-A08C-632DAA493E17}' = 'Deployed Printer Connections'
                    '{91FBB303-0CD5-4055-BF42-E512A681B325}' = 'Group Policy Services'
                    '{942A8E4F-A261-11D1-A760-00C04FB9603F}' = 'Software Installation'
                    '{9AD2BAFE-63B4-4883-A08C-C3C6196BCAFD}' = 'Power Options'
                    '{A2E30F80-D7DE-11D2-BBDE-00C04F86AE3B}' = 'Internet Explorer Branding'
                    '{A3F3E39B-5D83-4940-B954-28315B82F0A8}' = 'Group Policy Drive Maps'
                    '{AADCED64-746C-4633-A97C-D61349046527}' = 'Group Policy Folders'
                    '{B087BE9D-ED37-454F-AF9C-04291E351182}' = 'Group Policy Preferences'
                    '{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}' = 'EFS Recovery'
                    '{B587E2B1-4D59-4E7E-AED9-22B9DF11D053}' = '802.3 Group Policy'
                    '{B9CCA4DE-E2B9-4CBD-BF7D-11B6EBFBDDF7}' = 'Group Policy Network Options'
                    '{BC75B1ED-5833-4858-9BB4-B1E212E5790D}' = 'Group Policy INI Files'
                    '{C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7}' = 'Group Policy Shortcuts'
                    '{C631DF4C-088F-4156-B058-4375F0853CD8}' = 'Microsoft Offline Files'
                    '{CDEAFC3D-948D-49DD-AB12-E578BA4AF7AA}' = 'TCPIP'
                    '{D02B1F72-3407-48AE-BA88-E8213C6761F1}' = 'Wireless Group Policy'
                    '{E437BC1C-AA7D-11D2-A382-00C04F991E27}' = 'IP Security'
                    '{E47248BA-94CC-49C4-BBB5-9EB7F05183D0}' = 'Group Policy Internet Settings'
                    '{E4F48E54-F38D-4884-BFB9-D4D2E5729C18}' = 'Group Policy Start Menu Settings'
                    '{E5094040-C46C-4115-B030-04FB2E545B00}' = 'Group Policy Regional Options'
                    '{E62688F0-25FD-4c90-BFF5-F508B9D2E31F}' = 'Group Policy Environment'
                    '{E6BEFC42-E5F6-4AEB-B560-A2C1A6BEC5F0}' = 'Audit Policy'
                    '{F3CCC681-B74C-4060-9F26-CD84525DCA2A}' = 'Audit Policy Configuration'
                    '{F9C77450-3A41-477E-9310-9ACD617BD9E3}' = 'Group Policy Applications'
                    '{FC715823-C5FB-11D1-9EEF-00A0C90347FF}' = 'Internet Explorer Maintenance Extension Protocol'
                    '{FBF687E6-F063-4D9F-9F4F-FD9A26ACDD5F}' = 'Certificates'
                    '{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}' = 'Group Policy Infrastructure'
                }

                # Tool GUID to Snap-In Name Mapping
                $ToolNames = @{
                    '{0ACDD40C-75AC-47AB-BAA0-BF6DE7E7FE63}' = 'Wireless Group Policy'
                    '{0E28E245-9368-4853-AD84-6DA3BA35BB75}' = 'Group Policy Preference Tool'
                    '{16BE69FA-4209-4250-88CB-716CF41954E0}' = 'Central Access Policy'
                    '{17D89FEC-5C44-4972-B12D-241CAEF74509}' = 'Group Policy Local Users and Groups'
                    '{1A6364EB-776B-4120-ADE1-B63A406A76B5}' = 'Group Policy Device Settings'
                    '{25537BA6-77A8-11D2-9B6C-0000F8080861}' = 'Folder Redirection'
                    '{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}' = 'Group Policy Disk Quota'
                    '{3060E8CE-7020-11D2-842D-00C04FA372D4}' = 'Remote Installation Services'
                    '{3610EDA4-77EF-11D2-8DC5-00C04FA31A66}' = 'Disk Quota'
                    '{3A0DBA37-F8B2-4356-83DE-3E90BD5C261F}' = 'Group Policy Network Options'
                    '{40B6664F-4972-11D1-A7CA-0000F87571E3}' = 'Scripts'
                    '{426031c0-0b47-4852-b0ca-ac3d37bfcb39}' = 'QoS Packet Scheduler'
                    '{4CFB60C1-FAA6-47f1-89AA-0B18730C9FD3}' = 'Internet Explorer Zonemapping'
                    '{53D6AB1B-2488-11D1-A28C-00C04FB94F17}' = 'Registry Editor'
                    '{5794DAFD-BE60-433f-88A2-1A31939AC01F}' = 'Group Policy Drive Maps'
                    '{6232C319-91AC-4931-9385-E70C2B099F0E}' = 'Group Policy Folder Options'
                    '{6A4C88C6-C502-4f74-8F60-2CB23EDC24E2}' = 'Group Policy Network Shares'
                    '{6C5A2A86-9EB3-42B9-AA83-A7371BA011B9}' = 'Windows Search Group Policy Extension'
                    '{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}' = 'Group Policy Infrastructure'
                    '{728EE579-943C-4519-9EF7-AB56765798ED}' = 'Group Policy Data Sources'
                    '{74EE6C03-5363-4554-B161-627540339CAB}' = 'Group Policy Scheduled Tasks'
                    '{7933F41E-56F8-41d6-A31C-4148A711EE93}' = 'Windows Search Group Policy Extension'
                    '{79F92669-4224-476C-9C5C-6EFB4D87DF4A}' = 'Local Users and Groups'
                    '{7B849a69-220F-451E-B3FE-2CB811AF94AE}' = 'Internet Explorer Zonemapping'
                    '{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}' = 'Security Settings'
                    '{8A28E2C5-8D06-49A4-A08C-632DAA493E17}' = 'Deployed Printer Connections'
                    '{91FBB303-0CD5-4055-BF42-E512A681B325}' = 'Group Policy Services'
                    '{942A8E4F-A261-11D1-A760-00C04FB9603F}' = 'Software Installation'
                    '{9AD2BAFE-63B4-4883-A08C-C3C6196BCAFD}' = 'Power Options'
                    '{A2E30F80-D7DE-11D2-BBDE-00C04F86AE3B}' = 'Internet Explorer Branding'
                    '{A3F3E39B-5D83-4940-B954-28315B82F0A8}' = 'Group Policy Drive Maps'
                    '{AADCED64-746C-4633-A97C-D61349046527}' = 'Group Policy Folders'
                    '{B05566AC-FE9C-4368-BE01-7A4CBB6CBA11}' = 'Group Policy Preference Tool'
                    '{B087BE9D-ED37-454F-AF9C-04291E351182}' = 'Group Policy Preferences'
                    '{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}' = 'EFS Recovery'
                    '{B587E2B1-4D59-4E7E-AED9-22B9DF11D053}' = '802.3 Group Policy'
                    '{B9CCA4DE-E2B9-4CBD-BF7D-11B6EBFBDDF7}' = 'Group Policy Network Options'
                    '{BC75B1ED-5833-4858-9BB4-B1E212E5790D}' = 'Group Policy INI Files'
                    '{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}' = 'Group Policy Preference CSE'
                    '{C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7}' = 'Group Policy Shortcuts'
                    '{62C1845D-C4A6-4ACB-BBB0-C895FD090385}' = 'Microsoft Offline Files'
                    '{C631DF4C-088F-4156-B058-4375F0853CD8}' = 'Microsoft Offline Files'
                    '{CDEAFC3D-948D-49DD-AB12-E578BA4AF7AA}' = 'TCPIP'
                    '{D02B1F72-3407-48AE-BA88-E8213C6761F1}' = 'Wireless Group Policy'
                    '{E437BC1C-AA7D-11D2-A382-00C04F991E27}' = 'IP Security'
                    '{E47248BA-94CC-49C4-BBB5-9EB7F05183D0}' = 'Group Policy Internet Settings'
                    '{E4F48E54-F38D-4884-BFB9-D4D2E5729C18}' = 'Group Policy Start Menu Settings'
                    '{E5094040-C46C-4115-B030-04FB2E545B00}' = 'Group Policy Regional Options'
                    '{E62688F0-25FD-4c90-BFF5-F508B9D2E31F}' = 'Group Policy Environment'
                    '{E6BEFC42-E5F6-4AEB-B560-A2C1A6BEC5F0}' = 'Audit Policy Configuration'
                    '{F3CCC681-B74C-4060-9F26-CD84525DCA2A}' = 'Audit Policy Configuration'
                    '{F9C77450-3A41-477E-9310-9ACD617BD9E3}' = 'Group Policy Applications'
                    '{FC715823-C5FB-11D1-9EEF-00A0C90347FF}' = 'Internet Explorer Maintenance Extension Protocol'
                    '{FBF687E6-F063-4D9F-9F4F-FD9A26ACDD5F}' = 'Certificates'
                }

                # Parse gPCMachineExtensionNames (Client-Side Extensions)
                # Format: [{CSE-GUID}{Tool-GUID}][{CSE-GUID}{Tool-GUID}]...
                if ($GPO.gPCMachineExtensionNames) {
                    $ExtensionString = $GPO.gPCMachineExtensionNames
                    # Extract all [{GUID}{GUID}] pairs
                    $ExtensionPairs = [regex]::Matches($ExtensionString, '\[(\{[0-9a-fA-F-]+\})(\{[0-9a-fA-F-]+\})\]')

                    $ParsedExtensions = @()
                    foreach ($Match in $ExtensionPairs) {
                        $CSEGUID = $Match.Groups[1].Value
                        $ToolGUID = $Match.Groups[2].Value

                        # Resolve GUIDs to names
                        $CSEName = if ($CSENames.ContainsKey($CSEGUID)) { $CSENames[$CSEGUID] } else { $CSEGUID }
                        $ToolName = if ($ToolNames.ContainsKey($ToolGUID)) { $ToolNames[$ToolGUID] } else { $ToolGUID }

                        # Format: "CSE Name (Tool Name)"
                        $ParsedExtensions += "$CSEName ($ToolName)"
                    }

                    # Replace string with array of human-readable names
                    $GPO.gPCMachineExtensionNames = $ParsedExtensions
                }

                # Parse gPCUserExtensionNames (same format as Machine)
                if ($GPO.gPCUserExtensionNames) {
                    $ExtensionString = $GPO.gPCUserExtensionNames
                    $ExtensionPairs = [regex]::Matches($ExtensionString, '\[(\{[0-9a-fA-F-]+\})(\{[0-9a-fA-F-]+\})\]')

                    $ParsedExtensions = @()
                    foreach ($Match in $ExtensionPairs) {
                        $CSEGUID = $Match.Groups[1].Value
                        $ToolGUID = $Match.Groups[2].Value

                        # Resolve GUIDs to names
                        $CSEName = if ($CSENames.ContainsKey($CSEGUID)) { $CSENames[$CSEGUID] } else { $CSEGUID }
                        $ToolName = if ($ToolNames.ContainsKey($ToolGUID)) { $ToolNames[$ToolGUID] } else { $ToolGUID }

                        # Format: "CSE Name (Tool Name)"
                        $ParsedExtensions += "$CSEName ($ToolName)"
                    }

                    # Replace string with array of human-readable names
                    $GPO.gPCUserExtensionNames = $ParsedExtensions
                }
            }

            # If ShowLinkedOU is set, return only linked OUs (like -ShowMembers in Get-DomainGroup)
            if ($ShowLinkedOU) {
                Write-Log "[Get-DomainGPO] Searching for OUs linked to GPO..."

                # Query all OUs and Domain root with gPLink attribute (use Get-DomainObject)
                $AllOUs = @(Get-DomainObject `
                    -LDAPFilter "(|(objectClass=organizationalUnit)(objectClass=domain))" `
                    -Properties @('distinguishedName', 'gPLink') `
                    -SearchBase $Script:LDAPContext.DomainDN | Where-Object { $_.gPLink })
                Write-Log "[Get-DomainGPO] Found $($AllOUs.Count) OUs/Containers with gPLink attribute"

                # Since Identity is required, there should be only 1 GPO
                $GPO = $GPOs[0]
                $LinkedOUs = @()
                $GPOGUID = $GPO.name  # GPO GUID (already includes braces like {GUID})

                foreach ($OU in $AllOUs) {
                    # Check if this OU's gPLink contains the GPO GUID
                    # gPLink format: [LDAP://cn={GUID},cn=policies,cn=system,DC=domain,DC=com;0]
                    if ($OU.gPLink -match [regex]::Escape($GPOGUID)) {
                        $LinkedOUs += $OU.distinguishedName
                    }
                }

                Write-Log "[Get-DomainGPO] GPO '$($GPO.displayName)' is linked to $($LinkedOUs.Count) OU(s)"

                return $LinkedOUs
            }

            # If ShowPermissions is set, analyze ACLs for dangerous permissions
            if ($ShowPermissions) {
                Write-Log "[Get-DomainGPO] Analyzing GPO permissions..."

                # Need raw nTSecurityDescriptor bytes for ACL analysis
                # Query GPOs again with -Raw to get unprocessed security descriptors
                $RawParams = @{
                    LDAPFilter = $Filter
                    Properties = @('distinguishedName', 'nTSecurityDescriptor')
                    Raw = $true
                }
                if ($SearchBase) { $RawParams['SearchBase'] = $SearchBase }

                $RawGPOs = @(Get-DomainObject @RawParams)
                Write-Log "[Get-DomainGPO] Retrieved raw security descriptors for $($RawGPOs.Count) GPO(s)"

                # Build lookup table from raw GPO data
                $ACLLookup = @{}
                foreach ($RawGPO in $RawGPOs) {
                    if ($RawGPO.nTSecurityDescriptor -and $RawGPO.nTSecurityDescriptor -is [byte[]]) {
                        $ACLLookup[$RawGPO.distinguishedName] = $RawGPO.nTSecurityDescriptor
                    }
                }

                # Uses central privileged check from Test-IsPrivileged.ps1

                foreach ($GPO in $GPOs) {
                    $DangerousPermissions = @()

                    $SecurityDescriptorBytes = $ACLLookup[$GPO.distinguishedName]

                    if ($SecurityDescriptorBytes) {
                        try {
                            # Parse raw bytes into ActiveDirectorySecurity
                            $RawSD = New-Object System.DirectoryServices.ActiveDirectorySecurity
                            $RawSD.SetSecurityDescriptorBinaryForm($SecurityDescriptorBytes)

                            # Get DACL
                            $DACL = $RawSD.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

                            # Dangerous rights as enum for bitmask comparison
                            # Note: Central $Script:GenericDangerousRights uses strings for simple -contains checks
                            # Here we need enum values for bitwise AND comparison with ActiveDirectoryRights
                            $DangerousRightsEnum = @(
                                [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
                                [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
                                [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner,
                                [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
                                [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite
                            )

                            foreach ($ACE in $DACL) {
                                # Check if ACE grants dangerous rights
                                $HasDangerousRights = $false
                                $GrantedRights = @()

                                foreach ($Right in $DangerousRightsEnum) {
                                    if ($ACE.ActiveDirectoryRights -band $Right) {
                                        $HasDangerousRights = $true
                                        $GrantedRights += $Right.ToString()
                                    }
                                }

                                if ($HasDangerousRights -and $ACE.AccessControlType -eq 'Allow') {
                                    $TrusteeSID = $ACE.IdentityReference.Value
                                    $TrusteeName = ConvertFrom-SID -SID $TrusteeSID

                                    # Skip privileged accounts using central function
                                    $category = (Test-IsPrivileged -Identity $TrusteeSID).Category
                                    if ($category -ne 'Privileged') {
                                        # Determine severity based on rights and category
                                        $Severity = "Medium"
                                        if ($GrantedRights -contains 'GenericAll' -or $GrantedRights -contains 'WriteDacl' -or $GrantedRights -contains 'WriteOwner') {
                                            $Severity = "High"
                                        }

                                        # Broad groups (Domain Users, Everyone, Authenticated Users) with GPO write = Critical
                                        # This means potentially ALL domain users can modify the GPO!
                                        if ($category -eq 'BroadGroup') {
                                            $Severity = "Critical"
                                        }

                                        $DangerousPermissions += [PSCustomObject]@{
                                            Trustee = $TrusteeName
                                            TrusteeSID = $TrusteeSID
                                            Rights = $GrantedRights -join ', '
                                            Severity = $Severity
                                            Description = "Non-privileged principal has GPO modification rights - potential privilege escalation"
                                        }

                                        Write-Log "[Get-DomainGPO] Found dangerous permission on GPO '$($GPO.displayName)': $TrusteeName ($($GrantedRights -join ', '))"
                                    }
                                }
                            }

                        } catch {
                            Write-Log "[Get-DomainGPO] Error parsing nTSecurityDescriptor for GPO '$($GPO.displayName)': $_"
                        }
                    }

                    # Add DangerousPermissions property
                    $GPO | Add-Member -NotePropertyName "DangerousPermissions" -NotePropertyValue $DangerousPermissions -Force

                    if ($DangerousPermissions.Count -gt 0) {
                        Write-Log "[Get-DomainGPO] GPO '$($GPO.displayName)' has $($DangerousPermissions.Count) dangerous permission(s)"
                    }
                }
            }

            # If ShowDangerousSettings is set, analyze GPO contents for dangerous configurations
            if ($ShowDangerousSettings) {
                Write-Log "[Get-DomainGPO] Analyzing GPOs for dangerous settings..."

                # Pre-resolve IP for hostname substitution when custom DNS is used
                $resolvedSmbIP = $null
                if ($Script:LDAPContext -and $Script:LDAPContext['DnsServer'] -and $Script:LDAPContext['ServerIP']) {
                    $resolvedSmbIP = $Script:LDAPContext['ServerIP']
                    Write-Log "[Get-DomainGPO] Using resolved IP for SYSVOL access: $resolvedSmbIP"
                }

                # Use Invoke-SMBAccess to handle custom DNS and SimpleBind credentials
                Invoke-SMBAccess -Description "Analyzing GPO dangerous settings" -ErrorHandling "Warn" -ScriptBlock {

                foreach ($GPO in $GPOs) {
                    $DangerousSettings = @()

                    # Get GPO file system path
                    $GPOPath = $GPO.gPCFileSysPath

                    # If custom DNS is used, replace hostname with resolved IP in UNC path
                    if ($resolvedSmbIP -and $GPOPath -match '^\\\\([^\\]+)\\') {
                        $uncHost = $Matches[1]
                        $ipTest = $null
                        if (-not [System.Net.IPAddress]::TryParse($uncHost, [ref]$ipTest)) {
                            $GPOPath = $GPOPath -replace "^\\\\[^\\]+\\", "\\$resolvedSmbIP\"
                            Write-Log "[Get-DomainGPO] Converted UNC hostname to IP for GPO path"
                        }
                    }

                    if ($GPOPath -and (Test-Path $GPOPath -ErrorAction SilentlyContinue)) {
                        Write-Log "[Get-DomainGPO] Analyzing GPO path: $GPOPath"

                        # Check for Scheduled Tasks (GPO Immediate Tasks)
                        $ScheduledTasksPath = Join-Path $GPOPath "Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
                        if (Test-Path $ScheduledTasksPath -ErrorAction SilentlyContinue) {
                            try {
                                [xml]$TasksXML = Get-Content $ScheduledTasksPath -ErrorAction SilentlyContinue
                                $TaskCount = @($TasksXML.ScheduledTasks.ChildNodes | Where-Object { $_.name -ne '#comment' }).Count
                                if ($TaskCount -gt 0) {
                                    $DangerousSettings += [PSCustomObject]@{
                                        Type = "Scheduled Tasks"
                                        Severity = "High"
                                        Description = "$TaskCount scheduled task(s) configured - potential for arbitrary code execution"
                                        Path = $ScheduledTasksPath
                                    }
                                    Write-Log "[Get-DomainGPO] Found $TaskCount scheduled task(s) in GPO '$($GPO.displayName)'"
                                }
                            } catch {
                                Write-Log "[Get-DomainGPO] Error parsing ScheduledTasks.xml: $_"
                            }
                        }

                        # Check for Logon/Startup Scripts (Computer)
                        $ComputerScriptsIni = Join-Path $GPOPath "Machine\Scripts\scripts.ini"
                        if (Test-Path $ComputerScriptsIni -ErrorAction SilentlyContinue) {
                            $ScriptContent = Get-Content $ComputerScriptsIni -Raw -ErrorAction SilentlyContinue
                            if ($ScriptContent -and $ScriptContent.Trim().Length -gt 0) {
                                $DangerousSettings += [PSCustomObject]@{
                                    Type = "Computer Startup/Shutdown Scripts"
                                    Severity = "High"
                                    Description = "Computer scripts configured - runs as SYSTEM on boot/shutdown"
                                    Path = $ComputerScriptsIni
                                }
                                Write-Log "[Get-DomainGPO] Found computer scripts in GPO '$($GPO.displayName)'"
                            }
                        }

                        # Check for Logon/Startup Scripts (User)
                        $UserScriptsIni = Join-Path $GPOPath "User\Scripts\scripts.ini"
                        if (Test-Path $UserScriptsIni -ErrorAction SilentlyContinue) {
                            $ScriptContent = Get-Content $UserScriptsIni -Raw -ErrorAction SilentlyContinue
                            if ($ScriptContent -and $ScriptContent.Trim().Length -gt 0) {
                                $DangerousSettings += [PSCustomObject]@{
                                    Type = "User Logon/Logoff Scripts"
                                    Severity = "Medium"
                                    Description = "User scripts configured - runs in user context"
                                    Path = $UserScriptsIni
                                }
                                Write-Log "[Get-DomainGPO] Found user scripts in GPO '$($GPO.displayName)'"
                            }
                        }

                        # Check for Registry.xml (Registry Preferences)
                        $RegistryXMLPaths = @(
                            (Join-Path $GPOPath "Machine\Preferences\Registry\Registry.xml"),
                            (Join-Path $GPOPath "User\Preferences\Registry\Registry.xml")
                        )

                        foreach ($RegPath in $RegistryXMLPaths) {
                            if (Test-Path $RegPath -ErrorAction SilentlyContinue) {
                                try {
                                    [xml]$RegXML = Get-Content $RegPath -ErrorAction SilentlyContinue
                                    $RegCount = @($RegXML.RegistrySettings.ChildNodes | Where-Object { $_.name -ne '#comment' }).Count

                                    if ($RegCount -gt 0) {
                                        # Check for Run keys (common persistence mechanism)
                                        $RunKeys = $RegXML.SelectNodes("//Registry") | Where-Object {
                                            $_.Properties.key -match "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
                                        }

                                        $Context = if ($RegPath -match "\\Machine\\") { "Machine" } else { "User" }

                                        if ($RunKeys.Count -gt 0) {
                                            $DangerousSettings += [PSCustomObject]@{
                                                Type = "Registry Run Keys ($Context)"
                                                Severity = "High"
                                                Description = "$($RunKeys.Count) Run key(s) configured - potential persistence mechanism"
                                                Path = $RegPath
                                            }
                                            Write-Log "[Get-DomainGPO] Found $($RunKeys.Count) Run key(s) in GPO '$($GPO.displayName)'"
                                        } else {
                                            $DangerousSettings += [PSCustomObject]@{
                                                Type = "Registry Settings ($Context)"
                                                Severity = "Low"
                                                Description = "$RegCount registry setting(s) configured"
                                                Path = $RegPath
                                            }
                                        }
                                    }
                                } catch {
                                    Write-Log "[Get-DomainGPO] Error parsing Registry.xml: $_"
                                }
                            }
                        }

                        # Check for Groups.xml (Local Group Membership)
                        $GroupsXMLPaths = @(
                            (Join-Path $GPOPath "Machine\Preferences\Groups\Groups.xml"),
                            (Join-Path $GPOPath "User\Preferences\Groups\Groups.xml")
                        )

                        foreach ($GroupPath in $GroupsXMLPaths) {
                            if (Test-Path $GroupPath -ErrorAction SilentlyContinue) {
                                try {
                                    [xml]$GroupXML = Get-Content $GroupPath -ErrorAction SilentlyContinue
                                    $GroupCount = @($GroupXML.Groups.ChildNodes | Where-Object { $_.name -ne '#comment' }).Count

                                    if ($GroupCount -gt 0) {
                                        # Check for Administrators group modifications (S-1-5-32-544 = BUILTIN\Administrators)
                                        $AdminGroups = $GroupXML.SelectNodes("//Group") | Where-Object {
                                            $_.Properties.groupSid -eq 'S-1-5-32-544'
                                        }

                                        $Context = if ($GroupPath -match "\\Machine\\") { "Machine" } else { "User" }

                                        if ($AdminGroups.Count -gt 0) {
                                            $DangerousSettings += [PSCustomObject]@{
                                                Type = "Local Administrators Modification ($Context)"
                                                Severity = "Critical"
                                                Description = "Administrators group modification - potential privilege escalation"
                                                Path = $GroupPath
                                            }
                                            Write-Log "[Get-DomainGPO] Found Administrators group modification in GPO '$($GPO.displayName)'"
                                        } else {
                                            $DangerousSettings += [PSCustomObject]@{
                                                Type = "Local Group Membership ($Context)"
                                                Severity = "Medium"
                                                Description = "$GroupCount local group modification(s)"
                                                Path = $GroupPath
                                            }
                                        }
                                    }
                                } catch {
                                    Write-Log "[Get-DomainGPO] Error parsing Groups.xml: $_"
                                }
                            }
                        }

                        # Check for Services.xml (Service manipulation)
                        $ServicesXMLPath = Join-Path $GPOPath "Machine\Preferences\Services\Services.xml"
                        if (Test-Path $ServicesXMLPath -ErrorAction SilentlyContinue) {
                            try {
                                [xml]$ServicesXML = Get-Content $ServicesXMLPath -ErrorAction SilentlyContinue
                                $ServiceCount = @($ServicesXML.Services.ChildNodes | Where-Object { $_.name -ne '#comment' }).Count
                                if ($ServiceCount -gt 0) {
                                    $DangerousSettings += [PSCustomObject]@{
                                        Type = "Service Configuration"
                                        Severity = "High"
                                        Description = "$ServiceCount service(s) configured - potential for privilege escalation"
                                        Path = $ServicesXMLPath
                                    }
                                    Write-Log "[Get-DomainGPO] Found $ServiceCount service(s) in GPO '$($GPO.displayName)'"
                                }
                            } catch {
                                Write-Log "[Get-DomainGPO] Error parsing Services.xml: $_"
                            }
                        }

                    } else {
                        Write-Log "[Get-DomainGPO] GPO path not accessible or does not exist: $GPOPath"
                    }

                    # Add DangerousSettings property
                    $GPO | Add-Member -NotePropertyName "DangerousSettings" -NotePropertyValue $DangerousSettings -Force

                    if ($DangerousSettings.Count -gt 0) {
                        Write-Log "[Get-DomainGPO] GPO '$($GPO.displayName)' has $($DangerousSettings.Count) dangerous setting(s)"
                    }
                }

                } # End Invoke-SMBAccess ScriptBlock
            }

            # Cache unfiltered results for subsequent calls within the same session
            if ($isUnfilteredCall -and $GPOs.Count -gt 0) {
                $Script:CachedAllGPOs = $GPOs
                Write-Log "[Get-DomainGPO] Cached $($GPOs.Count) GPOs for session reuse"
            }

            return $GPOs

        } catch {
            Write-Log "[Get-DomainGPO] Error: $_"
            throw
        }
    }

    end {
        Write-Log "[Get-DomainGPO] GPO enumeration completed"
    }
}
