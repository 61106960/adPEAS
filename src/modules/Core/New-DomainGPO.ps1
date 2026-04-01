function New-DomainGPO {
<#
.SYNOPSIS
    Creates a new Group Policy Object in Active Directory.

.DESCRIPTION
    New-DomainGPO creates a new GPO in the domain's Group Policy Container via LDAP AddRequest.

    GPO Structure:
    - AD Object: CN={GUID},CN=Policies,CN=System,DC=domain,DC=com
    - SYSVOL Path: \\domain.com\SYSVOL\domain.com\Policies\{GUID}\
      - Machine\  (folder)
      - User\     (folder)
      - GPT.INI   (file with version info)

.PARAMETER DisplayName
    Display name for the new GPO (user-friendly name shown in GPMC).

.PARAMETER NoSYSVOL
    If specified, skip SYSVOL folder creation. Only the AD object will be created.
    The GPO will appear "broken" in GPMC until SYSVOL is populated manually.

.PARAMETER Domain
    Target domain (FQDN).

.PARAMETER Server
    Specific Domain Controller to target.

.PARAMETER Credential
    PSCredential object for authentication.

.EXAMPLE
    New-DomainGPO -DisplayName "Test Policy"
    Creates a new GPO with AD object and SYSVOL folder structure.

.EXAMPLE
    New-DomainGPO -DisplayName "Malicious GPO" -Domain "contoso.com" -Credential (Get-Credential)
    Creates a complete GPO in a remote domain using alternative credentials.

.EXAMPLE
    New-DomainGPO -DisplayName "AD Only GPO" -NoSYSVOL
    Creates only the AD object without SYSVOL files.

.EXAMPLE
    $result = New-DomainGPO -DisplayName "Test Policy" -PassThru
    Creates a GPO and returns the result object for programmatic use.

.PARAMETER PassThru
    Returns a result object instead of only console output.
    Useful for scripting and automation.

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        [string]$DisplayName,

        [Parameter(Mandatory=$false)]
        [switch]$NoSYSVOL,

        # Connection parameters
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$PassThru
    )

    begin {
        Write-Log "[New-DomainGPO] Starting GPO creation"
    }

    process {
        # Ensure LDAP connection at start of process block
        $ConnectionParams = @{}
        if ($Domain) { $ConnectionParams['Domain'] = $Domain }
        if ($Server) { $ConnectionParams['Server'] = $Server }
        if ($Credential) { $ConnectionParams['Credential'] = $Credential }

        if (-not (Ensure-LDAPConnection @ConnectionParams)) {
            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = "CreateGPO"
                    GPO = $DisplayName
                    Success = $false
                    Message = "No LDAP connection available"
                }
            }
            return
        }

        try {
            Write-Log "[New-DomainGPO] Creating new GPO: $DisplayName"

            # Generate new GUID for GPO
            $GPOGUID = [System.Guid]::NewGuid().ToString().ToUpper()
            $GPOGUIDWithBraces = "{$GPOGUID}"
            Write-Log "[New-DomainGPO] Generated GUID: $GPOGUIDWithBraces"

            # Determine GPO container DN
            $PoliciesContainer = "CN=Policies,CN=System,$($Script:LDAPContext.DomainDN)"
            Write-Log "[New-DomainGPO] Target container: $PoliciesContainer"

            # Create GPO via AddRequest (uses $Script:LdapConnection - works with all auth methods)
            $GPODN = "CN=$GPOGUIDWithBraces,$PoliciesContainer"

            # Set SYSVOL path (UNC format)
            $gPCFileSysPath = "\\$($Script:LDAPContext.Domain)\SysVol\$($Script:LDAPContext.Domain)\Policies\$GPOGUIDWithBraces"

            $AddRequest = New-Object System.DirectoryServices.Protocols.AddRequest
            $AddRequest.DistinguishedName = $GPODN

            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("objectClass", "groupPolicyContainer"))) | Out-Null
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("displayName", $DisplayName))) | Out-Null
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("flags", "0"))) | Out-Null
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("versionNumber", "0"))) | Out-Null
            $AddRequest.Attributes.Add((New-Object System.DirectoryServices.Protocols.DirectoryAttribute("gPCFileSysPath", $gPCFileSysPath))) | Out-Null

            $Response = $Script:LdapConnection.SendRequest($AddRequest)
            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                throw "LDAP AddRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
            }

            Write-Log "[New-DomainGPO] GPO object created in AD: $GPODN"

            # Create SYSVOL folder structure unless -NoSYSVOL is specified
            $SYSVOLCreated = $false
            $SYSVOLError = $null

            if (-not $NoSYSVOL) {
                Write-Log "[New-DomainGPO] Creating SYSVOL folder structure..."

                try {
                    # STEP 1: Read AD object ACLs to mirror them to SYSVOL
                    # This is required so GPMC doesn't show "permissions inconsistent" warning
                    Write-Log "[New-DomainGPO] Reading AD object ACLs to mirror to SYSVOL..."

                    # Read nTSecurityDescriptor via Invoke-LDAPSearch (works with all auth methods)
                    $SDResult = @(Invoke-LDAPSearch -Filter "(distinguishedName=$GPODN)" -Properties @('nTSecurityDescriptor') -SizeLimit 1 -Raw)[0]
                    if (-not $SDResult -or -not $SDResult.nTSecurityDescriptor) {
                        throw "Failed to read security descriptor from GPO object"
                    }
                    $SDBytes = [byte[]]($SDResult.nTSecurityDescriptor)
                    $ADSecurityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $ADSecurityDescriptor.SetSecurityDescriptorBinaryForm($SDBytes)

                    # Extract ACEs from AD object - we'll convert these to NTFS ACEs
                    $ADACEs = $ADSecurityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
                    $ADOwner = $ADSecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier])

                    # Build list of ACEs to apply to SYSVOL (convert AD rights to NTFS rights)
                    # GPMC maps AD permissions to NTFS permissions as follows:
                    # - Full Control on AD object = Full Control on SYSVOL folder
                    # - Read/Apply on AD object = Read & Execute on SYSVOL folder
                    # - Edit settings on AD = Modify on SYSVOL (rare, usually GPO creators)
                    #
                    # Key insight: GPMC uses a SIMPLIFIED comparison. It doesn't require exact
                    # bit-for-bit matching. It checks:
                    # 1. Same trustees have permissions on both AD and SYSVOL
                    # 2. Permission LEVEL is equivalent (Full/Modify/Read)
                    #
                    # AD Rights constants:
                    # - 0xF01FF = GenericAll (Full Control)
                    # - 0xF00FF = Full Control minus Delete (treat as Full Control)
                    # - 0x20094 = GenericRead (Read + ListChildren + ReadProperty)
                    # - 0x20028 = GenericWrite (Self + WriteProperty + CreateChild)
                    # - 0x100 = ExtendedRight (used for "Apply Group Policy")
                    #
                    # SYSVOL requires EXACTLY these permissions for GPMC to be happy:
                    # - Admins: Full Control (inherited to subfolders)
                    # - Authenticated Users: Read (for GPO application)
                    $SYSVOLACEData = @()
                    foreach ($ADACE in $ADACEs) {
                        $TrusteeSID = $ADACE.IdentityReference.Value
                        $ADRights = [int]$ADACE.ActiveDirectoryRights
                        $AccessType = $ADACE.AccessControlType

                        $NTFSRights = [System.Security.AccessControl.FileSystemRights]::None

                        # Full Control: Check if ADRights indicates "management" level access
                        # 0xF01FF = GenericAll, 0xF00FF = common variant (all except Delete)
                        # Any rights >= 0xF0000 typically indicate full management access
                        if ($ADRights -ge 0xF0000) {
                            $NTFSRights = [System.Security.AccessControl.FileSystemRights]::FullControl
                        }
                        # Write/Modify: GenericWrite (0x20028) or WriteProperty (0x20)
                        elseif (($ADRights -band 0x20028) -eq 0x20028 -or (($ADRights -band 0x20) -eq 0x20 -and ($ADRights -band 0x10000) -ne 0)) {
                            $NTFSRights = [System.Security.AccessControl.FileSystemRights]::Modify
                        }
                        # Read: GenericRead (0x20094) or any read-level permission
                        # ExtendedRight (0x100) alone = Apply GPO = Read on SYSVOL
                        else {
                            $NTFSRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                        }

                        Write-Log "[New-DomainGPO] Mapped AD ACE: Trustee=$TrusteeSID, ADRights=0x$($ADRights.ToString('X')), NTFSRights=$NTFSRights"

                        $SYSVOLACEData += @{
                            TrusteeSID = $TrusteeSID
                            NTFSRights = $NTFSRights
                            AccessType = $AccessType
                        }
                    }

                    # Consolidate ACEs: Multiple ACEs for same trustee -> keep highest privilege
                    # This prevents duplicate entries (e.g., Authenticated Users with Read twice)
                    $ConsolidatedACEs = @{}
                    foreach ($ace in $SYSVOLACEData) {
                        $key = "$($ace.TrusteeSID)|$($ace.AccessType)"
                        if ($ConsolidatedACEs.ContainsKey($key)) {
                            # Keep higher privilege level
                            $existing = $ConsolidatedACEs[$key]
                            if ([int]$ace.NTFSRights -gt [int]$existing.NTFSRights) {
                                $ConsolidatedACEs[$key] = $ace
                            }
                        } else {
                            $ConsolidatedACEs[$key] = $ace
                        }
                    }
                    $SYSVOLACEData = @($ConsolidatedACEs.Values)
                    Write-Log "[New-DomainGPO] Consolidated to $($SYSVOLACEData.Count) unique ACEs"

                    # Prepare variables for scriptblock (captured in closure)
                    $domainName = $Script:LDAPContext.Domain
                    $gpoGuid = $GPOGUIDWithBraces
                    $gpoDisplayName = $DisplayName
                    $ownerSID = $ADOwner.Value

                    # Use Invoke-SMBAccess for authenticated SYSVOL access
                    $smbResult = Invoke-SMBAccess -Description "Create GPO SYSVOL folders" -ErrorHandling Stop -ScriptBlock {
                        param($basePath)

                        # Build paths using captured variables
                        $gpoBasePath = Join-Path $basePath "$domainName\Policies\$gpoGuid"
                        $machinePath = Join-Path $gpoBasePath "Machine"
                        $userPath = Join-Path $gpoBasePath "User"
                        $gptIniPath = Join-Path $gpoBasePath "GPT.INI"

                        Write-Log "[New-DomainGPO] Creating folder: $gpoBasePath"

                        # Create GPO folder
                        if (-not (Test-Path $gpoBasePath)) {
                            $null = New-Item -Path $gpoBasePath -ItemType Directory -Force -ErrorAction Stop
                        }

                        # Create Machine folder
                        if (-not (Test-Path $machinePath)) {
                            $null = New-Item -Path $machinePath -ItemType Directory -Force -ErrorAction Stop
                        }

                        # Create User folder
                        if (-not (Test-Path $userPath)) {
                            $null = New-Item -Path $userPath -ItemType Directory -Force -ErrorAction Stop
                        }

                        # Create GPT.INI file with initial version
                        # Format: [General] section with Version=0 (initial, no settings applied)
                        $gptIniContent = "[General]`r`nVersion=0`r`ndisplayName=$gpoDisplayName"
                        Set-Content -Path $gptIniPath -Value $gptIniContent -Force -ErrorAction Stop

                        # STEP 2: Apply NTFS ACLs that mirror AD ACLs
                        # This is critical - GPMC compares AD and SYSVOL ACLs
                        try {
                            $acl = Get-Acl -Path $gpoBasePath

                            # Disable inheritance and clear existing rules (like AD object)
                            $acl.SetAccessRuleProtection($true, $false)
                            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

                            # Set owner to match AD object owner
                            try {
                                $ownerIdentity = New-Object System.Security.Principal.SecurityIdentifier($ownerSID)
                                $acl.SetOwner($ownerIdentity)
                                Write-Log "[New-DomainGPO] Set SYSVOL owner to: $ownerSID"
                            } catch {
                                Write-Log "[New-DomainGPO] Warning: Could not set SYSVOL owner: $_"
                            }

                            # Apply ACEs mirrored from AD
                            foreach ($aceData in $SYSVOLACEData) {
                                try {
                                    $sid = New-Object System.Security.Principal.SecurityIdentifier($aceData.TrusteeSID)
                                    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                                        $sid,
                                        $aceData.NTFSRights,
                                        ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
                                        [System.Security.AccessControl.PropagationFlags]::None,
                                        $aceData.AccessType
                                    )
                                    $acl.AddAccessRule($rule)
                                    Write-Log "[New-DomainGPO] Added SYSVOL ACE: Trustee=$($aceData.TrusteeSID), Rights=$($aceData.NTFSRights)"
                                } catch {
                                    Write-Log "[New-DomainGPO] Warning: Could not add ACE for $($aceData.TrusteeSID): $_"
                                }
                            }

                            # Apply ACL to GPO folder
                            Set-Acl -Path $gpoBasePath -AclObject $acl -ErrorAction Stop
                            Write-Log "[New-DomainGPO] SYSVOL ACLs mirrored from AD successfully"

                            # Also apply to Machine and User subfolders (they inherit, but ensure consistency)
                            Set-Acl -Path $machinePath -AclObject $acl -ErrorAction SilentlyContinue
                            Set-Acl -Path $userPath -AclObject $acl -ErrorAction SilentlyContinue

                        } catch {
                            Write-Log "[New-DomainGPO] Warning: Could not set SYSVOL ACLs: $_"
                            # Continue anyway - folder structure was created
                        }

                        # Return success indicator
                        return @{
                            Success = $true
                            GPOPath = $gpoBasePath
                            MachinePath = $machinePath
                            UserPath = $userPath
                            GptIniPath = $gptIniPath
                        }
                    }.GetNewClosure()

                    if ($smbResult -and $smbResult.Success) {
                        $SYSVOLCreated = $true
                        $SYSVOLResult = $smbResult
                    } else {
                        $SYSVOLError = "SMB access returned no result"
                    }
                }
                catch {
                    $SYSVOLError = $_.Exception.Message
                    if (-not $PassThru) {
                        Write-Warning "[New-DomainGPO] Failed to create SYSVOL folders: $SYSVOLError"
                        Write-Warning "    The GPO AD object was created, but SYSVOL structure is missing."
                        Write-Warning "    GPO will appear broken in GPMC until SYSVOL is populated manually."
                    }
                }
            } else {
                Write-Log "[New-DomainGPO] Skipping SYSVOL creation (-NoSYSVOL specified)"
            }

            # Build result object
            $resultMessage = if ($SYSVOLCreated) {
                "GPO created successfully (AD object + SYSVOL)"
            } elseif ($NoSYSVOL) {
                "GPO AD object created (SYSVOL skipped by request)"
            } else {
                "GPO AD object created (SYSVOL creation failed: $SYSVOLError)"
            }

            # Return result object only if -PassThru is specified (no console output)
            if ($PassThru) {
                $Result = [PSCustomObject]@{
                    Operation = "CreateGPO"
                    DisplayName = $DisplayName
                    GUID = $GPOGUIDWithBraces
                    DistinguishedName = $GPODN
                    SYSVOLPath = $gPCFileSysPath
                    SYSVOLCreated = $SYSVOLCreated
                    Success = $true
                    Message = $resultMessage
                }

                if ($SYSVOLError) {
                    $Result | Add-Member -NotePropertyName "SYSVOLError" -NotePropertyValue $SYSVOLError
                }

                return $Result
            } else {
                # Console output (default behavior)
                Show-Line "Successfully created GPO AD object: $DisplayName" -Class Hint
                Show-KeyValue "Distinguished Name:" $GPODN
                Show-KeyValue "GUID:" $GPOGUIDWithBraces
                Show-KeyValue "SYSVOL Path:" $gPCFileSysPath

                if ($SYSVOLCreated -and $SYSVOLResult) {
                    Show-Line "SYSVOL folder structure created successfully" -Class Hint
                    Show-KeyValue "Machine folder:" $SYSVOLResult.MachinePath
                    Show-KeyValue "User folder:" $SYSVOLResult.UserPath
                    Show-KeyValue "GPT.INI:" $SYSVOLResult.GptIniPath
                } elseif ($NoSYSVOL) {
                    Show-Line "SYSVOL creation skipped (-NoSYSVOL)" -Class Note
                }
            }
        }
        catch {
            Write-Error "[New-DomainGPO] Failed to create GPO '$DisplayName': $_"
            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = "CreateGPO"
                    DisplayName = $DisplayName
                    Success = $false
                    Message = $_.Exception.Message
                }
            }
        }
    }
}
