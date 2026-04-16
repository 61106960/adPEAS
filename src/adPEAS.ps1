<#
.SYNOPSIS
    adPEAS v2 - Active Directory Privilege Escalation Awesome Scripts

.DESCRIPTION
    Security analysis tool for identifying vulnerabilities and misconfigurations in Active Directory environments.

.EXAMPLE
    # v2 Style: Two-step (explicit session management)
    Import-Module .\adPEAS.ps1
    Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth
    Invoke-adPEAS

.EXAMPLE
    # v1 Style: One-step (direct execution with connection parameters)
    Import-Module .\adPEAS.ps1
    Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth

.EXAMPLE
    # v1 Style: With credentials
    Import-Module .\adPEAS.ps1
    Invoke-adPEAS -Domain "contoso.com" -Credential (Get-Credential)

.EXAMPLE
    # v1 Style: With username/password
    Import-Module .\adPEAS.ps1
    Invoke-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "P@ssw0rd!"

.EXAMPLE
    # Write output to file (with ANSI colors by default)
    Import-Module .\adPEAS.ps1
    Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Outputfile .\adPEAS_out.txt

.EXAMPLE
    # Write output to file without colors (plain text)
    Import-Module .\adPEAS.ps1
    Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -Outputfile .\adPEAS_out.txt -NoColor

.EXAMPLE
    # Run specific Modules with existing session
    Import-Module .\adPEAS.ps1
    Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth
    Invoke-adPEAS -Module Domain,Accounts,GPO

.EXAMPLE
    # OPSEC mode (stealth - no Kerberoast, ASREPRoast, BloodHound collection)
    Import-Module .\adPEAS.ps1
    Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -OPSEC

.NOTES
    Author: Alexander Sturz (@_61106960_)

.LINK
    https://github.com/61106960/adPEAS
#>

#Requires -Version 5.1

# ===== Script Variables =====
$Script:adPEASVersion = "2.0.2"

# Handle ScriptPath for different execution contexts:
# - Normal: $MyInvocation.MyCommand.Path is set
# - ScriptBlock::Create() (obfuscated/embedded): $MyInvocation.MyCommand.Path is $null
if ($MyInvocation.MyCommand.Path) {
    $Script:ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    # Running via ScriptBlock (e.g., obfuscated version) - modules are already combined
    $Script:ScriptPath = $null
}

# Output Configuration
$Script:adPEAS_OutputColor = $true
$Script:adPEAS_Outputfile = $null
$Script:adPEAS_VerboseLogging = $false

# Activity Threshold Configuration
# Default: 90 days - accounts inactive longer are considered stale
# Can be overridden via Invoke-adPEAS -InactiveDays parameter
$Script:DefaultInactiveDays = 90

# License Configuration
# EmbeddedLicense is replaced at build time by Build-Release.ps1 (Base64-encoded JSON)
# RuntimeLicense is set by -License parameter at runtime
$Script:EmbeddedLicense = $null
$Script:RuntimeLicense = $null

# ===== Load Modules =====
# Module loading for development mode (source execution)
# In standalone builds, these are replaced by inlined module code
if ($Script:ScriptPath) {

    # Core Modules
    . "$Script:ScriptPath\modules\Core\adPEAS-Types.ps1"
    . "$Script:ScriptPath\modules\Core\adPEAS-GUIDs.ps1"
    . "$Script:ScriptPath\modules\Core\adPEAS-OIDs.ps1"
    . "$Script:ScriptPath\modules\Core\adPEAS-SIDs.ps1"
    . "$Script:ScriptPath\modules\Core\adPEAS-ErrorCodes.ps1"
    . "$Script:ScriptPath\modules\Core\adPEAS-InputValidation.ps1"
    . "$Script:ScriptPath\modules\Core\Write-adPEASOutput.ps1"
    . "$Script:ScriptPath\modules\Core\adPEAS-AttributeOrder.ps1"
    . "$Script:ScriptPath\modules\Core\Get-RenderModel.ps1"
    . "$Script:ScriptPath\modules\Core\adPEAS-FindingDefinitions.ps1"
    . "$Script:ScriptPath\modules\Core\AttributeTransformers.ps1"
    . "$Script:ScriptPath\modules\Core\Render-ConsoleObject.ps1"
    . "$Script:ScriptPath\modules\Core\Render-HtmlObject.ps1"
    . "$Script:ScriptPath\modules\Core\adPEAS-ScoringDefinitions.ps1"
    . "$Script:ScriptPath\modules\Core\adPEAS-ObjectTypes.ps1"
    . "$Script:ScriptPath\modules\Core\adPEAS-SoftwareLifecycle.ps1"
    . "$Script:ScriptPath\modules\Core\adPEAS-Messages.ps1"
    . "$Script:ScriptPath\modules\Core\Get-AuthenticatedDirectoryEntry.ps1"
    . "$Script:ScriptPath\modules\Core\Show-ConnectionError.ps1"
    . "$Script:ScriptPath\modules\Helpers\ConvertFrom-KeyCredentialLink.ps1"
    . "$Script:ScriptPath\modules\Core\Connect-LDAP.ps1"
    . "$Script:ScriptPath\modules\Core\Connect-adPEAS.ps1"
    . "$Script:ScriptPath\modules\Core\Disconnect-adPEAS.ps1"
    . "$Script:ScriptPath\modules\Core\Invoke-LDAPSearch.ps1"
    . "$Script:ScriptPath\modules\Core\Get-DomainObject.ps1"
    . "$Script:ScriptPath\modules\Core\Get-ObjectACL.ps1"
    . "$Script:ScriptPath\modules\Core\Set-DomainObject.ps1"
    . "$Script:ScriptPath\modules\Core\Get-DomainUser.ps1"
    . "$Script:ScriptPath\modules\Core\Get-DomainComputer.ps1"
    . "$Script:ScriptPath\modules\Core\Get-DomainGroup.ps1"
    . "$Script:ScriptPath\modules\Core\Get-DomainGPO.ps1"
    . "$Script:ScriptPath\modules\Core\Get-CertificateTemplate.ps1"
    . "$Script:ScriptPath\modules\Core\Set-CertificateTemplate.ps1"
    . "$Script:ScriptPath\modules\Core\Set-DomainUser.ps1"
    . "$Script:ScriptPath\modules\Core\Set-DomainGroup.ps1"
    . "$Script:ScriptPath\modules\Core\Set-DomainComputer.ps1"
    . "$Script:ScriptPath\modules\Core\Set-DomainGPO.ps1"
    . "$Script:ScriptPath\modules\Core\New-DomainUser.ps1"
    . "$Script:ScriptPath\modules\Core\New-DomainComputer.ps1"
    . "$Script:ScriptPath\modules\Core\New-DomainGroup.ps1"
    . "$Script:ScriptPath\modules\Core\New-DomainGPO.ps1"
    . "$Script:ScriptPath\modules\Core\Get-CertificateAuthority.ps1"

    # Helper Modules
    . "$Script:ScriptPath\modules\Helpers\Write-Log.ps1"
    . "$Script:ScriptPath\modules\Helpers\New-SafePassword.ps1"
    . "$Script:ScriptPath\modules\Helpers\ConvertTo-FormattedACE.ps1"
    . "$Script:ScriptPath\modules\Helpers\ConvertFrom-SecurityDescriptor.ps1"
    . "$Script:ScriptPath\modules\Helpers\ConvertTo-AccessRules.ps1"
    . "$Script:ScriptPath\modules\Helpers\Get-GCConnection.ps1"
    . "$Script:ScriptPath\modules\Helpers\Resolve-CrossDomainIdentity.ps1"
    . "$Script:ScriptPath\modules\Helpers\ConvertFrom-SID.ps1"
    . "$Script:ScriptPath\modules\Helpers\ConvertTo-SID.ps1"
    . "$Script:ScriptPath\modules\Helpers\Test-IsPrivileged.ps1"
    . "$Script:ScriptPath\modules\Helpers\Get-ObjectOwner.ps1"
    . "$Script:ScriptPath\modules\Helpers\ConvertFrom-GPPPassword.ps1"
    . "$Script:ScriptPath\modules\Helpers\ConvertFrom-VBE.ps1"
    . "$Script:ScriptPath\modules\Helpers\ConvertFrom-Base64OrFile.ps1"
    . "$Script:ScriptPath\modules\Helpers\ConvertFrom-ManagedPassword.ps1"
    . "$Script:ScriptPath\modules\Helpers\ConvertFrom-LAPSEncryptedPassword.ps1"
    . "$Script:ScriptPath\modules\Helpers\ConvertFrom-SupplementalCredentials.ps1"
    . "$Script:ScriptPath\modules\Helpers\Get-CurrentUserTokenGroups.ps1"
    . "$Script:ScriptPath\modules\Helpers\Get-adPEASSession.ps1"
    . "$Script:ScriptPath\modules\Helpers\Test-KerberosTGTExists.ps1"
    . "$Script:ScriptPath\modules\Helpers\Ensure-LDAPConnection.ps1"
    . "$Script:ScriptPath\modules\Helpers\Test-AccountActivity.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-SMBAccess.ps1"
    . "$Script:ScriptPath\modules\Helpers\Show-Progress.ps1"
    . "$Script:ScriptPath\modules\Helpers\Kerberos-ASN1.ps1"
    . "$Script:ScriptPath\modules\Helpers\Kerberos-Crypto.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-PKINITAuth-Native.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-Kerberoast.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-ASREPRoast.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-KerberosAuth.ps1"
    . "$Script:ScriptPath\modules\Helpers\Request-ServiceTicket.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-UnPACTheHash.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-S4U.ps1"
    . "$Script:ScriptPath\modules\Helpers\Import-KerberosTicket.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-NTLMImpersonation.ps1"
    . "$Script:ScriptPath\modules\Helpers\Resolve-adPEASName.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-HostsFileManagement.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-KerberosAuthFlow.ps1"
    . "$Script:ScriptPath\modules\Helpers\Get-LAPSGPOConfig.ps1"
    . "$Script:ScriptPath\modules\Helpers\Get-OUPermissions.ps1"
    . "$Script:ScriptPath\modules\Helpers\Get-GPOLinkage.ps1"
    . "$Script:ScriptPath\modules\Helpers\Test-adPEASLicense.ps1"
    . "$Script:ScriptPath\modules\Helpers\NTLM-HTTP.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-HTTPRequest.ps1"
    . "$Script:ScriptPath\modules\Helpers\Register-adPEASCompleters.ps1"
    . "$Script:ScriptPath\modules\Helpers\Export-adPEASFile.ps1"
    . "$Script:ScriptPath\modules\Helpers\Test-RemoteAdminAccess.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-RBCDOperation.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-ShadowCredentialOperation.ps1"
    . "$Script:ScriptPath\modules\Helpers\Kerberos-PAC.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-TicketForge.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-DCSync.ps1"
    . "$Script:ScriptPath\modules\Helpers\Invoke-PasswordSpray.ps1"
    . "$Script:ScriptPath\modules\Helpers\Get-CertificateInfo.ps1"
    . "$Script:ScriptPath\modules\Helpers\Request-ADCSCertificate.ps1"
    . "$Script:ScriptPath\modules\Helpers\Search-Value.ps1"

    # Check Modules
    . "$Script:ScriptPath\modules\Checks\Domain\Get-DomainInformation.ps1"
    . "$Script:ScriptPath\modules\Checks\Domain\Get-DomainPasswordPolicy.ps1"
    . "$Script:ScriptPath\modules\Checks\Domain\Get-DomainTrusts.ps1"
    . "$Script:ScriptPath\modules\Checks\Domain\Get-LDAPConfiguration.ps1"
    . "$Script:ScriptPath\modules\Checks\Domain\Get-SMBSigningStatus.ps1"
    . "$Script:ScriptPath\modules\Checks\Accounts\Get-PrivilegedGroupMembers.ps1"
    . "$Script:ScriptPath\modules\Checks\Accounts\Get-ProtectedUsersStatus.ps1"
    . "$Script:ScriptPath\modules\Checks\Accounts\Get-InactiveAdminAccounts.ps1"
    . "$Script:ScriptPath\modules\Checks\Accounts\Get-AdminPasswordNeverExpires.ps1"
    . "$Script:ScriptPath\modules\Checks\Accounts\Get-AdminReversibleEncryption.ps1"
    . "$Script:ScriptPath\modules\Checks\Accounts\Get-ManagedServiceAccountSecurity.ps1"
    . "$Script:ScriptPath\modules\Checks\Accounts\Get-SIDHistoryInjection.ps1"
    . "$Script:ScriptPath\modules\Checks\Accounts\Get-NonDefaultUserOwners.ps1"
    . "$Script:ScriptPath\modules\Checks\Accounts\Get-PasswordNotRequired.ps1"
    . "$Script:ScriptPath\modules\Checks\Delegation\Get-UnconstrainedDelegation.ps1"
    . "$Script:ScriptPath\modules\Checks\Delegation\Get-ConstrainedDelegation.ps1"
    . "$Script:ScriptPath\modules\Checks\Delegation\Get-ResourceBasedConstrainedDelegation.ps1"
    . "$Script:ScriptPath\modules\Checks\Rights\Get-DangerousACLs.ps1"
    . "$Script:ScriptPath\modules\Checks\Rights\Get-DangerousOUPermissions.ps1"
    . "$Script:ScriptPath\modules\Checks\Rights\Get-PasswordResetRights.ps1"
    . "$Script:ScriptPath\modules\Checks\Rights\Get-AddComputerRights.ps1"
    . "$Script:ScriptPath\modules\Checks\Rights\Get-LAPSPermissions.ps1"
    . "$Script:ScriptPath\modules\Checks\Computer\Get-LAPSConfiguration.ps1"
    . "$Script:ScriptPath\modules\Checks\Computer\Get-OutdatedComputers.ps1"
    . "$Script:ScriptPath\modules\Checks\Computer\Get-InfrastructureServers.ps1"
    . "$Script:ScriptPath\modules\Checks\Computer\Get-NonDefaultComputerOwners.ps1"
    . "$Script:ScriptPath\modules\Checks\GPO\Get-GPOPermissions.ps1"
    . "$Script:ScriptPath\modules\Checks\GPO\Get-GPOLocalGroupMembership.ps1"
    . "$Script:ScriptPath\modules\Checks\GPO\Get-GPOScheduledTasks.ps1"
    . "$Script:ScriptPath\modules\Checks\GPO\Get-GPOScriptPaths.ps1"
    . "$Script:ScriptPath\modules\Checks\ADCS\Get-ADCSTemplate.ps1"
    . "$Script:ScriptPath\modules\Checks\ADCS\Get-ADCSVulnerabilities.ps1"
    . "$Script:ScriptPath\modules\Checks\Application\Get-ExchangeInfrastructure.ps1"
    . "$Script:ScriptPath\modules\Checks\Application\Get-SCCMInfrastructure.ps1"
    . "$Script:ScriptPath\modules\Checks\Application\Get-SCOMInfrastructure.ps1"
    . "$Script:ScriptPath\modules\Checks\Creds\Get-KerberoastableAccounts.ps1"
    . "$Script:ScriptPath\modules\Checks\Creds\Get-ASREPRoastableAccounts.ps1"
    . "$Script:ScriptPath\modules\Checks\Creds\Get-UnixPasswordAccounts.ps1"
    . "$Script:ScriptPath\modules\Checks\Creds\Get-CredentialExposure.ps1"
    . "$Script:ScriptPath\modules\Checks\Creds\Get-LAPSCredentialAccess.ps1"
    . "$Script:ScriptPath\modules\Checks\Creds\Get-PasswordInDescription.ps1"

    # Reporting Modules
    . "$Script:ScriptPath\modules\Reporting\Export-HTMLReport.ps1"
    . "$Script:ScriptPath\modules\Reporting\Convert-adPEASReport.ps1"
    . "$Script:ScriptPath\modules\Reporting\Compare-adPEASReport.ps1"

    # Collector Modules
    . "$Script:ScriptPath\modules\Collector\Invoke-adPEASCollector.ps1"
}
# ===== Main Function =====
function Invoke-adPEAS {
<#
.SYNOPSIS
    Main execution function for adPEAS v2.

.DESCRIPTION
    This function wraps the entire adPEAS execution logic.
    Can be called with connection parameters or reuse an existing session.

    Connection Parameters (Optional - pass-through to Connect-adPEAS):
    - Domain, Server, UseLDAPS, TimeoutSeconds
    - Authentication: UseWindowsAuth, Credential, Username/Password, Certificate/CertificatePassword

    If connection parameters are provided, Invoke-adPEAS will establish a connection automatically.
    If no parameters are provided, it will reuse an existing session or show help.

    SESSION PERSISTENCE:
    The LDAP session is always kept alive after Invoke-adPEAS completes.
    This allows you to:
    - Check the session with Get-adPEASSession
    - Run additional Get-Domain* queries
    - Execute additional scans with Invoke-adPEAS
    Use Disconnect-adPEAS to explicitly close the session when done.

.PARAMETER Domain
    The Active Directory domain to analyze (optional).

.PARAMETER Server
    Specific Domain Controller (FQDN or IP) (optional).

.PARAMETER UseWindowsAuth
    Use Windows Authentication (current user context).

.PARAMETER Credential
    PSCredential object for authentication.

.PARAMETER Username
    Username for authentication (requires -Password).

.PARAMETER Password
    Password for authentication (requires -Username). Accepts String or SecureString.

.PARAMETER Certificate
    Path to PKCS#12 certificate file or Base64-encoded certificate for PKINIT authentication.

.PARAMETER CertificatePassword
    Password for certificate (requires -Certificate). Accepts String or SecureString.

.PARAMETER UseLDAPS
    Forces LDAPS (Port 636).

.PARAMETER Outputfile
    Path to output file (without extension). If set, adPEAS writes reports to this path.
    Generates up to 3 files depending on -Format:
      - .txt  (Text report, with -Format Text or All)
      - .html (Interactive HTML report, with -Format HTML or All)
      - .json (Machine-readable JSON export, with -Format JSON or All)
    By default, text output includes ANSI color codes (viewable with cat/Get-Content).
    Use -NoColor to write plain text without color codes.

.PARAMETER Module
    Array of Modules to execute. Available: Domain, Creds, Rights, Delegation, ADCS, Accounts, GPO, Computer, Application, BloodHound.
    Default: All Modules.

.PARAMETER OPSEC
    Skips OPSEC-critical and heavy-load checks (Kerberoast, ASREPRoast, BloodHound collection, PasswordInDescription, NonDefaultOwners, OutdatedComputers).
    These checks enumerate thousands of objects and generate significant LDAP traffic.

.PARAMETER NoColor
    Disables colored console output. Useful for logging or terminals that don't support ANSI colors.

.PARAMETER VerboseLogging
    Writes verbose log messages (Write-Log) to the output file AND enables -Verbose for console output.
    Requires -Outputfile to be specified for file logging.
    Useful for troubleshooting and detailed analysis.

.PARAMETER InactiveDays
    Threshold in days for account activity analysis. Accounts without login activity
    within this period are considered inactive/stale. Default: 90 days.
    This affects checks like Get-LAPSPermissions, Get-LAPSConfiguration, Get-InactiveAdminAccounts, etc.

.PARAMETER IncludePrivileged
    Include privileged accounts (Domain Admins, Enterprise Admins, etc.) in permission checks.
    By default, these expected privileged accounts are hidden from output.
    When enabled, privileged accounts are shown in yellow (Hint) instead of red (Finding).
    Affects: Get-DangerousACLs, Get-GPOPermissions, Get-AddComputerRights, Get-PrivilegedGroupMembers, Get-ADCSVulnerabilities.

.PARAMETER TimeoutSeconds
    Timeout in seconds for LDAP operations.
    Default: 30 seconds
    Valid range: 5-600 seconds. Increase for high-latency connections (SOCKS tunnels, VPN).
    Example: -TimeoutSeconds 120

.PARAMETER OutputAppend
    Appends findings to an existing report instead of overwriting it.
    Requires -Outputfile to be specified.
    When used with -Module, only the specified module's findings are replaced in the report.
    Previous findings from other modules are preserved using the JSON export file.
    Example: Run modules individually and build up a combined report:
      Invoke-adPEAS -Module Domain -Outputfile report -OutputAppend
      Invoke-adPEAS -Module Accounts -Outputfile report -OutputAppend

.EXAMPLE
    # v1 Style: Direct execution with connection parameters
    Import-Module .\adPEAS.ps1
    Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth

.EXAMPLE
    # v1 Style: With credentials
    Import-Module .\adPEAS.ps1
    Invoke-adPEAS -Domain "contoso.com" -Credential (Get-Credential)

.EXAMPLE
    # v1 Style: With username/password
    Import-Module .\adPEAS.ps1
    Invoke-adPEAS -Domain "contoso.com" -Username "john.doe" -Password "P@ssw0rd!"

.EXAMPLE
    # v2 Style: Establish session first, then run
    Import-Module .\adPEAS.ps1
    Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth
    Invoke-adPEAS

.EXAMPLE
    # Write to file with existing session
    Invoke-adPEAS -Outputfile .\adPEAS_out.txt

.EXAMPLE
    # Run specific Modules only
    Invoke-adPEAS -Module Domain,Accounts,GPO

.EXAMPLE
    # OPSEC mode (stealth - no Kerberoast, ASREPRoast, BloodHound collection)
    Invoke-adPEAS -Domain "contoso.com" -UseWindowsAuth -OPSEC

.EXAMPLE
    # Incremental scan: Run modules separately and build up one combined report
    Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth
    Invoke-adPEAS -Module Domain -Outputfile .\report -OutputAppend
    Invoke-adPEAS -Module Accounts -Outputfile .\report -OutputAppend
    Invoke-adPEAS -Module Rights -Outputfile .\report -OutputAppend
    # report.html now contains findings from all three modules
#>
    [CmdletBinding(DefaultParameterSetName='Default')]
    param(
        # ===== Connection Parameters (Optional - Pass-through to Connect-adPEAS) =====
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [switch]$UseLDAPS,

        [Parameter(Mandatory=$false, ParameterSetName='WindowsAuth')]
        [switch]$UseWindowsAuth,

        [Parameter(Mandatory=$false, ParameterSetName='PSCredential')]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false, ParameterSetName='UsernamePassword')]
        [string]$Username,

        [Parameter(Mandatory=$false, ParameterSetName='UsernamePassword')]
        $Password,  # Accepts SecureString or String

        [Parameter(Mandatory=$false, ParameterSetName='Certificate')]
        [string]$Certificate,

        [Parameter(Mandatory=$false, ParameterSetName='Certificate')]
        $CertificatePassword = "",  # Accepts SecureString or String. Default: empty (for unprotected PFX)

        # ===== Execution Parameters =====
        [Parameter(Mandatory=$false)]
        [string]$Outputfile,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Domain","Creds","Rights","Delegation","ADCS","Accounts","GPO","Computer","Application","Bloodhound")]
        [string[]]$Module,

        [Parameter(Mandatory=$false)]
        [switch]$OPSEC,

        [Parameter(Mandatory=$false)]
        [switch]$NoColor,

        [Parameter(Mandatory=$false)]
        [switch]$VerboseLogging,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1, 3650)]
        [int]$InactiveDays = 90,

        [Parameter(Mandatory=$false)]
        [switch]$IncludePrivileged,

        [Parameter(Mandatory=$false)]
        [ValidateRange(5, 600)]
        [int]$TimeoutSeconds = 30,

        # ===== Output Format Parameters =====
        [Parameter(Mandatory=$false)]
        [ValidateSet('Text', 'HTML', 'JSON', 'All')]
        [string]$Format = 'All',

        # ===== Append Mode =====
        [Parameter(Mandatory=$false)]
        [switch]$OutputAppend,

        # ===== License Parameter =====
        [Parameter(Mandatory=$false)]
        [string]$License,

        # ===== Statistics Parameter =====
        [Parameter(Mandatory=$false)]
        [switch]$Statistics
    )

    # Reset script variables for each invocation
    $Script:StartTime = Get-Date
    $Script:adPEAS_OutputColor = -not $NoColor
    $Script:adPEAS_Outputfile = $null
    $Script:adPEAS_VerboseLogging = $VerboseLogging
    $Script:DefaultInactiveDays = $InactiveDays

    # Initialize LDAP Statistics tracking (null = disabled, zero overhead)
    if ($Statistics) {
        $Script:LDAPStatistics = @{
            TotalQueries        = 0
            TotalResults        = 0
            TotalEstimatedBytes = 0
            Modules             = [ordered]@{}
            _ModuleStartQueries = 0
            _ModuleStartResults = 0
            _ModuleStartBytes   = 0
            _CurrentModule      = $null
        }
    } else {
        $Script:LDAPStatistics = $null
    }

    # Auto-enable -Verbose when -VerboseLogging is used
    # Set local $VerbosePreference so it propagates to child function calls via scope chain
    if ($VerboseLogging) {
        $VerbosePreference = 'Continue'
    }

    # Validate -OutputAppend requires -Outputfile
    if ($OutputAppend -and -not $PSBoundParameters['Outputfile']) {
        Write-Warning "[adPEAS] -OutputAppend requires -Outputfile. Ignoring -OutputAppend."
        $OutputAppend = [switch]::new($false)
    }

    # Validate -OutputAppend requires a format that produces JSON (for findings merge)
    if ($OutputAppend -and $Format -notin @('All', 'JSON')) {
        Write-Warning "[adPEAS] -OutputAppend requires JSON findings cache. Use -Format All or -Format JSON. Ignoring -OutputAppend."
        $OutputAppend = [switch]::new($false)
    }

    # Initialize findings collection if HTML or JSON format requested
    if ($Format -in @('HTML', 'JSON', 'All')) {
        Initialize-FindingsCollection
        Write-Log "[adPEAS] Findings collection enabled (Format: $Format)"
    }

    # ===== Output File Configuration =====
    # Determine output file paths based on -Outputfile and -Format parameters
    $Script:HTMLOutputPath = $null
    $Script:JSONOutputPath = $null
    # Track IncludePrivileged mode for HTML report tooltip filtering
    $Script:IncludePrivilegedMode = $IncludePrivileged.IsPresent

    if ($PSBoundParameters['Outputfile']) {
        # Resolve to absolute path to ensure consistent file access throughout the script
        # This is critical because relative paths may fail when functions change working directory
        $resolvedOutputfile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Outputfile)

        # Strip any existing extension from the base path
        $basePath = $resolvedOutputfile
        if ([System.IO.Path]::HasExtension($resolvedOutputfile)) {
            $basePath = [System.IO.Path]::ChangeExtension($resolvedOutputfile, $null).TrimEnd('.')
        }

        # Create directory if it doesn't exist
        $OutputDir = Split-Path -Parent $basePath
        if ($OutputDir -and -not (Test-Path $OutputDir)) {
            try {
                New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
                Write-Warning "[adPEAS] Directory '$OutputDir' did not exist and was created"
            } catch {
                Write-Warning "[adPEAS] Could not create directory '$OutputDir': $_"
                return
            }
        }

        # Set output paths based on format
        if ($Format -in @('Text', 'All')) {
            $textPath = "$basePath.txt"
            try {
                if (-not $OutputAppend) {
                    # Normal mode: Create/truncate file to verify write access
                    [io.file]::OpenWrite($textPath).close()
                }
                # Append mode: File will be created or appended to by Write-adPEASOutput
                $Script:adPEAS_Outputfile = $textPath
            } catch {
                Write-Warning "[adPEAS] Unable to write text output to '$textPath', please check path and permissions!"
            }
        }

        if ($Format -in @('HTML', 'All')) {
            $Script:HTMLOutputPath = "$basePath.html"
        }

        # For HTML-only and JSON-only mode, don't write to text file
        if ($Format -in @('HTML', 'JSON')) {
            $Script:adPEAS_Outputfile = $null
        }
    }

    # Warn if VerboseLogging is enabled without text output (but still enable console verbose)
    if ($VerboseLogging -and -not $Script:adPEAS_Outputfile) {
        Write-Warning "[adPEAS] -VerboseLogging: File logging requires -Outputfile with Text format. Verbose messages will be shown in console only."
        # Keep VerboseLogging = $true so that $VerbosePreference stays 'Continue' for console output
        # File logging won't happen since $Script:adPEAS_Outputfile is $null
    }

# ===== Banner =====
Show-Logo -Version $Script:adPEASVersion

# ===== Main Logic =====
try {
    # ===== License Validation =====
    $_licJson = $null
    # Priority: runtime -License param > Connect-adPEAS stored license > embedded license
    if ($PSBoundParameters.ContainsKey('License') -and $License -and (Test-Path $License -ErrorAction SilentlyContinue)) {
        $_licJson = Get-Content $License -Raw -Encoding UTF8
    }
    elseif ($Script:RuntimeLicense) {
        $_licJson = $Script:RuntimeLicense
    }
    elseif ($Script:EmbeddedLicense) {
        $_licJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Script:EmbeddedLicense))
    }

    $_licResult = if ($_licJson) { Test-adPEASLicense -LicenseJson $_licJson } else { $null }

    if ($_licResult -and $_licResult.IsValid -and -not $_licResult.Expired) {
        $Script:adPEASDisclaimer = $_licResult.Message
        Show-Line $Script:adPEASDisclaimer -Class Note
    }
    else {
        # Default disclaimer (XOR obfuscated)
        $_lm="GCQlP2w+KTwjPjhsOy0/bCspIik+LTgpKGw5PyUiK2wtbDgjIyBsOCQtOGw+KT05JT4pP2wtbDotICUobC8jISEpPi8lLSBsICUvKSI/KWwqIz5sLyMiPzkgOCUiK2wjPmwhLSItKykobD8pPjolLylsOT8pYg==";$_lk=0x4C
        $Script:adPEASDisclaimer=(-join([Convert]::FromBase64String($_lm)|ForEach-Object{[char]($_-bxor$_lk)}))
        Show-Line $Script:adPEASDisclaimer -Class Finding
    }
    Write-Log "[adPEAS] Script started: $Script:StartTime"
    Write-Log "[adPEAS] Version: $Script:adPEASVersion"

    if ($OPSEC) {
        Write-Log "[adPEAS] OPSEC mode enabled: No ASREPRoast/Kerberoast/BloodHound"
    }

    # ===== Connection Handling =====
    # Check if ANY connection/authentication parameters were provided
    $HasConnectionParams = $PSBoundParameters.ContainsKey('Domain') -or
                          $PSBoundParameters.ContainsKey('Server') -or
                          $PSBoundParameters.ContainsKey('UseWindowsAuth') -or
                          $PSBoundParameters.ContainsKey('Credential') -or
                          $PSBoundParameters.ContainsKey('Username') -or
                          $PSBoundParameters.ContainsKey('Password') -or
                          $PSBoundParameters.ContainsKey('Certificate') -or
                          $PSBoundParameters.ContainsKey('CertificatePassword') -or
                          $PSBoundParameters.ContainsKey('UseLDAPS')

    # Check for active LdapConnection (used for all LDAP operations)
    $hasLdapConnection = ($null -ne $Script:LdapConnection)
    $HasActiveSession = ($null -ne $Script:LDAPContext) -and $hasLdapConnection

    # Scenario 1: No connection parameters AND no active session ? Show help
    if (-not $HasConnectionParams -and -not $HasActiveSession) {
        Show-NoSessionError -Context "Invoke-adPEAS"
        return
    }

    # Scenario 2: Active session exists AND no new connection parameters ? Reuse session
    if ($HasActiveSession -and -not $HasConnectionParams) {
        Write-Log "[adPEAS] Reusing existing LDAP session"
        Show-Header "Using existing LDAP connection"

        # Use LDAP-verified identity if available
        $AuthenticatedUser = if ($Script:LDAPContext.AuthenticatedUser) {
            $Script:LDAPContext.AuthenticatedUser
        } elseif ($Script:LDAPContext.Credential) {
            $Script:LDAPContext.Credential.UserName
        } else {
            "$env:USERDOMAIN\$env:USERNAME"
        }

        # Build auth method display string
        $AuthDisplay = switch ($Script:LDAPContext.AuthMethod) {
            'Kerberos'    { "Kerberos" }
            'SimpleBind'  { "LDAP SimpleBind" }
            'WindowsSSPI' { if ($Script:LDAPContext.KerberosUsed) { "Kerberos (SSPI)" } else { "Windows SSPI" } }
            default       { $Script:LDAPContext.Protocol }  # Fallback to protocol if AuthMethod not set
        }

        Show-Line "Connected to domain '$($Script:LDAPContext.Domain)' on server '$($Script:LDAPContext.Server)' as '$AuthenticatedUser' via $AuthDisplay"
    }
    # Scenario 3: Connection parameters provided ? Establish new connection via Connect-adPEAS
    elseif ($HasConnectionParams) {
        Show-Header "Establishing LDAP Connection"

        # Build parameters for Connect-adPEAS (pass-through)
        $ConnectionParams = @{}

        # Common parameters
        if ($PSBoundParameters.ContainsKey('Domain')) { $ConnectionParams['Domain'] = $Domain }
        if ($PSBoundParameters.ContainsKey('Server')) { $ConnectionParams['Server'] = $Server }
        if ($PSBoundParameters.ContainsKey('UseLDAPS')) { $ConnectionParams['UseLDAPS'] = $true }
        # Always ignore SSL errors for maximum compatibility in pentesting environments
        $ConnectionParams['IgnoreSSLErrors'] = $true

        # Authentication parameters (parameter-set specific)
        if ($PSBoundParameters.ContainsKey('UseWindowsAuth')) { $ConnectionParams['UseWindowsAuth'] = $true }
        if ($PSBoundParameters.ContainsKey('Credential')) { $ConnectionParams['Credential'] = $Credential }
        if ($PSBoundParameters.ContainsKey('Username')) { $ConnectionParams['Username'] = $Username }
        if ($PSBoundParameters.ContainsKey('Password')) { $ConnectionParams['Password'] = $Password }
        if ($PSBoundParameters.ContainsKey('Certificate')) { $ConnectionParams['Certificate'] = $Certificate }
        if ($PSBoundParameters.ContainsKey('CertificatePassword')) { $ConnectionParams['CertificatePassword'] = $CertificatePassword }

        # Timeout parameter (pass-through to Connect-adPEAS)
        if ($PSBoundParameters.ContainsKey('TimeoutSeconds')) { $ConnectionParams['TimeoutSeconds'] = $TimeoutSeconds }

        # License parameter (pass-through to Connect-adPEAS)
        if ($PSBoundParameters.ContainsKey('License')) { $ConnectionParams['License'] = $License }

        # Authentication method handling
        $HasAuthMethod = $PSBoundParameters.ContainsKey('UseWindowsAuth') -or
                        $PSBoundParameters.ContainsKey('Credential') -or
                        $PSBoundParameters.ContainsKey('Username') -or
                        $PSBoundParameters.ContainsKey('Certificate')

        if (-not $HasAuthMethod) {
            # No new auth method specified - check if we can reuse existing session credentials
            if ($HasActiveSession -and $Script:LDAPContext.Credential) {
                # Reuse credentials from existing session
                Write-Log "[adPEAS] Reusing credentials from existing session"
                $ConnectionParams['Credential'] = $Script:LDAPContext.Credential
            }
            elseif ($HasActiveSession -and $Script:LDAPContext.Certificate) {
                # Reuse certificate auth from existing session
                Write-Log "[adPEAS] Reusing certificate authentication from existing session"
                $ConnectionParams['Certificate'] = $Script:LDAPContext.Certificate
                if ($Script:LDAPContext.CertificatePassword) {
                    $ConnectionParams['CertificatePassword'] = $Script:LDAPContext.CertificatePassword
                }
            }
            else {
                # No session or session uses Windows Auth - default to Windows Auth
                Write-Log "[adPEAS] No authentication method specified - defaulting to Windows Authentication"
                $ConnectionParams['UseWindowsAuth'] = $true
            }
        }

        try {
            # Call Connect-adPEAS with pass-through parameters (use -Quiet to suppress session info)
            # Connect-adPEAS handles all auth logic, error messages, and user verification
            $Connection = Connect-adPEAS @ConnectionParams -Quiet

            if (-not $Connection) {
                # Connect-adPEAS failed (returned $null)
                Show-Error -Type Connection
                return
            }

            # Use LDAP-verified identity if available
            $AuthenticatedUser = if ($Connection.AuthenticatedUser) {
                $Connection.AuthenticatedUser
            } elseif ($Connection.Credential) {
                $Connection.Credential.UserName
            } else {
                "$env:USERDOMAIN\$env:USERNAME"
            }

            # Build auth method display string
            $AuthDisplay = switch ($Connection.AuthMethod) {
                'Kerberos'    { "Kerberos" }
                'SimpleBind'  { "LDAP SimpleBind" }
                'WindowsSSPI' { if ($Connection.KerberosUsed) { "Kerberos (SSPI)" } else { "Windows SSPI" } }
                default       { $Connection.Protocol }  # Fallback to protocol if AuthMethod not set
            }

            Show-Line "Successfully connected to domain '$($Connection.Domain)' on server '$($Connection.Server)' as '$AuthenticatedUser' via $AuthDisplay" -Class Note
        } catch {
            # Connect-adPEAS threw an error (already displayed by Connect-adPEAS)
            Show-Error -Type Connection
            return
        }
    }

    # ===== Connection Health Check =====
    # Verify that the DC is actually reachable by performing a test query
    Write-Log "[adPEAS] Verifying Domain Controller connectivity..."

    # Use -Quiet mode to suppress detailed output
    $connectionHealthy = Get-adPEASSession -TestConnection -Quiet

    if (-not $connectionHealthy) {
        Show-Error -Type HealthCheck -Message "Domain Controller is not responding" -Hints @(
            "The connection was established but queries to the DC are failing",
            "Possible causes: DC offline, network connectivity lost, firewall blocking LDAP queries"
        )
        return
    }

    Write-Log "[adPEAS] Connection health check passed - DC is reachable"

    # ===== Kerberos Session Health Check =====
    # For Kerberos-based sessions, verify the TGT is still valid before starting module execution
    # This catches overnight ticket expiration early, instead of failing on every individual check
    # Reset SessionInvalid flag from any previous failed run — give fresh TGT check a fair chance
    if ($Script:LDAPContext -and $Script:LDAPContext['SessionInvalid']) {
        $Script:LDAPContext.Remove('SessionInvalid')
        Write-Log "[adPEAS] Cleared SessionInvalid flag from previous run"
    }
    if (-not (Ensure-LDAPConnection)) {
        # Ensure-LDAPConnection already displayed the error message and set SessionInvalid flag
        Show-Header "Scan Summary"
        Show-Line "Duration: 0 seconds" -Class Hint
        Show-Line "Scan was aborted due to invalid LDAP session. No reports were generated." -Class Finding
        Show-Line "Re-authenticate with Connect-adPEAS and try again." -Class Hint
        return
    }

    # 2. Determine Modules
    if (-not $Module) {
        $Module = @('Domain','Creds','Rights','Delegation','ADCS','Accounts','GPO','Computer','Application','Bloodhound')
    }

    Write-Log "[adPEAS] Executing Modules: $($Module -join ', ')"
    Show-Line "Executing Modules: $($Module -join ', ')"

    # Module progress counter
    $moduleCounter = 0
    $moduleTotal = $Module.Count

    # Category Header Mapping - displayed once per module category
    $Script:ModuleCategoryHeaders = @{
        'Domain'     = "Domain Configuration"
        'Accounts'   = "Privileged Accounts"
        'Delegation' = "Delegation Settings"
        'Rights'     = "Access Permissions"
        'Computer'   = "Computer Security"
        'GPO'        = "Group Policy Objects"
        'ADCS'       = "Certificate Services"
        'Application'= "Application Infrastructure"
        'Creds'      = "Credential Exposure"
        'Bloodhound' = "BloodHound Data"
    }

    # 3. Execute checks
    # Helper function to run a check with context for HTML reporting
    function Invoke-CheckWithContext {
        param(
            [string]$Category,
            [string]$CheckName,
            [string]$Title,
            [scriptblock]$Check
        )
        # Skip all remaining checks if session became invalid (e.g., expired Kerberos TGT)
        if ($Script:LDAPContext -and $Script:LDAPContext['SessionInvalid']) {
            Write-Log "[adPEAS] Skipping check '$CheckName' - session invalid"
            return
        }
        Set-CheckContext -Category $Category -CheckName $CheckName -Title $Title
        try {
            & $Check
        } catch {
            Write-Warning "[adPEAS] Check '$CheckName' failed: $_"
            Write-Log "[adPEAS] Check '$CheckName' failed: $_" -Level Error
        } finally {
            Clear-CheckContext
        }
    }

    # Helper functions for LDAP Statistics tracking (no-op when $Script:LDAPStatistics is $null)
    function Enter-StatisticsModule {
        param([string]$ModuleName)
        if (-not $Script:LDAPStatistics) { return }
        $Script:LDAPStatistics._CurrentModule = $ModuleName
        $Script:LDAPStatistics._ModuleStartQueries = $Script:LDAPStatistics.TotalQueries
        $Script:LDAPStatistics._ModuleStartResults = $Script:LDAPStatistics.TotalResults
        $Script:LDAPStatistics._ModuleStartBytes   = $Script:LDAPStatistics.TotalEstimatedBytes
    }

    function Exit-StatisticsModule {
        param([string]$ModuleName)
        if (-not $Script:LDAPStatistics) { return }

        $deltaQueries = $Script:LDAPStatistics.TotalQueries - $Script:LDAPStatistics._ModuleStartQueries
        $deltaResults = $Script:LDAPStatistics.TotalResults - $Script:LDAPStatistics._ModuleStartResults
        $deltaBytes   = $Script:LDAPStatistics.TotalEstimatedBytes - $Script:LDAPStatistics._ModuleStartBytes

        $Script:LDAPStatistics.Modules[$ModuleName] = @{
            Queries        = $deltaQueries
            Results        = $deltaResults
            EstimatedBytes = $deltaBytes
        }
        $Script:LDAPStatistics._CurrentModule = $null

        # Per-module display
        $displayName = if ($Script:ModuleCategoryHeaders[$ModuleName]) {
            $Script:ModuleCategoryHeaders[$ModuleName]
        } else { $ModuleName }

        Show-SubHeader "LDAP Statistics for $displayName"
        Show-KeyValue "Queries" $deltaQueries -Class Note
        Show-KeyValue "Results" $deltaResults -Class Note
        Show-KeyValue "Estimated Traffic" (Format-ByteSize $deltaBytes) -Class Note
    }

    function Format-ByteSize {
        param([long]$Bytes)
        if ($Bytes -ge 1MB) { return "{0:N1} MB" -f ($Bytes / 1MB) }
        if ($Bytes -ge 1KB) { return "{0:N1} KB" -f ($Bytes / 1KB) }
        return "$Bytes Bytes"
    }

    # Domain Module - baseline context for all subsequent checks
    if ($Module -contains 'Domain') {
        $moduleCounter++
        Enter-StatisticsModule 'Domain'
        Show-Header "[$moduleCounter/$moduleTotal] Analyzing $($Script:ModuleCategoryHeaders['Domain'])"
        try {
            Invoke-CheckWithContext -Category 'Domain' -CheckName 'Get-DomainInformation' -Title 'Domain Information' -Check { Get-DomainInformation }
            Invoke-CheckWithContext -Category 'Domain' -CheckName 'Get-DomainPasswordPolicy' -Title 'Password Policy' -Check { Get-DomainPasswordPolicy }
            Invoke-CheckWithContext -Category 'Domain' -CheckName 'Get-DomainTrusts' -Title 'Domain Trusts' -Check { Get-DomainTrusts }
            Invoke-CheckWithContext -Category 'Domain' -CheckName 'Get-LDAPConfiguration' -Title 'LDAP Configuration' -Check { Get-LDAPConfiguration }
            Invoke-CheckWithContext -Category 'Domain' -CheckName 'Get-SMBSigningStatus' -Title 'SMB Signing Status' -Check { Get-SMBSigningStatus }
        } catch {
            Write-Warning "[adPEAS] Error executing Domain Module: $_"
        }
        Exit-StatisticsModule 'Domain'
    }

    # Creds Module - immediately actionable findings first
    if ($Module -contains 'Creds') {
        $moduleCounter++
        Enter-StatisticsModule 'Creds'
        Show-Header "[$moduleCounter/$moduleTotal] Analyzing $($Script:ModuleCategoryHeaders['Creds'])"
        try {
            Invoke-CheckWithContext -Category 'Creds' -CheckName 'Get-LAPSCredentialAccess' -Title 'LAPS Credential Access' -Check { Get-LAPSCredentialAccess }
            Invoke-CheckWithContext -Category 'Creds' -CheckName 'Get-CredentialExposure' -Title 'Credential Exposure' -Check { Get-CredentialExposure }
            Invoke-CheckWithContext -Category 'Creds' -CheckName 'Get-PasswordInDescription' -Title 'Passwords in Description/Info' -Check { Get-PasswordInDescription -OPSEC:$OPSEC }
            Invoke-CheckWithContext -Category 'Creds' -CheckName 'Get-KerberoastableAccounts' -Title 'Kerberoastable Accounts' -Check { Get-KerberoastableAccounts -OPSEC:$OPSEC }
            Invoke-CheckWithContext -Category 'Creds' -CheckName 'Get-ASREPRoastableAccounts' -Title 'ASREProastable Accounts' -Check { Get-ASREPRoastableAccounts -OPSEC:$OPSEC }
            Invoke-CheckWithContext -Category 'Creds' -CheckName 'Get-UnixPasswordAccounts' -Title 'Unix Password Accounts' -Check { Get-UnixPasswordAccounts }
        } catch {
            Write-Warning "[adPEAS] Error executing Creds Module: $_"
        }
        Exit-StatisticsModule 'Creds'
    }

    # Rights Module - privilege escalation paths
    if ($Module -contains 'Rights') {
        $moduleCounter++
        Enter-StatisticsModule 'Rights'
        Show-Header "[$moduleCounter/$moduleTotal] Analyzing $($Script:ModuleCategoryHeaders['Rights'])"
        try {
            Invoke-CheckWithContext -Category 'Rights' -CheckName 'Get-DangerousACLs' -Title 'Dangerous ACLs' -Check { Get-DangerousACLs -IncludePrivileged:$IncludePrivileged }
            Invoke-CheckWithContext -Category 'Rights' -CheckName 'Get-DangerousOUPermissions' -Title 'Dangerous OU Permissions' -Check { Get-DangerousOUPermissions -IncludePrivileged:$IncludePrivileged }
            Invoke-CheckWithContext -Category 'Rights' -CheckName 'Get-PasswordResetRights' -Title 'Password Reset Rights' -Check { Get-PasswordResetRights -IncludePrivileged:$IncludePrivileged }
            Invoke-CheckWithContext -Category 'Rights' -CheckName 'Get-AddComputerRights' -Title 'Add Computer Rights' -Check { Get-AddComputerRights -IncludePrivileged:$IncludePrivileged }
            Invoke-CheckWithContext -Category 'Rights' -CheckName 'Get-LAPSPermissions' -Title 'LAPS Permissions' -Check { Get-LAPSPermissions -IncludePrivileged:$IncludePrivileged }
        } catch {
            Write-Warning "[adPEAS] Error executing Rights Module: $_"
        }
        Exit-StatisticsModule 'Rights'
    }

    # Delegation Module - delegation abuse vectors
    if ($Module -contains 'Delegation') {
        $moduleCounter++
        Enter-StatisticsModule 'Delegation'
        Show-Header "[$moduleCounter/$moduleTotal] Analyzing $($Script:ModuleCategoryHeaders['Delegation'])"
        try {
            Invoke-CheckWithContext -Category 'Delegation' -CheckName 'Get-UnconstrainedDelegation' -Title 'Unconstrained Delegation' -Check { Get-UnconstrainedDelegation }
            Invoke-CheckWithContext -Category 'Delegation' -CheckName 'Get-ConstrainedDelegation' -Title 'Constrained Delegation' -Check { Get-ConstrainedDelegation }
            Invoke-CheckWithContext -Category 'Delegation' -CheckName 'Get-ResourceBasedConstrainedDelegation' -Title 'Resource-Based Constrained Delegation' -Check { Get-ResourceBasedConstrainedDelegation }
        } catch {
            Write-Warning "[adPEAS] Error executing Delegation Module: $_"
        }
        Exit-StatisticsModule 'Delegation'
    }

    # ADCS Module - certificate abuse (often critical)
    if ($Module -contains 'ADCS') {
        $moduleCounter++
        Enter-StatisticsModule 'ADCS'
        Show-Header "[$moduleCounter/$moduleTotal] Analyzing $($Script:ModuleCategoryHeaders['ADCS'])"
        try {
            Invoke-CheckWithContext -Category 'ADCS' -CheckName 'Get-ADCSVulnerabilities' -Title 'ADCS Vulnerabilities' -Check { Get-ADCSVulnerabilities -IncludePrivileged:$IncludePrivileged }
        } catch {
            Write-Warning "[adPEAS] Error executing ADCS Module: $_"
        }
        Exit-StatisticsModule 'ADCS'
    }

    # Accounts Module - privileged account hygiene
    if ($Module -contains 'Accounts') {
        $moduleCounter++
        Enter-StatisticsModule 'Accounts'
        Show-Header "[$moduleCounter/$moduleTotal] Analyzing $($Script:ModuleCategoryHeaders['Accounts'])"
        try {
            Invoke-CheckWithContext -Category 'Accounts' -CheckName 'Get-PrivilegedGroupMembers' -Title 'Privileged Group Members' -Check { Get-PrivilegedGroupMembers -IncludePrivileged:$IncludePrivileged }
            Invoke-CheckWithContext -Category 'Accounts' -CheckName 'Get-SIDHistoryInjection' -Title 'SID History Injection' -Check { Get-SIDHistoryInjection }
            Invoke-CheckWithContext -Category 'Accounts' -CheckName 'Get-ManagedServiceAccountSecurity' -Title 'Managed Service Account Security' -Check { Get-ManagedServiceAccountSecurity }
            Invoke-CheckWithContext -Category 'Accounts' -CheckName 'Get-ProtectedUsersStatus' -Title 'Protected Users Status' -Check { Get-ProtectedUsersStatus }
            Invoke-CheckWithContext -Category 'Accounts' -CheckName 'Get-InactiveAdminAccounts' -Title 'Inactive Admin Accounts' -Check { Get-InactiveAdminAccounts }
            Invoke-CheckWithContext -Category 'Accounts' -CheckName 'Get-AdminPasswordNeverExpires' -Title 'Admin Password Never Expires' -Check { Get-AdminPasswordNeverExpires }
            Invoke-CheckWithContext -Category 'Accounts' -CheckName 'Get-AdminReversibleEncryption' -Title 'Admin Reversible Encryption' -Check { Get-AdminReversibleEncryption }
            Invoke-CheckWithContext -Category 'Accounts' -CheckName 'Get-PasswordNotRequired' -Title 'Password Not Required Accounts' -Check { Get-PasswordNotRequired }
            Invoke-CheckWithContext -Category 'Accounts' -CheckName 'Get-NonDefaultUserOwners' -Title 'Non-Default User Owners' -Check { Get-NonDefaultUserOwners -OPSEC:$OPSEC }
        } catch {
            Write-Warning "[adPEAS] Error executing Accounts Module: $_"
        }
        Exit-StatisticsModule 'Accounts'
    }

    # GPO Module - GPO abuse vectors
    if ($Module -contains 'GPO') {
        $moduleCounter++
        Enter-StatisticsModule 'GPO'
        Show-Header "[$moduleCounter/$moduleTotal] Analyzing $($Script:ModuleCategoryHeaders['GPO'])"
        try {
            Invoke-CheckWithContext -Category 'GPO' -CheckName 'Get-GPOPermissions' -Title 'GPO Permissions' -Check { Get-GPOPermissions -IncludePrivileged:$IncludePrivileged }
            Invoke-CheckWithContext -Category 'GPO' -CheckName 'Get-GPOLocalGroupMembership' -Title 'GPO Local Group Membership' -Check { Get-GPOLocalGroupMembership }
            Invoke-CheckWithContext -Category 'GPO' -CheckName 'Get-GPOScheduledTasks' -Title 'GPO Scheduled Tasks' -Check { Get-GPOScheduledTasks }
            Invoke-CheckWithContext -Category 'GPO' -CheckName 'Get-GPOScriptPaths' -Title 'GPO Script Paths' -Check { Get-GPOScriptPaths }
        } catch {
            Write-Warning "[adPEAS] Error executing GPO Module: $_"
        }
        Exit-StatisticsModule 'GPO'
    }

    # Computer Module - computer security and LAPS configuration
    if ($Module -contains 'Computer') {
        $moduleCounter++
        Enter-StatisticsModule 'Computer'
        Show-Header "[$moduleCounter/$moduleTotal] Analyzing $($Script:ModuleCategoryHeaders['Computer'])"
        try {
            Invoke-CheckWithContext -Category 'Computer' -CheckName 'Get-InfrastructureServers' -Title 'Infrastructure Servers' -Check { Get-InfrastructureServers }
            Invoke-CheckWithContext -Category 'Computer' -CheckName 'Get-NonDefaultComputerOwners' -Title 'Non-Default Computer Owners' -Check { Get-NonDefaultComputerOwners -OPSEC:$OPSEC }
            Invoke-CheckWithContext -Category 'Computer' -CheckName 'Get-LAPSConfiguration' -Title 'LAPS Configuration' -Check { Get-LAPSConfiguration }
            Invoke-CheckWithContext -Category 'Computer' -CheckName 'Get-OutdatedComputers' -Title 'Outdated Computers' -Check { Get-OutdatedComputers -OPSEC:$OPSEC }
        } catch {
            Write-Warning "[adPEAS] Error executing Computer Module: $_"
        }
        Exit-StatisticsModule 'Computer'
    }

    # Application Module - infrastructure overview (Exchange, SCCM, SCOM)
    if ($Module -contains 'Application') {
        $moduleCounter++
        Enter-StatisticsModule 'Application'
        Show-Header "[$moduleCounter/$moduleTotal] Analyzing $($Script:ModuleCategoryHeaders['Application'])"
        try {
            Invoke-CheckWithContext -Category 'Application' -CheckName 'Get-ExchangeInfrastructure' -Title 'Exchange Infrastructure' -Check { Get-ExchangeInfrastructure }
            Invoke-CheckWithContext -Category 'Application' -CheckName 'Get-SCCMInfrastructure' -Title 'SCCM Infrastructure' -Check { Get-SCCMInfrastructure }
            Invoke-CheckWithContext -Category 'Application' -CheckName 'Get-SCOMInfrastructure' -Title 'SCOM Infrastructure' -Check { Get-SCOMInfrastructure }
        } catch {
            Write-Warning "[adPEAS] Error executing Application Module: $_"
        }
        Exit-StatisticsModule 'Application'
    }

    # Bloodhound Module
    if ($Module -contains 'Bloodhound') {
        $moduleCounter++
        Enter-StatisticsModule 'Bloodhound'
        Show-Header "[$moduleCounter/$moduleTotal] Collecting $($Script:ModuleCategoryHeaders['Bloodhound'])"

        if ($OPSEC) {
            Show-Line "OPSEC mode: Skipping BloodHound collection" -Class Hint
        }
        else {
            try {
                # Pass output directory to collector if -Outputfile was specified
                $bhOutputDir = $null
                if ($Script:adPEAS_Outputfile) {
                    $bhOutputDir = Split-Path -Parent $Script:adPEAS_Outputfile
                } elseif ($Script:HTMLOutputPath) {
                    $bhOutputDir = Split-Path -Parent $Script:HTMLOutputPath
                }
                if ($bhOutputDir) {
                    Invoke-CheckWithContext -Category 'Bloodhound' -CheckName 'Invoke-adPEASCollector' -Title 'BloodHound Collector' -Check { Invoke-adPEASCollector -OutputPath $bhOutputDir }
                } else {
                    Invoke-CheckWithContext -Category 'Bloodhound' -CheckName 'Invoke-adPEASCollector' -Title 'BloodHound Collector' -Check { Invoke-adPEASCollector }
                }
            } catch {
                Write-Warning "[adPEAS] Error executing Bloodhound Module: $_"
            }
        }
        Exit-StatisticsModule 'Bloodhound'
    }

    # Check if session became invalid during check execution (e.g., expired Kerberos TGT)
    $sessionAborted = $Script:LDAPContext -and $Script:LDAPContext['SessionInvalid']

    # 4. Merge with previous findings if -OutputAppend
    # The JSON cache path is always basePath.json, regardless of output format
    if ($OutputAppend -and -not $sessionAborted) {
        $cachePath = "$basePath.json"

        if (Test-Path $cachePath) {
            try {
                $previousFindings = Import-FindingsCache -Path $cachePath
                $currentFindings = Get-FindingsCollection

                # Module names = Category names (1:1 mapping)
                $replacedCategories = @($Module)

                $mergedFindings = Merge-FindingsCollection `
                    -PreviousFindings $previousFindings `
                    -CurrentFindings $currentFindings `
                    -ReplacedCategories $replacedCategories

                Set-FindingsCollection -Findings $mergedFindings
                Show-Line "Appended to existing report: merged $($previousFindings.Count) previous + $($currentFindings.Count) new findings" -Class Note
            }
            catch {
                Write-Warning "[adPEAS] Could not load previous findings from '$cachePath': $_"
                Write-Warning "[adPEAS] Continuing without append - creating fresh report"
            }
        } else {
            Write-Log "[adPEAS] No previous cache found at '$cachePath' - first append run"
        }
    }

    # 5. Generate HTML Report if requested
    if ($Script:HTMLOutputPath -and -not $sessionAborted) {
        try {
            Export-HTMLReport -OutputPath $Script:HTMLOutputPath
            Write-Log "[adPEAS] HTML report generated: $($Script:HTMLOutputPath)"
        } catch {
            Write-Warning "[adPEAS] Error generating HTML report: $_"
            $Script:HTMLOutputPath = $null  # Clear path so we don't show it in summary
        }
    }

    # 5b. Generate JSON export (for -Format All or -Format JSON)
    # JSON path is always basePath.json, used for -OutputAppend cache and Convert-adPEASReport
    if ($Format -in @('All', 'JSON') -and $basePath -and -not $sessionAborted) {
        $jsonPath = "$basePath.json"
        try {
            Export-FindingsCache -Path $jsonPath
            $Script:JSONOutputPath = $jsonPath
            Write-Log "[adPEAS] Findings JSON saved to: $jsonPath"
        }
        catch {
            Write-Warning "[adPEAS] Could not save JSON export to '$jsonPath': $_"
            $Script:JSONOutputPath = $null
        }
    }

    # 6. LDAP Statistics Summary (before Scan Summary)
    if ($Script:LDAPStatistics -and $Script:LDAPStatistics.Modules.Count -gt 0) {
        Show-Header "LDAP Statistics Summary"

        foreach ($modName in $Script:LDAPStatistics.Modules.Keys) {
            $modStats = $Script:LDAPStatistics.Modules[$modName]
            $displayName = if ($Script:ModuleCategoryHeaders[$modName]) {
                $Script:ModuleCategoryHeaders[$modName]
            } else { $modName }

            $statsObj = [PSCustomObject]@{
                Name             = $displayName
                Queries          = $modStats.Queries
                Results          = $modStats.Results
                EstimatedTraffic = Format-ByteSize $modStats.EstimatedBytes
            }
            $statsObj | Add-Member '_adPEASObjectType' 'LDAPStatisticsModule' -Force
            Show-Object $statsObj
        }

        # Total row
        $totalObj = [PSCustomObject]@{
            Name             = "Total"
            Queries          = $Script:LDAPStatistics.TotalQueries
            Results          = $Script:LDAPStatistics.TotalResults
            EstimatedTraffic = Format-ByteSize $Script:LDAPStatistics.TotalEstimatedBytes
        }
        $totalObj | Add-Member '_adPEASObjectType' 'LDAPStatisticsTotal' -Force
        Show-Object $totalObj
    }

    # 7. Summary
    $EndTime = Get-Date
    $Duration = $EndTime - $Script:StartTime

    Show-Header "Scan Summary"
    Show-Line "Duration: $([Math]::Round($Duration.TotalSeconds, 1)) seconds" -Class Hint

    if ($sessionAborted) {
        Show-Line "Scan was aborted due to invalid LDAP session. No reports were generated." -Class Finding
        Show-Line "Re-authenticate with Connect-adPEAS and try again." -Class Hint
    } else {
        # 7. Report file notifications (after summary)
        if ($Script:adPEAS_Outputfile) {
            Show-Line "Text report saved to: $Script:adPEAS_Outputfile" -Class Hint
        }
        if ($Script:HTMLOutputPath) {
            Show-Line "HTML report saved to: $Script:HTMLOutputPath" -Class Hint
        }
        if ($htmlPath) {
            $cachePath = [System.IO.Path]::ChangeExtension($htmlPath, '.json')
            if (Test-Path $cachePath) {
                Show-Line "JSON export saved to: $cachePath" -Class Hint
            }
        }
        if ($Script:JSONOutputPath -and (Test-Path $Script:JSONOutputPath)) {
            Show-Line "JSON export saved to: $Script:JSONOutputPath" -Class Hint
        }
    }

} catch {
    Show-Line "CRITICAL ERROR: $_" -Class Finding
    Write-Error $_.ScriptStackTrace
    return
}
finally {
    # Clean up findings collection (even on early returns, to prevent stale state)
    Clear-FindingsCollection

    # Session is always kept alive after Invoke-adPEAS completes.
    # This allows users to run Get-adPEASSession, Get-Domain* queries, or additional scans.
    # Use Disconnect-adPEAS to explicitly close the session when done.
    Write-Log "[adPEAS] Session kept alive - use Disconnect-adPEAS to close"
    Write-Log "[adPEAS] adPEAS v2 completed"
}
}
# ===== End of Invoke-adPEAS Function =====

# ===== Module Import Message =====
# Use Show-Logo for consistent banner display

Show-Logo -Version $Script:adPEASVersion

# Quick Start Guide (centralized in Get-adPEASHelp)
Get-adPEASHelp -Section QuickStart
