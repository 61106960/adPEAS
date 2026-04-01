<#
.SYNOPSIS
    Creates a new "runas /netonly" type logon and impersonates the token.

.DESCRIPTION
    This function uses LogonUser() with the LOGON32_LOGON_NEW_CREDENTIALS LogonType
    to simulate "runas /netonly". The resulting token is then impersonated with
    ImpersonateLoggedOnUser() and the token handle is returned for later usage
    with Invoke-RevertToSelf.

    IMPORTANT: This uses NTLM authentication, NOT Kerberos!
    - Does NOT modify the Kerberos ticket cache
    - Original Kerberos tickets remain intact
    - Network operations use NTLM Challenge/Response
    - Supports LDAP Signing (unlike SimpleBind)

.PARAMETER Credential
    A [Management.Automation.PSCredential] object with alternate credentials
    to impersonate in the current thread space.

.PARAMETER TokenHandle
    An IntPtr TokenHandle returned by a previous Invoke-NTLMImpersonation.
    If this is supplied, LogonUser() is skipped and only ImpersonateLoggedOnUser()
    is executed.

.PARAMETER Quiet
    Suppress any warnings about STA vs MTA.

.EXAMPLE
    $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('CONTOSO\admin', $SecPassword)
    $Token = Invoke-NTLMImpersonation -Credential $Cred

    # ... do network operations ...

    Invoke-RevertToSelf -TokenHandle $Token

.OUTPUTS
    IntPtr - The TokenHandle result from LogonUser.

.NOTES
    Based on PowerView's Invoke-UserImpersonation by Will Schroeder (@harmj0y)
    Adapted for adPEAS v2 with standalone P/Invoke (no PSReflect dependency)
#>
function Invoke-NTLMImpersonation {
    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $true, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle,

        [Switch]
        $Quiet
    )

    begin {
        # Define P/Invoke signatures if not already defined
        if (-not ([System.Management.Automation.PSTypeName]'adPEAS.NativeMethods.Impersonation').Type) {
            $ImpersonationCode = @'
using System;
using System.Runtime.InteropServices;

namespace adPEAS.NativeMethods
{
    public class Impersonation
    {
        // LogonUser constants
        public const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
        public const int LOGON32_PROVIDER_WINNT50 = 3;

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
'@
            try {
                Add-Type -TypeDefinition $ImpersonationCode -Language CSharp -ErrorAction Stop
                Write-Log "[Invoke-NTLMImpersonation] P/Invoke types compiled successfully"
            }
            catch {
                # Type might already exist from previous load
                if ($_.Exception.Message -notmatch 'already exists') {
                    throw "[Invoke-NTLMImpersonation] Failed to compile P/Invoke types: $_"
                }
            }
        }
    }

    process {
        # Check apartment state - token impersonation works best in STA
        if (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') -and (-not $Quiet)) {
            Write-Warning "[Invoke-NTLMImpersonation] PowerShell is not in single-threaded apartment state, token impersonation may not work correctly."
        }

        $LogonTokenHandle = [IntPtr]::Zero

        if ($PSCmdlet.ParameterSetName -eq 'TokenHandle') {
            # Re-use existing token
            $LogonTokenHandle = $TokenHandle
            Write-Log "[Invoke-NTLMImpersonation] Re-using existing token handle"
        }
        else {
            # Get network credentials
            $NetworkCredential = $Credential.GetNetworkCredential()
            $UserDomain = $NetworkCredential.Domain
            $UserName = $NetworkCredential.UserName

            # If domain is empty, try to extract from username
            if ([string]::IsNullOrEmpty($UserDomain)) {
                if ($Credential.UserName -match '^([^\\]+)\\(.+)$') {
                    $UserDomain = $Matches[1]
                    $UserName = $Matches[2]
                }
                elseif ($Credential.UserName -match '^(.+)@(.+)$') {
                    $UserName = $Matches[1]
                    $UserDomain = $Matches[2]
                }
            }

            Write-Log "[Invoke-NTLMImpersonation] Executing LogonUser() with user: $UserDomain\$UserName"

            # LOGON32_LOGON_NEW_CREDENTIALS = 9: Creates a token for outbound network connections only
            # LOGON32_PROVIDER_WINNT50 = 3: Use the NTLM provider
            $Result = [adPEAS.NativeMethods.Impersonation]::LogonUser(
                $UserName,
                $UserDomain,
                $NetworkCredential.Password,
                [adPEAS.NativeMethods.Impersonation]::LOGON32_LOGON_NEW_CREDENTIALS,
                [adPEAS.NativeMethods.Impersonation]::LOGON32_PROVIDER_WINNT50,
                [ref]$LogonTokenHandle
            )

            if (-not $Result) {
                $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                $ErrorMessage = (New-Object System.ComponentModel.Win32Exception($LastError)).Message
                throw "[Invoke-NTLMImpersonation] LogonUser() failed: $ErrorMessage (Error: $LastError)"
            }

            Write-Log "[Invoke-NTLMImpersonation] LogonUser() successful, token handle: $LogonTokenHandle"
        }

        # Impersonate the token
        $Result = [adPEAS.NativeMethods.Impersonation]::ImpersonateLoggedOnUser($LogonTokenHandle)

        if (-not $Result) {
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $ErrorMessage = (New-Object System.ComponentModel.Win32Exception($LastError)).Message

            # Clean up token handle on failure
            if ($LogonTokenHandle -ne [IntPtr]::Zero) {
                $null = [adPEAS.NativeMethods.Impersonation]::CloseHandle($LogonTokenHandle)
            }

            throw "[Invoke-NTLMImpersonation] ImpersonateLoggedOnUser() failed: $ErrorMessage (Error: $LastError)"
        }

        Write-Log "[Invoke-NTLMImpersonation] Token impersonation successful"

        # Return the token handle for later cleanup
        return $LogonTokenHandle
    }
}


<#
.SYNOPSIS
    Reverts any token impersonation and optionally closes the token handle.

.DESCRIPTION
    This function uses RevertToSelf() to revert any impersonated tokens.
    If -TokenHandle is passed (the token handle returned by Invoke-NTLMImpersonation),
    CloseHandle() is used to close the opened handle.

.PARAMETER TokenHandle
    An optional IntPtr TokenHandle returned by Invoke-NTLMImpersonation.
    If provided, the handle will be closed after reverting.

.EXAMPLE
    $Token = Invoke-NTLMImpersonation -Credential $Cred
    # ... do network operations ...
    Invoke-RevertToSelf -TokenHandle $Token

.NOTES
    Based on PowerView's Invoke-RevertToSelf by Will Schroeder (@harmj0y)
    Adapted for adPEAS v2 with standalone P/Invoke
#>
function Invoke-RevertToSelf {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [IntPtr]
        $TokenHandle = [IntPtr]::Zero
    )

    process {
        # Close the token handle if provided
        if ($TokenHandle -ne [IntPtr]::Zero) {
            Write-Log "[Invoke-RevertToSelf] Closing token handle: $TokenHandle"
            $Result = [adPEAS.NativeMethods.Impersonation]::CloseHandle($TokenHandle)
            if (-not $Result) {
                $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "[Invoke-RevertToSelf] CloseHandle() failed: Error $LastError"
            }
        }

        # Revert to self
        $Result = [adPEAS.NativeMethods.Impersonation]::RevertToSelf()

        if (-not $Result) {
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $ErrorMessage = (New-Object System.ComponentModel.Win32Exception($LastError)).Message
            throw "[Invoke-RevertToSelf] RevertToSelf() failed: $ErrorMessage (Error: $LastError)"
        }

        Write-Log "[Invoke-RevertToSelf] Token impersonation successfully reverted"
    }
}
