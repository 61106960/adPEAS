function Get-CredentialRoaming {
    <#
    .SYNOPSIS
    Reports users whose DPAPI master keys and private keys are stored in Active Directory,
    and whether anybody can read them.

    .DESCRIPTION
    Credential Roaming copies the public-key material of a Windows profile into attributes
    on the user object so that it follows the user to every machine they log on to. What
    roams is certificates, certificate requests, private keys and the user's DPAPI master
    keys - and a DPAPI master key is what protects everything else the user has stored
    under DPAPI: saved RDP credentials, browser secrets, WLAN keys, the Credential Manager.

    Three attributes carry it, all on the user class:

        msPKIAccountCredentials   certificates, requests and private keys
        msPKIDPAPIMasterKeys      the user's DPAPI master keys
        msPKIRoamingTimeStamp     when it last synchronised

    The contents are not plaintext. A master key blob is protected by a pre-key derived from
    the user's password AND by the domain backup key; the private keys are in turn protected
    by those master keys. So reading the attributes yields ciphertext, and the material only
    becomes usable with the user's password or hash, or with the domain backup key - which
    every domain administrator has.

    That is why this check reports three separate things rather than one:

      1. Which users have roamed material at all. On its own that is a hint: private keys
         and master keys are sitting in the directory where they need not be, and anybody
         who later obtains the backup key or the user's hash can use them. It is also the
         precondition for everything else - without material, the rest is academic.

      2. Whether the two sensitive attributes are marked confidential in the schema. This is
         the part that decides the blanket readability, and it is a single forest-wide
         answer.

      3. Who has been given an explicit read of the attributes by delegation. That is the
         case the flag does not cover, and the one most likely to have happened by
         accident: a delegation wizard pointed at the wrong attribute set hands a helpdesk
         group a right nobody intended it to have.

    The confidential flag is searchFlags bit 7, fCONFIDENTIAL, value 128. These attributes
    do not carry it by default and most forests have never set it. Without it, readability
    follows the ordinary read ACEs of the user object, and in a default domain that means
    every authenticated user can read the roamed material of every other user. With it, a
    reader additionally needs the Control Access right, which generic read does not grant.

    That flag is also what decides whether a delegated right is live. A confidential
    attribute needs READ_PROPERTY *and* CONTROL_ACCESS; without the flag, READ_PROPERTY
    alone is enough. So the same ACE is a finding in one forest and dormant in another, and
    step 3 reports which of the two it is rather than printing the ACE and leaving the
    reader to work it out.

    Step 3 is scoped to the containers that hold users with material, because that is where
    a read of it has any effect. A delegation on a container whose users have never roamed
    anything is not reported - there is nothing there to read - and it becomes visible as
    soon as the first user synchronises.

    Nor does any of this constrain somebody with DCSync, a copy of ntds.dit or an AD backup.
    They read the material regardless of the attribute ACL and regardless of the flag, so
    the hardening below protects against ordinary users and not against Tier 0.

    Deliberately NOT retrieved: the blob attributes themselves. Their presence is established
    with an LDAP presence filter, and only the name, the DN and the timestamp are read back.
    adPEAS has no use for the ciphertext, and writing base64-encoded DPAPI master keys into
    an HTML report somebody then mails around would create the exposure the check exists to
    report. The two attributes are also excluded from display centrally, so that another
    check fetching a full user object cannot surface them either.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .PARAMETER IncludePrivileged
    Also report privileged principals that hold a delegated read of the roaming attributes
    (shown as yellow/Hint severity). Privileged principals can read the material anyway, so
    they are hidden by default.

    .EXAMPLE
    Get-CredentialRoaming

    .EXAMPLE
    Get-CredentialRoaming -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Creds
    Author: Alexander Sturz (@_61106960_)
    Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/credential-roaming
    Reference: CVE-2022-30170 - client-side handling of roamed data, patched 09/2022
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory=$false)]
        [switch]$IncludePrivileged
    )

    begin {
        Write-Log "[Get-CredentialRoaming] Starting check"
    }

    process {
        try {
            # Connection parameters only, per CF-006. Never @PSBoundParameters: a parameter
            # this check owns would be splatted into callees that have none by that name,
            # and the binding failure is a terminating error before the first line of
            # output - a check that silently produces nothing.
            $CredParams = @{}
            if ($Domain)     { $CredParams['Domain']     = $Domain }
            if ($Server)     { $CredParams['Server']     = $Server }
            if ($Credential) { $CredParams['Credential'] = $Credential }

            if (-not (Ensure-LDAPConnection @CredParams)) {
                return
            }

            Show-SubHeader "Checking for roamed DPAPI master keys and private keys in AD..." -ObjectType "CredentialRoaming"

            # ----- Step 1: who has roamed material? -----
            #
            # Before the schema, not after. Whether the attributes are confidential only
            # matters once something is in them, and in a domain that never switched Credential
            # Roaming on - the common case, and the first one this met - reading the schema
            # partition first was a query for an answer nobody uses. The comment on
            # Get-CredentialRoamingConfidentiality already claimed the caller "only asks once
            # material has been found"; now it does.
            #
            # Two presence filters rather than one with the blobs requested. The filter
            # establishes presence server-side, so only the identity and the timestamp
            # travel - the private keys and master keys never leave the directory. Asking
            # for them would move megabytes and put ciphertext nobody needs into the
            # report.
            $lightProperties = @('sAMAccountName', 'distinguishedName', 'objectSid', 'msPKIRoamingTimeStamp')

            $byDN = @{}

            foreach ($pair in @(
                @{ Filter = '(msPKIDPAPIMasterKeys=*)';    Material = 'DPAPI master keys' }
                @{ Filter = '(msPKIAccountCredentials=*)'; Material = 'private keys and certificates' }
            )) {
                try {
                    foreach ($user in @(Get-DomainUser -LDAPFilter $pair.Filter -Properties $lightProperties @CredParams)) {
                        if (-not $user.distinguishedName) { continue }

                        $key = [string]$user.distinguishedName
                        if (-not $byDN.ContainsKey($key)) {
                            $byDN[$key] = [PSCustomObject]@{
                                User     = $user
                                Material = New-Object System.Collections.Generic.List[string]
                            }
                        }
                        $byDN[$key].Material.Add([string]$pair.Material)
                    }
                }
                catch {
                    # One attribute failing must not hide the other. A forest that never had
                    # Credential Roaming has no such attribute in the schema at all, and the
                    # query then errors rather than returning nothing.
                    Write-Log "[Get-CredentialRoaming] Query $($pair.Filter) failed: $($_.Exception.Message)"
                }
            }

            # Nothing after this point runs when there is no material, which is the point of
            # the ordering above: no schema read, and no container ACL sweep either.
            if ($byDN.Count -eq 0) {
                Show-Line "No user object carries roamed credential material" -Class Secure
                return
            }

            # ----- Step 2: is the material readable by everyone? -----
            #
            # One forest-wide answer, and now only asked when there is material to read.
            $confidential = Get-CredentialRoamingConfidentiality @CredParams

            # ----- Build the findings -----
            $findings = New-Object System.Collections.Generic.List[object]

            foreach ($key in @($byDN.Keys | Sort-Object)) {
                $entry = $byDN[$key]
                $user  = $entry.User

                # A roamed privileged account is a different proposition from a roamed
                # helpdesk account: the certificate it carries authenticates as that
                # account. Reported as its own row so a reader does not have to recognise
                # the names.
                # The whole object, not the SID. Test-IsPrivileged takes sAMAccountName and
                # distinguishedName from an object, and both are already on this one from the
                # query above; handed a bare SID it calls ConvertFrom-SID to get the name,
                # which is an LDAP round trip per user that has not been resolved before.
                # The DN is a smaller gain - the sIDHistory check fetches it anyway - but
                # passing the object costs nothing either way.
                $privileged = $false
                try {
                    if ($user.objectSid) {
                        $privileged = ((Test-IsPrivileged -Identity $user).IsPrivileged -eq $true)
                    }
                } catch {
                    Write-Log "[Get-CredentialRoaming] Privilege check failed for '$($user.sAMAccountName)': $_"
                }

                $finding = [PSCustomObject]@{
                    sAMAccountName    = [string]$user.sAMAccountName
                    distinguishedName = [string]$user.distinguishedName
                    RoamedMaterial    = (@($entry.Material) -join ', ')
                    RoamingTimeStamp  = $(if ($user.msPKIRoamingTimeStamp) { [string]$user.msPKIRoamingTimeStamp } else { 'Unknown' })
                    PrivilegedAccount = $(if ($privileged) { 'Yes' } else { 'No' })
                    ReadableBy        = $confidential.ReadableBy
                }
                $finding | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'CredentialRoaming' -Force
                $findings.Add($finding)
            }

            # ----- Output -----
            #
            # Material present is a hint on its own: the ciphertext needs a password, a hash
            # or the domain backup key before it is worth anything. Readable material is a
            # finding, because the one thing an attacker cannot usually get - the private
            # key of another user - is then one offline step away.
            $privilegedCount = @($findings | Where-Object { $_.PrivilegedAccount -eq 'Yes' }).Count
            $countText = if ($privilegedCount -gt 0) {
                "$($findings.Count) user(s) carry roamed credential material in Active Directory, $privilegedCount of them privileged"
            } else {
                "$($findings.Count) user(s) carry roamed credential material in Active Directory"
            }

            if ($confidential.Confidential -eq $false) {
                Show-Line "Found $countText" -Class Finding -FindingId 'CREDENTIAL_ROAMING_READABLE'
                Show-Line ("The attributes are not marked confidential in the schema, so reading them follows the " +
                           "ordinary read permissions of the user object - in a default domain every authenticated " +
                           "user can read them") -Class Finding -FindingId 'CREDENTIAL_ROAMING_READABLE'
            } else {
                Show-Line "Found $countText" -Class Hint -FindingId 'CREDENTIAL_ROAMING_PRESENT'

                if ($confidential.Confidential -eq $true) {
                    Show-Line ("Both attributes are marked confidential in the schema, so reading them needs the " +
                               "Control Access right and generic read does not grant it") -Class Secure
                } else {
                    Show-Line ("Whether the attributes are readable could not be established - the schema could not " +
                               "be read, so treat them as readable until checked by hand") -Class Note
                }
            }

            # Privileged first: a roamed administrator certificate is the row that matters.
            foreach ($finding in @($findings | Sort-Object -Property @{Expression = { $_.PrivilegedAccount -ne 'Yes' }}, sAMAccountName)) {
                Show-Object $finding -Class $(if ($confidential.Confidential -eq $false) { 'Finding' } else { 'Hint' })
            }

            # ----- Step 3: who has been given an explicit read of the material? -----
            Show-CredentialRoamingDelegation -AffectedUserDNs @($byDN.Keys) `
                -Confidentiality $confidential -IncludePrivileged:$IncludePrivileged `
                -ConnectionParams $CredParams

            Show-Line ("Reading these attributes is not constrained for anybody with DCSync, a copy of ntds.dit or " +
                       "an AD backup - the confidential flag protects against ordinary users, not against Tier 0") -Class Note
        }
        catch {
            Write-Log "[Get-CredentialRoaming] Error: $_" -Level Error
            Show-Line "Error during check: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-CredentialRoaming] Check completed"
    }
}

<#
.SYNOPSIS
    Reports principals that hold a delegated read of the Credential Roaming attributes.

.DESCRIPTION
    Step 3 of Get-CredentialRoaming. The confidential flag read in step 2 answers the
    blanket question - can every authenticated user read the material - and this answers the
    narrower one the flag says nothing about: has somebody been given the right explicitly.

    That is the case worth catching, because it is the one that happens by accident. A
    delegation wizard pointed at the wrong attribute set, or a script copied from a
    Credential Roaming rollout guide, hands a helpdesk group a read of another user's
    private keys, and nothing about the result looks unusual afterwards.

    Scoped to the containers that hold users with roamed material. Those are read once each
    rather than once per user: the DACL of a container already carries everything it
    inherits from above, so one read answers for every user below it, and an OU delegation
    is what this is looking for in the first place. The consequence is the one documented
    limitation - an ACE set directly on a single user object, bypassing the container, is
    not seen.

    Whether a delegated right is live depends on the schema, which is why the verdict needs
    step 2's answer:

      not confidential  the delegated READ_PROPERTY works today                   Finding
      confidential      READ_PROPERTY alone is blocked; CONTROL_ACCESS is needed
                          with CONTROL_ACCESS   works today                       Finding
                          without               dormant until the flag is cleared  Hint
      unknown           cannot be decided                                         Hint

    The dormant case is reported rather than dropped because the delegation is still there:
    the day somebody clears the flag, every one of those rights becomes live at once.

    Privileged principals are hidden unless -IncludePrivileged. They can read the material
    anyway, through the domain backup key if not through the attribute, so reporting them by
    default would bury the one row that matters under the rows that do not.

.PARAMETER AffectedUserDNs
    DNs of the users found to carry roamed material. Their parent containers are what gets
    analysed.

.PARAMETER Confidentiality
    The result of Get-CredentialRoamingConfidentiality. Its three-valued Confidential field
    decides whether a delegated right is live, dormant or undecidable.

.PARAMETER IncludePrivileged
    Also report privileged principals, as Hint rather than Finding.

.PARAMETER ConnectionParams
    Domain/Server/Credential hashtable, passed through unchanged.
#>
function Show-CredentialRoamingDelegation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [string[]]$AffectedUserDNs,

        [Parameter(Mandatory=$true)]
        $Confidentiality,

        [Parameter(Mandatory=$false)]
        [switch]$IncludePrivileged,

        [Parameter(Mandatory=$false)]
        [hashtable]$ConnectionParams = @{}
    )

    # Parent container per affected user, with a count, so the row can say how much material
    # a delegation actually reaches. The DN pattern strips exactly one RDN; a user DN whose
    # RDN contains an escaped comma (CN=Doe\, Jane) still has its comma escaped at this
    # point, so [^,] must not stop at it.
    $usersByContainer = @{}
    foreach ($userDN in $AffectedUserDNs) {
        if ([string]::IsNullOrWhiteSpace($userDN)) { continue }
        if ($userDN -match '^[A-Za-z][A-Za-z0-9-]*=(?:[^,\\]|\\.)+,(.+)$') {
            $containerDN = $Matches[1]
            if (-not $usersByContainer.ContainsKey($containerDN)) { $usersByContainer[$containerDN] = 0 }
            $usersByContainer[$containerDN]++
        }
    }

    if ($usersByContainer.Count -eq 0) {
        Write-Log "[Get-CredentialRoaming] No container could be derived from the affected users"
        return
    }

    # Low is left out on purpose: it is the roaming timestamp alone, which is a date and not
    # a credential. Info is what Get-OUPermissions assigns a privileged principal.
    $allowedSeverities = if ($IncludePrivileged) { @('Critical', 'High', 'Medium', 'Info') } else { @('Critical', 'High', 'Medium') }

    # Aggregated per principal, not per ACE. A principal can hold the right on several
    # containers and on several attributes, and the two halves of the confidential-attribute
    # requirement can sit in two separate ACEs - ORing GrantsControlAccess across them is
    # the only way to judge that combination correctly.
    $byPrincipal = @{}

    # Counted rather than assumed. The closing note used to be printed whenever anything was
    # found, which reads as a claim that privileged holders exist and sends somebody looking
    # for rows that are not there.
    $suppressedPrivileged = @{}

    $totalContainers = $usersByContainer.Keys.Count
    $currentIndex = 0
    foreach ($containerDN in @($usersByContainer.Keys)) {
        $currentIndex++
        if ($totalContainers -gt $Script:ProgressThreshold) {
            Show-Progress -Activity "Checking Credential Roaming delegations" -Current $currentIndex -Total $totalContainers -ObjectName $containerDN
        }

        try {
            $perms = Get-OUPermissions -DistinguishedName $containerDN -CheckType 'CredentialRoaming'
        }
        catch {
            Write-Log "[Get-CredentialRoaming] Failed to read permissions for '$containerDN': $($_.Exception.Message)"
            continue
        }

        if (-not $perms -or -not $perms.Findings) { continue }

        foreach ($aclFinding in @($perms.Findings)) {
            $sid = [string]$aclFinding.SID
            if ([string]::IsNullOrEmpty($sid)) { continue }

            if ($aclFinding.Severity -notin $allowedSeverities) {
                if ($aclFinding.Severity -eq 'Info') { $suppressedPrivileged[$sid] = $true }
                continue
            }

            if (-not $byPrincipal.ContainsKey($sid)) {
                $byPrincipal[$sid] = [PSCustomObject]@{
                    Principal           = $aclFinding.Principal
                    SID                 = $sid
                    Rights              = New-Object System.Collections.Generic.List[string]
                    Containers          = New-Object System.Collections.Generic.List[string]
                    GrantsControlAccess = $false
                    IsPrivileged        = ($aclFinding.Severity -eq 'Info')
                }
            }

            $entry = $byPrincipal[$sid]
            if (-not $entry.Rights.Contains([string]$aclFinding.Right)) {
                $entry.Rights.Add([string]$aclFinding.Right)
            }

            $containerEntry = "$containerDN ($($usersByContainer[$containerDN]) user(s) with material)"
            if (-not $entry.Containers.Contains($containerEntry)) {
                $entry.Containers.Add($containerEntry)
            }

            if ($aclFinding.GrantsControlAccess -eq $true) { $entry.GrantsControlAccess = $true }
        }
    }
    if ($totalContainers -gt $Script:ProgressThreshold) {
        Show-Progress -Activity "Checking Credential Roaming delegations" -Completed
    }

    if ($byPrincipal.Count -eq 0) {
        # "Nobody" and "nobody except the principals we filtered out" are different
        # statements. Printing the first when the second is true would call a forest clean on
        # the strength of a filter this function applied itself.
        if ($suppressedPrivileged.Count -gt 0) {
            Show-Line ("No non-privileged principal holds a delegated read of the roaming attributes, but " +
                       "$($suppressedPrivileged.Count) privileged one(s) do - use -IncludePrivileged to see them") -Class Note
        } else {
            Show-Line ("No principal holds a delegated read of the roaming attributes on the $totalContainers " +
                       "container(s) holding this material") -Class Secure
        }
        return
    }

    # Live rights first, then dormant ones, then the privileged rows. Sorting on the verdict
    # rather than on the name keeps the rows that need acting on at the top.
    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($sid in @($byPrincipal.Keys | Sort-Object)) {
        $entry = $byPrincipal[$sid]

        # CONTROL_ACCESS is tested first and on its own, because it satisfies the stricter of
        # the two schema states. A principal holding it reads the attribute whether the flag
        # is set or not, so the schema answer does not enter into it - including when that
        # answer is unknown, where asking the flag first would have downgraded a live right
        # to "cannot tell".
        #
        # Only read-without-control depends on the flag, and there the test is -eq $false
        # rather than -not: $null is falsy in PowerShell, and unknown must not read as
        # "not confidential".
        $isLive = $null
        if ($entry.GrantsControlAccess) {
            $isLive = $true
        } elseif ($Confidentiality.Confidential -eq $false) {
            $isLive = $true
        } elseif ($Confidentiality.Confidential -eq $true) {
            $isLive = $false
        }

        $effectiveText = if ($isLive -eq $true) {
            'Yes - the principal can read the material today'
        } elseif ($isLive -eq $false) {
            'No - blocked by the confidential flag, live the moment it is cleared'
        } else {
            'Unknown - the schema could not be read'
        }

        # A privileged principal reads the material anyway, so the right is expected rather
        # than wrong. A dormant right is a warning, not a finding. Everything else is live.
        $isFinding = (-not $entry.IsPrivileged) -and ($isLive -eq $true)

        $row = [PSCustomObject]@{
            sAMAccountName          = $(if ($entry.Principal) { $entry.Principal } else { ConvertFrom-SID -SID $sid })
            objectSid               = $sid
            dangerousRights         = (@($entry.Rights) -join ', ')
            EffectiveToday          = $effectiveText
            PrivilegedAccount       = $(if ($entry.IsPrivileged) { 'Yes' } else { 'No' })
            affectedOUs             = @($entry.Containers)
        }
        if (-not $isFinding) {
            $row | Add-Member -NotePropertyName 'dangerousRightsSeverity' -NotePropertyValue 'Hint' -Force
        }
        $row | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'CredentialRoamingPermission' -Force
        $row | Add-Member -NotePropertyName '_IsFinding' -NotePropertyValue $isFinding -Force

        $rows.Add($row)
    }

    $findingRows = @($rows | Where-Object { $_._IsFinding })
    $hintRows    = @($rows | Where-Object { -not $_._IsFinding })

    if (@($findingRows).Count -gt 0) {
        Show-Line ("Found $(@($findingRows).Count) non-privileged principal(s) with a delegated read of the " +
                   "roaming attributes") -Class Finding -FindingId 'CREDENTIAL_ROAMING_DELEGATED'
        foreach ($row in $findingRows) { Show-Object $row -Class Finding }
    }

    if (@($hintRows).Count -gt 0) {
        Show-Line ("Found $(@($hintRows).Count) further delegated read(s) of the roaming attributes that do not " +
                   "grant access today or belong to a privileged principal") -Class Hint -FindingId 'CREDENTIAL_ROAMING_DELEGATED'
        foreach ($row in $hintRows) { Show-Object $row -Class Hint }
    }

    if ($suppressedPrivileged.Count -gt 0) {
        Show-Line ("$($suppressedPrivileged.Count) privileged principal(s) hold the same right and are not " +
                   "listed - they can read the material regardless. Use -IncludePrivileged to see them") -Class Note
    }
}

<#
.SYNOPSIS
    Reads whether the two sensitive Credential Roaming attributes are marked confidential.

.DESCRIPTION
    searchFlags bit 7 - fCONFIDENTIAL, value 128 - on the attributeSchema objects for
    msPKIAccountCredentials and msPKIDPAPIMasterKeys. Set, a reader needs the Control Access
    right and generic read does not suffice. Not set, readability follows the ordinary read
    ACEs of the user object, which in a default domain means every authenticated user.

    These attributes ship without the flag and most forests have never set it, so the
    interesting answer is the common one.

    Both attributes are judged together and the weaker of the two decides. Marking one and
    not the other protects nothing: the private keys in msPKIAccountCredentials are useless
    without the master keys, but the master keys unlock everything else the user stored
    under DPAPI, so either one left readable is worth reporting.

    Three-valued on purpose. $null means the schema could not be read, and the caller must
    not report that as either safe or exposed - the same discipline as the Resolved flag on
    Get-CertificateTrustAnchor. A forest that never deployed Credential Roaming has no such
    attribute in the schema; that is reported as unknown too, and the caller only asks once
    material has been found, so the question does not arise there.

.PARAMETER Domain
    Passed through to Get-DomainObject.

.PARAMETER Server
    Passed through to Get-DomainObject.

.PARAMETER Credential
    Passed through to Get-DomainObject.

.OUTPUTS
    [PSCustomObject] with
      Confidential - $true, $false, or $null when the schema could not be read
      ReadableBy   - the sentence that goes on the finding row
#>
function Get-CredentialRoamingConfidentiality {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $CredParams = @{}
    if ($Domain)     { $CredParams['Domain']     = $Domain }
    if ($Server)     { $CredParams['Server']     = $Server }
    if ($Credential) { $CredParams['Credential'] = $Credential }

    $unknown = [PSCustomObject]@{
        Confidential = $null
        ReadableBy   = 'Unknown - the schema could not be read'
    }

    $schemaDN = $null
    if ($Script:LDAPContext) { $schemaDN = $Script:LDAPContext.SchemaNamingContext }
    if ([string]::IsNullOrWhiteSpace($schemaDN)) {
        Write-Log "[Get-CredentialRoamingConfidentiality] No SchemaNamingContext - answer stays unknown"
        return $unknown
    }

    # cn as well as lDAPDisplayName: the two differ for these attributes - the schema object
    # is called ms-PKI-DPAPIMasterKeys while the attribute is msPKIDPAPIMasterKeys - and
    # matching on only one of them finds nothing in a forest that reports the other.
    $filter = '(&(objectClass=attributeSchema)' +
              '(|(lDAPDisplayName=msPKIAccountCredentials)(cn=ms-PKI-AccountCredentials)' +
              '(lDAPDisplayName=msPKIDPAPIMasterKeys)(cn=ms-PKI-DPAPIMasterKeys)))'

    try {
        $attributes = @(Get-DomainObject -LDAPFilter $filter -SearchBase $schemaDN `
            -Properties 'lDAPDisplayName', 'cn', 'searchFlags' @CredParams)
    }
    catch {
        Write-Log "[Get-CredentialRoamingConfidentiality] Schema query failed: $($_.Exception.Message)"
        return $unknown
    }

    if (@($attributes).Count -eq 0) {
        Write-Log "[Get-CredentialRoamingConfidentiality] Neither attribute found in the schema"
        return $unknown
    }

    # The weaker of the two decides, and an attribute whose searchFlags could not be read
    # counts as not confidential: assuming the stricter state would report an exposed forest
    # as protected, which is the wrong direction to guess in.
    $allConfidential = $true
    foreach ($attribute in $attributes) {
        $flags = 0
        if ($null -ne $attribute.searchFlags) { $flags = [int]$attribute.searchFlags }
        if (($flags -band 128) -eq 0) { $allConfidential = $false }
    }

    if ($allConfidential) {
        return [PSCustomObject]@{
            Confidential = $true
            ReadableBy   = 'Control Access holders only (attributes are confidential)'
        }
    }

    return [PSCustomObject]@{
        Confidential = $false
        ReadableBy   = 'Any authenticated user (attributes are not confidential)'
    }
}
