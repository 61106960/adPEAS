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

    That is why this check reports two separate things rather than one:

      1. Which users have roamed material at all. On its own that is a hint: private keys
         and master keys are sitting in the directory where they need not be, and anybody
         who later obtains the backup key or the user's hash can use them. It is also the
         precondition for everything else - without material, the rest is academic.

      2. Whether the two sensitive attributes are marked confidential in the schema. This is
         the part that decides who can read them, and it is a single forest-wide answer.

    The confidential flag is searchFlags bit 7, fCONFIDENTIAL, value 128. These attributes
    do not carry it by default and most forests have never set it. Without it, readability
    follows the ordinary read ACEs of the user object, and in a default domain that means
    every authenticated user can read the roamed material of every other user. With it, a
    reader additionally needs the Control Access right, which generic read does not grant.

    What this check does NOT do, and what the next step adds: it does not enumerate who
    holds an explicit read ACE on these attributes. The confidential flag answers the
    common case - the blanket readability that comes from the default ACL - but a right
    delegated to a single group by accident is invisible here.

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
        [System.Management.Automation.PSCredential]$Credential
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

            # ----- Step 1: is the material readable by everyone? -----
            $confidential = Get-CredentialRoamingConfidentiality @CredParams

            # ----- Step 2: who has roamed material? -----
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

            if ($byDN.Count -eq 0) {
                Show-Line "No user object carries roamed credential material" -Class Secure
                return
            }

            # ----- Build the findings -----
            $findings = New-Object System.Collections.Generic.List[object]

            foreach ($key in @($byDN.Keys | Sort-Object)) {
                $entry = $byDN[$key]
                $user  = $entry.User

                # A roamed privileged account is a different proposition from a roamed
                # helpdesk account: the certificate it carries authenticates as that
                # account. Reported as its own row so a reader does not have to recognise
                # the names.
                $privileged = $false
                try {
                    if ($user.objectSid) {
                        $privileged = ((Test-IsPrivileged -Identity $user.objectSid).IsPrivileged -eq $true)
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
