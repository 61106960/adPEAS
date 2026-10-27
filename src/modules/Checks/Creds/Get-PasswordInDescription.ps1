function Get-PasswordInDescription {
    <#
    .SYNOPSIS
    Detects directory objects with potential passwords in their free-text attributes.

    .DESCRIPTION
    Scans the free-text attributes of every object class - description, info, comment,
    adminDescription, wWWHomePage, url, scriptPath, homeDirectory, profilePath,
    extensionAttribute1-15 and msDS-cloudExtensionAttribute1-20 - for patterns that indicate
    credentials are stored in plaintext. Uses a two-tier detection system:

    Tier 1 (Finding): High-confidence patterns with explicit password assignments (e.g., "password=Secret123"),
    and credentials embedded in a URL (e.g., "https://svc:Secret123@host")
    Tier 2 (Hint): Lower-confidence patterns with generic credential mentions (e.g., "password" without value).
    Not applied to the link and path attributes: a link to a password reset page, or a share
    named after a team, mentions the word and holds nothing.

    Exclusion patterns filter out false positives from password policy text, help text, and placeholders.

    .PARAMETER Domain
    Target domain (optional, uses current domain if not specified)

    .PARAMETER Server
    Domain Controller to query (optional, uses auto-discovery if not specified)

    .PARAMETER Credential
    PSCredential object for authentication (optional, uses current user if not specified)

    .EXAMPLE
    Get-PasswordInDescription

    .EXAMPLE
    Get-PasswordInDescription -Domain "contoso.com" -Credential (Get-Credential)

    .NOTES
    Category: Creds
    Author: Alexander Sturz (@_61106960_)
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
        [switch]$OPSEC
    )

    begin {
        Write-Log "[Get-PasswordInDescription] Starting check"
    }

    process {
        try {
            # Build connection parameters (exclude OPSEC which Ensure-LDAPConnection doesn't accept)
            $connectionParams = @{}
            if ($Domain) { $connectionParams['Domain'] = $Domain }
            if ($Server) { $connectionParams['Server'] = $Server }
            if ($Credential) { $connectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @connectionParams)) {
                return
            }

            Show-SubHeader "Searching for credentials in description/info attributes..." -ObjectType "PasswordInDescription"

            # OPSEC mode: Skip heavy-load enumeration
            if ($OPSEC) {
                Show-Line "OPSEC mode: Skipping password-in-description check (would check all users and computers)" -Class "Hint"
                return
            }

            $findingCount = 0
            $hintCount = 0
            $unreadableCount = 0

            # Every object class, not only users and computers. description and info sit on
            # practically everything in the directory, and a password typed into a group's
            # description - "Zugang Fileserver, PW Sommer2024" - is the same credential as
            # one in a user's. Get-DomainUser prepends
            # (&(objectCategory=person)(objectClass=user)(!(objectClass=computer))), which is
            # what kept groups, organizational units, contacts, managed service accounts,
            # Group Policy objects and containers out of a check whose own secure line
            # claims the directory is clean. Get-UnixPasswordAccounts makes the same
            # argument in its own comment, one file over.
            #
            # And more than two attributes: the free-text fields a human types into, which is
            # where a password ends up. The lists live beside the credential triggers
            # (adPEAS-FindingDefinitions.ps1), which colour each of them.
            #
            # Three queries rather than one: description, info, comment, adminDescription,
            # wWWHomePage and url are in every schema, the other two sets are not.
            # extensionAttribute1-15 arrive with the Exchange schema extension, which most
            # but not all domains have; msDS-cloudExtensionAttribute1-20 with the Windows
            # Server 2012 schema. A filter that names an attribute the schema does not
            # define does not skip that one clause, the whole search fails with an
            # undefined-attribute error, so each optional set runs on its own and a failure
            # there costs that set alone.
            $baseAttributes     = $Script:CredentialTextBaseAttributes
            $exchangeAttributes = $Script:CredentialTextExchangeAttributes
            $cloudAttributes    = $Script:CredentialTextCloudAttributes

            # Merged by distinguishedName: an object can come back from several queries, and
            # reporting it twice would be two findings for one account.
            $candidates = @{}
            foreach ($set in @(
                @{ Attributes = $baseAttributes;     Optional = $false; Label = 'the base attributes' }
                @{ Attributes = $exchangeAttributes; Optional = $true;  Label = 'extensionAttribute1-15' }
                @{ Attributes = $cloudAttributes;    Optional = $true;  Label = 'msDS-cloudExtensionAttribute1-20' }
            )) {
                $presenceFilter = '(|' + ((@($set.Attributes) | ForEach-Object { "($_=*)" }) -join '') + ')'
                $wanted = @($set.Attributes) + @('objectCategory', 'sAMAccountName', 'name')

                $found = @()
                try {
                    $found = @(Get-DomainObject -LDAPFilter $presenceFilter -Properties $wanted @connectionParams)
                } catch {
                    if (-not $set.Optional) { throw }
                    Write-Log "[Get-PasswordInDescription] Optional attribute query failed, schema may not define $($set.Label): $_"
                }

                foreach ($obj in $found) {
                    $dn = [string]$obj.distinguishedName
                    if ([string]::IsNullOrWhiteSpace($dn)) { continue }
                    if (-not $candidates.ContainsKey($dn)) {
                        $candidates[$dn] = @{ Object = $obj; Attributes = @() }
                    }
                    foreach ($name in @($set.Attributes)) {
                        # Joined rather than cast: description is multi-valued in the schema,
                        # and a cast would render an array as System.Object[].
                        $value = (@($obj.$name) | Where-Object { $_ }) -join ' '
                        if (-not [string]::IsNullOrWhiteSpace($value)) {
                            $candidates[$dn].Attributes += @{ Name = $name; Value = $value }
                        }
                    }
                }
            }

            $currentIndex = 0
            $totalCandidates = $candidates.Count

            foreach ($dn in @($candidates.Keys)) {
                    $candidate = $candidates[$dn].Object
                    $currentIndex++

                    # Progress indicator for large candidate counts
                    if ($totalCandidates -gt 50) {
                        Show-Progress -Activity "Checking free-text attributes" `
                                     -Current $currentIndex `
                                     -Total $totalCandidates
                    }
                    $accountName = $dn
                    $attributesToCheck = @($candidates[$dn].Attributes)

                    # What kind of object this is, out of objectCategory - which names the
                    # most specific class, and names it the way the schema does: a user
                    # object's category is Person. The four that a reader would otherwise
                    # have to translate are translated; anything else keeps the schema's
                    # own word, which is better than a wrong guess.
                    $objectType = 'object'
                    if ($candidate.objectCategory) {
                        $schemaClass = ((([string]$candidate.objectCategory) -split ',')[0] -replace '^CN=', '')
                        $objectType = $schemaClass
                        $kindLabels = @{
                            'Person'                              = 'User'
                            'Organizational-Unit'                 = 'OU'
                            'Group-Policy-Container'              = 'GPO'
                            'ms-DS-Group-Managed-Service-Account' = 'gMSA'
                        }
                        if ($kindLabels.ContainsKey($schemaClass)) { $objectType = $kindLabels[$schemaClass] }
                    }

                    # The pattern logic is shared with Get-DeletedObjectAccess, which reads
                    # the same attributes on deleted objects (Get-CredentialTextMatch).
                    $credentialMatch = Get-CredentialTextMatch -Attributes $attributesToCheck -Label $accountName
                    $bestTier = $credentialMatch.Tier
                    $bestAttrName = $credentialMatch.Attribute

                    if ($bestTier -gt 0) {
                        # Phase 2: the full object, for the row itself. Get-DomainObject
                        # rather than the two typed wrappers, for the same reason as the
                        # query above - and it escapes the DN on the way in.
                        $fullObj = @(Get-DomainObject -Identity $accountName -ShowOwner @connectionParams)[0]

                        if ($fullObj) {
                            # Counted here rather than above. The counter used to be raised
                            # before this guard, and it is also what suppresses the clean
                            # line at the end - so a candidate that matched and could not be
                            # read again left a section with nothing in it at all: no row, no
                            # finding, and no statement that nothing was found either. In the
                            # HTML report that is an empty section, which reads as clean.
                            # An organizational unit has no sAMAccountName, and a Group
                            # Policy object's name is its GUID while displayName is the one
                            # a reader recognises.
                            $shownName = if ($fullObj.sAMAccountName) { $fullObj.sAMAccountName }
                                         elseif ($fullObj.displayName) { $fullObj.displayName }
                                         elseif ($fullObj.name) { $fullObj.name }
                                         else { $accountName }

                            $fullObj | Add-Member -NotePropertyName '_adPEASObjectType' -NotePropertyValue 'PasswordInDescription' -Force
                            $fullObj | Add-Member -NotePropertyName '_adPEASContext' -NotePropertyValue "$objectType - $bestAttrName attribute" -Force
                            if ($bestTier -eq 1) {
                                Show-Line "Probable credential found in $bestAttrName of $objectType '$shownName'" -Class Finding
                            } else {
                                Show-Line "Possible credential mention in $bestAttrName of $objectType '$shownName'" -Class Hint
                            }
                            Show-Object $fullObj -Class $(if ($bestTier -eq 1) { 'Finding' } else { 'Hint' })
                            if ($bestTier -eq 1) { $findingCount++ } else { $hintCount++ }
                        } else {
                            # Named, because the reader can go and look: the object matched
                            # on a value this check read a moment earlier and then could not
                            # be read back - deleted in between, or moved out of reach.
                            $unreadableCount++
                            Write-Log "[Get-PasswordInDescription] Candidate could not be re-read: $accountName"
                            Show-Line "Matched but could not be read again: $accountName" -Class Note
                        }
                    }
            }

            if ($totalCandidates -gt 50) {
                Show-Progress -Activity "Checking free-text attributes" -Completed
            }

            if ($findingCount -eq 0 -and $hintCount -eq 0) {
                if ($unreadableCount -gt 0) {
                    # Not green: a candidate matched and could not be read back, so the
                    # directory was not cleared - it was not fully looked at.
                    Show-Line "Nothing could be reported - every match could not be read again" -Class Note
                } else {
                    Show-Line "No credentials found in the free-text attributes of any object" -Class Secure
                }
            } else {
                Write-Log "[Get-PasswordInDescription] Total: $findingCount finding(s), $hintCount hint(s)"
            }

        } catch {
            Write-Log "[Get-PasswordInDescription] Error: $_" -Level Error
            Show-Line "Error during check - credentials in free-text attributes could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-PasswordInDescription] Check completed"
    }
}
