function Test-EKUPresent {
    <#
    .SYNOPSIS
    Tests whether an extended key usage list names a specific OID.

    .DESCRIPTION
    The EKUs of a template arrive as a list that may carry friendly names beside the
    numbers - "Client Authentication (1.3.6.1.5.5.7.3.2)" - so the match has to be on the
    OID inside the text rather than on an equal string.

    What it must not do is match a longer OID that merely starts with the one asked about.
    1.3.6.1.5.5.7.3.2 is Client Authentication; 1.3.6.1.5.5.7.3.21 and .22 are the
    registered SSH client and server usages, and a plain substring test reads both of them
    as Client Authentication. Every enrollment-driven ESC in this check keys off that flag
    - ESC1, ESC2, ESC3-TARGET and ESC9 - so a template that can only be used for SSH was
    enough to raise one.

    The guard is a digit-or-dot boundary on both sides, which leaves the parenthesised form
    matching because '(' and ')' are neither.

    .PARAMETER Eku
    The extended key usages and application policies of the template, in any shape a join
    produces.

    .PARAMETER Oid
    The OID to look for, in dotted form.

    .OUTPUTS
    Boolean.

    .EXAMPLE
    Test-EKUPresent -Eku @('Client Authentication (1.3.6.1.5.5.7.3.2)') -Oid '1.3.6.1.5.5.7.3.2'
    True

    .EXAMPLE
    Test-EKUPresent -Eku @('1.3.6.1.5.5.7.3.21') -Oid '1.3.6.1.5.5.7.3.2'
    False
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$false, Position=0)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object]$Eku,

        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$Oid
    )

    $text = (@($Eku) | Where-Object { $_ }) -join ' '
    if ([string]::IsNullOrWhiteSpace($text)) { return $false }

    $pattern = '(?<![\d.])' + [regex]::Escape($Oid) + '(?![\d.])'
    return [bool]($text -match $pattern)
}

function Get-ADCSTemplate {
    <#
    .SYNOPSIS
    Retrieves AD CS certificate templates with security-relevant analysis for vulnerability detection.

    .DESCRIPTION
    Wrapper around Get-CertificateTemplate (Core module) that adds security-focused computed properties for ESC vulnerability detection:
    - EnrolleeSuppliesSubject (ESC1)
    - ClientAuthentication (ESC1)
    - AnyPurpose (ESC2)
    - EnrollmentAgent (ESC3 condition 1)
    - EnrollmentAgentSignatureRequired (ESC3 condition 2)
    - NoSecurityExtension (ESC9)
    - ManagerApprovalRequired
    - ExportableKey
    - EnrollmentPrincipals

    .PARAMETER Identity
    Specific certificate template name (cn) to query. If not specified, returns all templates.

    .PARAMETER ShowAll
    Include disabled (unpublished) templates. By default only enabled templates are returned.

    .PARAMETER Domain
    Target domain (FQDN). If not specified, uses current domain from session.

    .PARAMETER Server
    Specific Domain Controller to query. If not specified, uses session server.

    .PARAMETER Credential
    PSCredential object for authentication. If not specified, uses session credentials.

    .EXAMPLE
    Get-ADCSTemplate
    Returns all enabled certificate templates with security analysis.

    .EXAMPLE
    Get-ADCSTemplate -ShowAll
    Returns all templates (enabled and disabled).

    .NOTES
    Category: ADCS
    Author: Alexander Sturz (@_61106960_)
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Identity,

        [Parameter(Mandatory=$false)]
        [switch]$ShowAll,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [string]$Server,

        [Parameter(Mandatory=$false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        Write-Log "[Get-ADCSTemplate] Starting certificate template enumeration via Get-CertificateTemplate"
    }

    process {
        try {
            # Build connection parameters (only pass Domain/Server/Credential to Ensure-LDAPConnection)
            $ConnectionParams = @{}
            if ($Domain) { $ConnectionParams['Domain'] = $Domain }
            if ($Server) { $ConnectionParams['Server'] = $Server }
            if ($Credential) { $ConnectionParams['Credential'] = $Credential }

            # Ensure LDAP connection (displays error if needed)
            if (-not (Ensure-LDAPConnection @ConnectionParams)) {
                # Return without output to avoid redundant error display
                return
            }

        # Get templates from Core module (with converted values)
        # Use @PSBoundParameters to pass all parameters directly (simple module, no inner functions)
        # Core module handles all LDAP attribute conversion (pKIExpirationPeriod, flags, etc.)
        $templateResults = @(Get-CertificateTemplate @PSBoundParameters)

        # Check if query failed (auth error, network issue, etc.)
        $queryError = $templateResults | Where-Object { $_._QueryError -eq $true }
        if ($queryError) {
            Write-Log "[Get-ADCSTemplate] Get-CertificateTemplate returned error: $($queryError.ErrorMessage)"
            # Pass through the error marker so caller can handle it
            return $queryError
        }

        # Filter out any error markers (should be none at this point)
        # Drop nulls before anything else. Get-CertificateTemplate returns $null when the
        # domain has no AD CS at all, and @($null) is a ONE-element array holding $null,
        # which the _QueryError filter happily keeps. The empty guard below then never
        # fired and an all-null placeholder was analysed as a real template - with no EKU
        # it reads as Any Purpose and Client Authentication, so a domain without AD CS
        # produced a phantom vulnerable template.
        $templates = @($templateResults | Where-Object { $null -ne $_ -and $_._QueryError -ne $true })

        if (@($templates).Count -eq 0) {
            Write-Log "[Get-ADCSTemplate] No templates returned from Get-CertificateTemplate"
            return
        }

        Write-Log "[Get-ADCSTemplate] Processing $($templates.Count) template(s) for security analysis"

        $totalTemplates = @($templates).Count
        $currentIndex = 0
        foreach ($coreTemplate in $templates) {
            $currentIndex++
            if ($totalTemplates -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing certificate templates" -Current $currentIndex -Total $totalTemplates -ObjectName $coreTemplate.displayName }
            # Build enhanced template object with security-relevant properties
            # Core module already converted all values - we just restructure and add computed properties
            $template = [PSCustomObject]@{
                # Basic identification (from Core)
                Name = $coreTemplate.cn
                DisplayName = $coreTemplate.displayName
                DistinguishedName = $coreTemplate.distinguishedName

                # CA publishing info: which CAs have this template enabled (from Core)
                PublishedOn = if ($coreTemplate.PublishedOn) { @($coreTemplate.PublishedOn) } else { @() }

                # And whether that list means anything: Get-CertificateTemplate falls back
                # to every template when the CA query fails, which drops the publication
                # gate without a word. Carried through here because the analysis reads its
                # templates from this function, not from Core.
                PublicationUnknown = [bool]$coreTemplate.PublicationUnknown

                # Schema Version (from Core).
                #
                # $null when the attribute did not arrive, not 1. A template whose version
                # could not be read was taken for version 1, which is the worse of the two
                # readings: ESC15 exists only for v1, and the ESC2 Any-Purpose gate is
                # stricter there. The result was an ESC15 hint produced by a missing
                # attribute - the second place in this module where absent data was read as
                # the worst case.
                SchemaVersion = if ($null -ne $coreTemplate.'msPKI-Template-Schema-Version' -and
                                    ([string]$coreTemplate.'msPKI-Template-Schema-Version') -ne '') {
                    [int]$coreTemplate.'msPKI-Template-Schema-Version'
                } else { $null }

                # Flags for security analysis - Core converts to string arrays like @('ENROLLEE_SUPPLIES_SUBJECT')
                # We keep original values for display AND extract raw integers for bitwise operations
                CertificateNameFlagDisplay = $coreTemplate.'msPKI-Certificate-Name-Flag'
                EnrollmentFlagDisplay = $coreTemplate.'msPKI-Enrollment-Flag'
                PrivateKeyFlagDisplay = $coreTemplate.'msPKI-Private-Key-Flag'

                # The plain "flags" attribute. ConvertFrom-LDAPAttribute has an arm for
                # each msPKI-*-Flag and none for this one, so it arrives as the raw LDAP
                # value - the same idiom Get-CertificateAuthority and Get-DomainGPO use.
                TemplateFlags = if ($coreTemplate.flags) { [int]$coreTemplate.flags } else { 0 }

                # Signatures required (from Core)
                RASignatureCount = if ($coreTemplate.'msPKI-RA-Signature') {
                    [int]$coreTemplate.'msPKI-RA-Signature'
                } else { 0 }
                RAApplicationPolicies = if ($coreTemplate.'msPKI-RA-Application-Policies') {
                    @($coreTemplate.'msPKI-RA-Application-Policies')
                } else { @() }

                # EKUs (from Core - may include friendly names like "Client Authentication (1.3.6.1.5.5.7.3.2)")
                ExtendedKeyUsage = if ($coreTemplate.pKIExtendedKeyUsage) {
                    @($coreTemplate.pKIExtendedKeyUsage)
                } else { @() }
                ApplicationPolicies = if ($coreTemplate.'msPKI-Certificate-Application-Policy') {
                    @($coreTemplate.'msPKI-Certificate-Application-Policy')
                } else { @() }

                # Key settings (from Core)
                MinimalKeySize = if ($coreTemplate.'msPKI-Minimal-Key-Size') {
                    [int]$coreTemplate.'msPKI-Minimal-Key-Size'
                } else { 0 }

                # Validity Period (already converted by Core to "2 year(s)", "90 day(s)", etc.)
                ValidityPeriod = if ($coreTemplate.pKIExpirationPeriod) {
                    $coreTemplate.pKIExpirationPeriod
                } else { "Unknown" }

                # Certificate Policies (issuance policy OIDs - needed for ESC13 detection)
                CertificatePolicies = if ($coreTemplate.'msPKI-Certificate-Policy') {
                    @($coreTemplate.'msPKI-Certificate-Policy')
                } else { @() }

                # Security Descriptor (from Core - for enrollment permissions parsing)
                SecurityDescriptor = $coreTemplate.nTSecurityDescriptor
            }

            # ===== Computed Security Properties (Check module logic) =====
            # Parse flags from converted string arrays (e.g., @('ENROLLEE_SUPPLIES_SUBJECT', 'SUBJECT_ALT_REQUIRE_UPN'))
            $certNameFlags = $template.CertificateNameFlagDisplay
            $enrollFlags = $template.EnrollmentFlagDisplay
            $privKeyFlags = $template.PrivateKeyFlagDisplay

            # EnrolleeSuppliesSubject (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            $template | Add-Member -NotePropertyName 'EnrolleeSuppliesSubject' -NotePropertyValue (
                ($certNameFlags -contains 'ENROLLEE_SUPPLIES_SUBJECT') -or
                ($certNameFlags -match 'ENROLLEE_SUPPLIES_SUBJECT')
            )

            # NoSecurityExtension (CT_FLAG_NO_SECURITY_EXTENSION)
            $template | Add-Member -NotePropertyName 'NoSecurityExtension' -NotePropertyValue (
                ($enrollFlags -contains 'NO_SECURITY_EXTENSION') -or
                ($enrollFlags -match 'NO_SECURITY_EXTENSION')
            )

            # Combine EKUs for analysis (Core may add friendly names, so match on OID)
            $allEKUs = @($template.ExtendedKeyUsage) + @($template.ApplicationPolicies) | Where-Object { $_ } | Select-Object -Unique

            # ClientAuthentication - can be used for Kerberos auth.
            #
            # These four OIDs are the authentication EKUs the ESC1 precondition names, and
            # every enrollment-driven ESC in this check keys off this flag: ESC1, ESC2,
            # ESC3-TARGET and ESC9. PKINIT Client Authentication was missing, so a template
            # carrying only that OID authenticated in the domain while adPEAS reported
            # nothing about it - it is the OID used for smart-card and certificate logon in
            # environments that do not also set the Microsoft-specific one.
            $template | Add-Member -NotePropertyName 'ClientAuthentication' -NotePropertyValue (
                (Test-EKUPresent -Eku $allEKUs -Oid '1.3.6.1.5.5.7.3.2') -or       # Client Authentication
                (Test-EKUPresent -Eku $allEKUs -Oid '1.3.6.1.4.1.311.20.2.2') -or # Smart Card Logon
                (Test-EKUPresent -Eku $allEKUs -Oid '1.3.6.1.5.2.3.4') -or          # PKINIT Client Authentication
                (Test-EKUPresent -Eku $allEKUs -Oid '2.5.29.37.0') -or                 # Any Purpose
                ($allEKUs.Count -eq 0)                                    # No EKUs = Any Purpose
            )

            # AnyPurpose EKU
            $template | Add-Member -NotePropertyName 'AnyPurpose' -NotePropertyValue (
                (Test-EKUPresent -Eku $allEKUs -Oid '2.5.29.37.0') -or ($allEKUs.Count -eq 0)
            )

            # IsCA (CT_FLAG_IS_CA, bit 0x80 of "flags" - MS-CRTD 2.4)
            # A certificate issued from a template carrying this flag is a CA
            # certificate: its holder signs certificates for anybody. ESC2's write-up has
            # named this case since it was written - the title says "Any Purpose or SubCA
            # Certificate Template", one of its remediation commands reads this exact
            # bit, and the CertificateTemplate ObjectType lists it under WhatWeCheck
            # - and nothing anywhere evaluated it.
            $template | Add-Member -NotePropertyName 'IsCA' -NotePropertyValue (
                ($template.TemplateFlags -band 0x80) -ne 0
            )

            # EnrollmentAgent (Certificate Request Agent EKU)
            # ESC3 condition 1: the certificate issued FROM this template is an enrollment agent
            # certificate and can be used to co-sign requests on behalf of other principals.
            $template | Add-Member -NotePropertyName 'EnrollmentAgent' -NotePropertyValue (
                Test-EKUPresent -Eku $allEKUs -Oid '1.3.6.1.4.1.311.20.2.1'
            )

            # EnrollmentAgentSignatureRequired (ESC3 condition 2)
            # The inverse of EnrollmentAgent: this template can only be issued when the request is
            # co-signed by a certificate carrying the Certificate Request Agent application policy.
            # Such a template is the TARGET of an "enroll on behalf of" attack - the agent picks the
            # subject, so client-auth templates of this kind are a full impersonation primitive.
            # RAApplicationPolicies carries friendly names ("Certificate Request Agent (Enrollment
            # Agent) (1.3.6.1.4.1.311.20.2.1)"), so match on the OID rather than on the name.
            $template | Add-Member -NotePropertyName 'EnrollmentAgentSignatureRequired' -NotePropertyValue (
                ($template.RASignatureCount -ge 1) -and (Test-EKUPresent -Eku $template.RAApplicationPolicies -Oid '1.3.6.1.4.1.311.20.2.1')
            )

            # ManagerApprovalRequired (PEND_ALL_REQUESTS)
            $template | Add-Member -NotePropertyName 'ManagerApprovalRequired' -NotePropertyValue (
                ($enrollFlags -contains 'PEND_ALL_REQUESTS') -or
                ($enrollFlags -match 'PEND_ALL_REQUESTS')
            )

            # ExportableKey (CT_FLAG_EXPORTABLE_KEY)
            $template | Add-Member -NotePropertyName 'ExportableKey' -NotePropertyValue (
                ($privKeyFlags -contains 'EXPORTABLE_KEY') -or
                ($privKeyFlags -match 'EXPORTABLE_KEY')
            )

            # Parse enrollment permissions from Security Descriptor
            # nTSecurityDescriptor is now a unified object with ACEs array
            $enrollmentPrincipals = @()
            $enrollmentPrincipalSIDs = @()

            # Access ACEs from the unified nTSecurityDescriptor structure
            $sdACEs = if ($coreTemplate.nTSecurityDescriptor -and $coreTemplate.nTSecurityDescriptor.ACEs) {
                $coreTemplate.nTSecurityDescriptor.ACEs
            } else {
                @()
            }

            # Who may enrol, read in the order the access check reads the DACL:
            #
            # - The explicit Denies first. A Deny written on the template wins over every
            #   Allow, wherever it stands among the explicit ACEs. Only Allow ACEs were read
            #   at first, so the common hardening - Allow Enroll inherited from the
            #   container, Deny Enroll on the template - kept reporting ESC1, ESC2, ESC3,
            #   ESC9, ESC13 and ESC15 for principals that cannot enrol at all, and those are
            #   precisely the templates a customer considers dealt with.
            # - Then the explicit Allows, and only then the inherited ACEs, in the order the
            #   DACL holds them - the nearest parent's first. An inherited Deny therefore
            #   does not stop an Allow written on the template. Every Deny used to win, which
            #   dropped the principal, and with it the ESC findings, from a template the
            #   principal can in fact enrol from.
            #
            # The first ACE that decides for a trustee is the one that counts. Which ACEs
            # cover enrollment at all - their scope, inherit-only - says
            # Get-TemplateEnrollmentRight.
            #
            # Only a Deny for the same trustee is acted on. A Deny that reaches the
            # principal through a group it belongs to is not resolved here - that needs the
            # membership of every trustee - so such a Deny is reported as its own row and
            # left for the reader to apply.
            $enrollmentDenied = @()
            $explicitDenies = @()
            $explicitAllows = @()
            $inheritedEntries = @()
            foreach ($ace in @($sdACEs)) {
                if ($ace.Type -ne 'Allow' -and $ace.Type -ne 'Deny') { continue }
                $coveredRights = @(Get-TemplateEnrollmentRight -ACE $ace)
                if ($coveredRights.Count -eq 0) { continue }

                $entry = [PSCustomObject]@{ ACE = $ace; Rights = $coveredRights }
                if ($ace.IsInherited) {
                    $inheritedEntries += $entry
                } elseif ($ace.Type -eq 'Deny') {
                    $explicitDenies += $entry
                } else {
                    $explicitAllows += $entry
                }

                if ($ace.Type -ne 'Deny') { continue }

                $deniedRight = if ($coveredRights.Count -gt 1) {
                    'every right, enrollment included'
                } elseif ($coveredRights -contains 'Certificate-Enrollment') {
                    'Certificate-Enrollment'
                } else {
                    # Autoenrollment alone. It does not stop a manual request, so the
                    # trustee stays in the enrollment list and only the row is printed.
                    'Certificate-AutoEnrollment only, manual enrollment still allowed'
                }

                $deniedName = if ($ace.Name) { [string]$ace.Name } else { [string]$ace.SID }
                if (-not $deniedName) { continue }
                $deniedEntry = "${deniedName}: Deny on $deniedRight"
                if ($ace.IsInherited) { $deniedEntry += ' (inherited - an Allow written on the template overrides it)' }
                if ($enrollmentDenied -notcontains $deniedEntry) { $enrollmentDenied += $deniedEntry }
            }

            $decidedSIDs = @{}
            $decidedNames = @{}
            foreach ($entry in @($explicitDenies + $explicitAllows + $inheritedEntries)) {
                $ace = $entry.ACE
                $aceSID = [string]$ace.SID
                $aceName = [string]$ace.Name
                if ($aceSID -and $decidedSIDs.ContainsKey($aceSID)) { continue }
                if ($aceName -and $decidedNames.ContainsKey($aceName)) { continue }

                if ($ace.Type -eq 'Deny') {
                    # A Deny of autoenrollment alone decides nothing about a manual request.
                    if ($entry.Rights -notcontains 'Certificate-Enrollment') { continue }
                } elseif ($aceName -and $enrollmentPrincipals -notcontains $aceName) {
                    $enrollmentPrincipals += $aceName
                    # Append unconditionally, even when the ACE carries no SID. The
                    # consumer pairs the two lists by index, and appending only the
                    # SIDs that exist shifted every later entry by one: a principal
                    # was then judged against another principal's SID. That can rate
                    # an unprivileged group as privileged and silently suppress the
                    # ESC1, ESC2 and ESC3 findings for the whole template. A $null
                    # here makes the consumer fall back to the name, which is the
                    # documented behaviour for a principal without a SID.
                    $enrollmentPrincipalSIDs += $ace.SID
                }

                if ($aceSID) { $decidedSIDs[$aceSID] = $true }
                if ($aceName) { $decidedNames[$aceName] = $true }
            }
            $template | Add-Member -NotePropertyName 'EnrollmentPrincipals' -NotePropertyValue $enrollmentPrincipals
            $template | Add-Member -NotePropertyName 'EnrollmentPrincipalSIDs' -NotePropertyValue $enrollmentPrincipalSIDs

            # Shown, not only applied: a Deny that reaches a principal through a group is
            # not resolved here, so the reader needs to see which Deny ACEs exist to judge
            # the enrollment list for themselves.
            if (@($enrollmentDenied).Count -gt 0) {
                $template | Add-Member -NotePropertyName 'enrollmentDeniedPrincipals' -NotePropertyValue @($enrollmentDenied) -Force
            }

            # Whether the security descriptor was there to read, which is a different
            # statement from "no principal holds Certificate-Enrollment". A template that
            # withdraws Read-Control from Authenticated Users arrives without
            # nTSecurityDescriptor, the SD conversion can fail, and in both cases the
            # enrollment list comes out empty - the same shape as a template that really
            # grants enrollment to nobody. Get-ADCSVulnerabilities needs to tell them
            # apart: one is an unknown, the other is a template nobody can enroll from.
            $template | Add-Member -NotePropertyName 'EnrollmentRightsRead' -NotePropertyValue (@($sdACEs).Count -gt 0)

            # Parse write/modify permissions from Security Descriptor (for informational display)
            # These rights allow modifying the template itself (relevant for ESC4 context)
            $templateACL = @()
            $writeRights = @('GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner')

            if (@($sdACEs).Count -gt 0) {
                $seenSIDs = @{}
                foreach ($ace in $sdACEs) {
                    if ($ace.Type -ne 'Allow') { continue }
                    if (-not $ace.SID) { continue }

                    # The same two readings as for enrollment: an inherit-only ACE does not
                    # apply to the template, and a scoped one grants its mask on the
                    # attribute or child class it names only - GenericAll scoped that way
                    # is no control over the template.
                    if (-not (Test-ACEAppliesToSelf -ACE $ace)) { continue }

                    # Check for write/modify rights
                    $hasWriteRight = $false
                    $matchedRight = ""

                    if (-not $ace.ObjectType) {
                        foreach ($right in $writeRights) {
                            if ($ace.Rights -match $right) {
                                $hasWriteRight = $true
                                $matchedRight = $right
                                break
                            }
                        }
                    }

                    # WriteProperty on all properties (empty ObjectType = all properties)
                    if (-not $hasWriteRight -and $ace.Rights -match 'WriteProperty') {
                        if (-not $ace.ObjectType) {
                            $hasWriteRight = $true
                            $matchedRight = "WriteProperty"
                        }
                    }

                    if (-not $hasWriteRight) { continue }

                    # Deduplicate by SID+right combination
                    $dedupeKey = "$($ace.SID)|$matchedRight"
                    if ($seenSIDs.ContainsKey($dedupeKey)) { continue }
                    $seenSIDs[$dedupeKey] = $true

                    $templateACL += [PSCustomObject]@{
                        Identity = if ($ace.Name) { $ace.Name } else { $ace.SID }
                        SID      = $ace.SID
                        Right    = $matchedRight
                    }
                }
            }

            # Add owner as well if not already covered by a write ACE
            if ($coreTemplate.nTSecurityDescriptor -and $coreTemplate.nTSecurityDescriptor.Owner) {
                $ownerSID  = $coreTemplate.nTSecurityDescriptor.Owner.SID
                $ownerName = $coreTemplate.nTSecurityDescriptor.Owner.Name
                if ($ownerSID -and -not ($templateACL | Where-Object { $_.SID -eq $ownerSID -and $_.Right -eq 'Owner' })) {
                    $templateACL += [PSCustomObject]@{
                        Identity = if ($ownerName) { $ownerName } else { $ownerSID }
                        SID      = $ownerSID
                        Right    = 'Owner'
                    }
                }
            }

            $template | Add-Member -NotePropertyName 'TemplateACL' -NotePropertyValue $templateACL

            Write-Output $template
        }
        if ($totalTemplates -gt $Script:ProgressThreshold) { Show-Progress -Activity "Analyzing certificate templates" -Completed }

        } catch {
            Write-Log "[Get-ADCSTemplate] Error: $_" -Level Error
            Show-Line "Error during check - certificate templates could not be evaluated: $_" -Class Finding
        }
    }

    end {
        Write-Log "[Get-ADCSTemplate] Enumeration complete"
    }
}
