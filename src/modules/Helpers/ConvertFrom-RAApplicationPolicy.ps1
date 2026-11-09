<#
.SYNOPSIS
    Reads msPKI-RA-Application-Policies, in either of the two forms it is stored in.

.DESCRIPTION
    MS-CRTD gives the attribute two syntaxes, and only one of them is what its name says.

    A template of schema version 1 to 3 stores the application policy OIDs an enrollment
    agent's certificate has to carry before it may co-sign a request for this template -
    the second condition of ESC3.

    A version 4 template whose msPKI-Private-Key-Flag does not carry
    CT_FLAG_USE_LEGACY_PROVIDER stores a string of name`type`value triplets instead, where
    the type is DWORD or PZPWSTR. The key settings of the template live in it:
    msPKI-Asymmetric-Algorithm, msPKI-Hash-Algorithm, msPKI-Key-Usage,
    msPKI-Symmetric-Algorithm, msPKI-Symmetric-Key-Length, msPKI-Key-Security-Descriptor -
    and, where the template does require a co-signature, a nested
    msPKI-RA-Application-Policies property whose value is the OIDs as a comma-separated
    list. Read as one string that form is unreadable, and nothing in it is what the row it
    reached was called:

        msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA256`...

    Told apart by shape rather than by the template version, so this still reads a value
    whose msPKI-Private-Key-Flag could not be read - and so a value that is neither form
    is passed through rather than dropped.

    Of the key settings only an outdated algorithm earns a row of its own, because nothing
    in adPEAS rates template cryptography and a row printed for every version 4 template
    would say nothing. Reported: MD2, MD4, MD5 or SHA1 as the request hash, DES, RC2 or RC4
    as the symmetric algorithm, and a symmetric key under 112 bits.

    NOT reported, deliberately: 3DES. Windows writes it wherever AES-256 was not chosen, so
    a rule that fires on it fires on nearly every version 4 template; and the algorithm
    wraps the private key once on its way to the CA for archival, which is not the long
    lived channel the attacks on its 64-bit block size need. Nor is msPKI-Key-Usage
    0xFFFFFF reported - that is "no restriction", the normal state, not a finding.

.PARAMETER Value
    The attribute as it arrives from LDAP: one string, or several.

.OUTPUTS
    PSCustomObject with Policies (the application policy OIDs, in dotted form), Settings
    (every name-value pair of the triplet form, in the order stored) and Notable (the
    outdated settings as one short string, or $null).

.NOTES
    Author: Alexander Sturz (@_61106960_)
    References:
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/3fe798de-6252-4350-aace-f418603ddeda
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/c55ec697-be3f-4117-8316-8895e4399237
    - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/b083a3c4-f57e-4925-b3f8-3dba81dae946
#>
function ConvertFrom-RAApplicationPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowNull()]
        [AllowEmptyCollection()]
        $Value
    )

    $policies = New-Object System.Collections.ArrayList
    $settings = New-Object System.Collections.Specialized.OrderedDictionary

    foreach ($entry in @($Value)) {
        $text = [string]$entry
        if ([string]::IsNullOrWhiteSpace($text)) { continue }

        # The triplet form by its shape: a type the specification allows, between two
        # backticks. A list of OIDs never contains one.
        if ($text -match '(?i)`(DWORD|PZPWSTR)`') {
            $parts = $text.Split('`')
            for ($i = 0; ($i + 2) -lt $parts.Count; $i += 3) {
                $name = $parts[$i].Trim()
                $type = $parts[$i + 1].Trim()
                $data = $parts[$i + 2]
                if (-not $name) { continue }
                if (@('DWORD', 'PZPWSTR') -notcontains $type) { continue }

                # The OIDs the attribute is named after, nested inside it.
                if ($name -ieq 'msPKI-RA-Application-Policies') {
                    foreach ($oid in ([string]$data -split ',')) {
                        if ($oid.Trim()) { [void]$policies.Add($oid.Trim()) }
                    }
                    continue
                }
                $settings[$name] = $data
            }
            continue
        }

        [void]$policies.Add($text.Trim())
    }

    $notable = New-Object System.Collections.ArrayList

    $hashAlgorithm = [string]$settings['msPKI-Hash-Algorithm']
    if ($hashAlgorithm -match '(?i)^(MD2|MD4|MD5|SHA-?1)$') {
        [void]$notable.Add("request hash $hashAlgorithm")
    }

    # Anchored, so 3DES is not read as DES.
    $symmetricAlgorithm = [string]$settings['msPKI-Symmetric-Algorithm']
    if ($symmetricAlgorithm -match '(?i)^(DES|RC2|RC4)$') {
        [void]$notable.Add("symmetric $symmetricAlgorithm")
    }

    $symmetricLength = [string]$settings['msPKI-Symmetric-Key-Length']
    if ($symmetricLength -match '^\d+$' -and [int]$symmetricLength -lt 112) {
        [void]$notable.Add("symmetric key $symmetricLength bit")
    }

    return [PSCustomObject]@{
        Policies = @($policies)
        Settings = $settings
        Notable  = if ($notable.Count -gt 0) { ($notable -join ', ') } else { $null }
    }
}
