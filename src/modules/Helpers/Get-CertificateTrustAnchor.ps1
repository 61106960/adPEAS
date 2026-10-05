<#
.SYNOPSIS
    Reports whether this directory publishes any certificate issuer trusted for
    authentication.

.DESCRIPTION
    Answers one question for the checks that report certificate mapping problems: could a
    certificate authenticate in this domain at all?

    One container carries the answer: CN=NTAuthCertificates under CN=Public Key
    Services,CN=Services in the Configuration partition. It holds the issuers allowed to
    authenticate an account to the domain, and it governs both routes a certificate can
    take:

      PKINIT   - Kerberos smartcard and certificate logon.
      Schannel - TLS client authentication mapped to an account, as IIS and LDAPS do.

    Schannel is the one worth stating explicitly, because it is easy to assume it only
    needs the issuer in a trust store. It does not. Microsoft's own walkthrough for
    certificate authentication across two forests with no trust between them still begins
    by publishing the issuing CA into the Enterprise NTAuth store, and that holds on the
    altSecurityIdentities route as well - the AltSecID note there replaces the requirement
    to carry the UPN in the certificate's SAN, not the NTAuth requirement.

    CN=Certification Authorities is read too, but only as context. Those are the roots
    distributed to domain members as trusted, which governs chain validation in general -
    a TLS server certificate, a signature - and not permission to authenticate as someone.
    A domain can publish a root and still let nobody log on with a certificate, so this
    count never decides the verdict. It is reported because "no NTAuth issuer, but a PKI
    does exist here" is worth a reader's attention.

    Why this is the right question for ESC14: altSecurityIdentities holds no certificate.
    It holds a pattern - X509:<S>CN=jdoe,... - that a certificate must match, and the
    certificate does not exist until an attacker enrols one. So there is no chain to
    validate at scan time; what can be established is whether any chain could ever be
    accepted. For the two weak forms that name no issuer at all, <S> and <RFC822>, any
    trusted issuer will do, which makes the presence of an anchor the whole question.

    What this does NOT establish, and why nothing here may be called secure:

      - The Enterprise NTAuth store is a machine store as well as a directory object.
        certutil -dspublish writes it into Active Directory and it is distributed from
        there, but certutil -enterprise -addstore NTAuth writes it straight onto one
        machine. An issuer added that way on a domain controller does not appear in the
        directory and cannot be seen from here.
      - An issuer can be published tomorrow, and every mapping in the domain becomes live
        without anyone touching an account.

    So the result dampens a finding and says why; it never clears one.

    Resolved is the flag that matters most. A caller that cannot read the Configuration
    partition - no permission, a dropped connection - must not read that as "no issuer is
    trusted" and quietly downgrade a real finding. Unknown is not absent.

    Cached for the session: two checks ask, and the answer cannot change while a scan runs.
    Cleared by Clear-SessionState.

.PARAMETER Refresh
    Query again rather than answering from the session cache.

.OUTPUTS
    [PSCustomObject] with
      Resolved                 - $true when both containers were queried without error
      NTAuthCertificateCount   - issuers allowed to authenticate an account
      RootCACount              - published trusted root CAs, context only
      HasAuthenticationAnchor  - whether NTAuth holds an issuer. This is the verdict;
                                 RootCACount deliberately does not feed into it.
      Summary                  - one line naming what was found, for a report row

.EXAMPLE
    $anchor = Get-CertificateTrustAnchor
    if ($anchor.Resolved -and -not $anchor.HasAuthenticationAnchor) { 'nothing can authenticate today' }

.NOTES
    Author: Alexander Sturz (@_61106960_)
    Reference: https://support.microsoft.com/help/5014754
#>
function Get-CertificateTrustAnchor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$Refresh
    )

    if ($Script:CertificateTrustAnchor -and -not $Refresh) {
        return $Script:CertificateTrustAnchor
    }

    $result = [PSCustomObject]@{
        Resolved                = $false
        NTAuthCertificateCount  = 0
        RootCACount             = 0
        HasAuthenticationAnchor = $false
        Summary                 = 'Unknown - the Configuration partition could not be read'
    }

    $configNC = $null
    if ($Script:LDAPContext) { $configNC = $Script:LDAPContext.ConfigurationNamingContext }
    if ([string]::IsNullOrWhiteSpace($configNC)) {
        Write-Log "[Get-CertificateTrustAnchor] No ConfigurationNamingContext - leaving the answer unresolved"
        $Script:CertificateTrustAnchor = $result
        return $result
    }

    $pkiBase = "CN=Public Key Services,CN=Services,$configNC"

    # Both queries must succeed. Counting one container and failing on the other would
    # produce a confident "no anchor" from half an answer.
    try {
        $ntAuth = @(Invoke-LDAPSearch -Filter '(cn=NTAuthCertificates)' `
            -SearchBase $pkiBase -Properties 'cn','cACertificate' -Scope OneLevel)

        $ntAuthCount = 0
        if (@($ntAuth).Count -gt 0) {
            # The container existing is not the same as it holding an issuer: an empty
            # NTAuthCertificates object trusts nobody.
            $ntAuthCount = @($ntAuth[0].cACertificate | Where-Object { $_ }).Count
        }

        $rootCAs = @(Invoke-LDAPSearch -Filter '(objectClass=certificationAuthority)' `
            -SearchBase "CN=Certification Authorities,$pkiBase" -Properties 'cn' -Scope OneLevel)
        $rootCACount = @($rootCAs | Where-Object { $_ }).Count

        $result.Resolved                = $true
        $result.NTAuthCertificateCount  = $ntAuthCount
        $result.RootCACount             = $rootCACount

        # NTAuth alone. A published root CA is not permission to authenticate as an
        # account, so it must not keep a finding at full severity on its own.
        $result.HasAuthenticationAnchor = ($ntAuthCount -gt 0)

        $result.Summary = if ($ntAuthCount -gt 0) {
            "NTAuth issuers: $ntAuthCount, published root CAs: $rootCACount"
        } elseif ($rootCACount -gt 0) {
            "No NTAuth issuer, but $rootCACount published root CA(s) - a PKI exists here"
        } else {
            'No NTAuth issuer and no published root CA'
        }

        Write-Log "[Get-CertificateTrustAnchor] $($result.Summary)"
    }
    catch {
        Write-Log "[Get-CertificateTrustAnchor] Query failed, answer stays unresolved: $_" -Level Warning
        # $result keeps Resolved = $false, so no caller downgrades anything on this.
    }

    $Script:CertificateTrustAnchor = $result
    return $result
}
