<#
.SYNOPSIS
    Returns a certificate validation callback that accepts every server certificate and
    runs on any thread.

.DESCRIPTION
    adPEAS talks HTTPS to internal services - AD CS web enrollment, NDES, CEP/CES, the EPA
    probe - whose certificates come from the customer's own CA or are self-signed, and
    which the scanning host usually does not trust. Every one of those requests therefore
    sets [System.Net.ServicePointManager]::ServerCertificateValidationCallback first.

    It used to be set to the script block { $true }. PowerShell turns a script block into
    a delegate that can only run on a thread with a runspace. Windows PowerShell 5.1 calls
    the callback on the thread that called GetResponse(), which has one. PowerShell 7 does
    not: HttpWebRequest is built on HttpClient there and validates the certificate on a
    thread-pool thread, the script block throws "There is no Runspace available to run
    scripts in this thread", the handshake fails, and every HTTPS endpoint read as not
    reachable. Measured against a lab CA: CertSrv, CEP, CES and NDES over HTTPS all went
    missing from the report under pwsh 7, the EPA probe failed, and nothing said why -
    the scan fell back to the HTTP endpoints and reported those as all there is.

    The delegate returned here is compiled from an expression tree, so no script block is
    involved and it runs on whatever thread .NET calls it from. System.Linq.Expressions is
    part of both .NET Framework and .NET, so this needs neither Add-Type nor a compiler.

    The SslStream callback in Connect-LDAP and the VerifyServerCertificate callback of the
    LDAPS connection stay script blocks on purpose: both are called synchronously on the
    calling thread on both runtimes (measured), and the SslStream one reads
    $IgnoreSSLErrors from its scope.

.OUTPUTS
    [System.Net.Security.RemoteCertificateValidationCallback]

.EXAMPLE
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = New-AcceptAnyCertificateCallback

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>
function New-AcceptAnyCertificateCallback {
    [CmdletBinding()]
    [OutputType([System.Net.Security.RemoteCertificateValidationCallback])]
    param()

    $expression = [System.Linq.Expressions.Expression]
    $parameters = [System.Linq.Expressions.ParameterExpression[]]@(
        $expression::Parameter([object], 'sender'),
        $expression::Parameter([System.Security.Cryptography.X509Certificates.X509Certificate], 'certificate'),
        $expression::Parameter([System.Security.Cryptography.X509Certificates.X509Chain], 'chain'),
        $expression::Parameter([System.Net.Security.SslPolicyErrors], 'sslPolicyErrors')
    )

    return $expression::Lambda(
        [System.Net.Security.RemoteCertificateValidationCallback],
        $expression::Constant($true),
        $parameters
    ).Compile()
}
