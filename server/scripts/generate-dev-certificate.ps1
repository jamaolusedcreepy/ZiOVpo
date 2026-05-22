[CmdletBinding()]
param(
    [string]$OutputDirectory = "src/main/resources/certs",
    [string]$PfxPassword = "changeit23358"
)

$ErrorActionPreference = "Stop"

$absoluteOutputDirectory = Join-Path $PSScriptRoot "..\\$OutputDirectory"
New-Item -ItemType Directory -Path $absoluteOutputDirectory -Force | Out-Null

$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$distinguishedName = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=localhost, OU=23358, O=InfoGuard, C=RU")
$request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    $distinguishedName,
    $rsa,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)

$sanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
$sanBuilder.AddDnsName("localhost")
$sanBuilder.AddIpAddress([System.Net.IPAddress]::Parse("127.0.0.1"))
$request.CertificateExtensions.Add($sanBuilder.Build())
$request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $false))
$request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
    [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
    [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment,
    $false
))
$request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($request.PublicKey, $false))

$signatureGenerator = [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForRSA(
    $rsa,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)

$notBefore = [System.DateTimeOffset]::UtcNow.AddDays(-1)
$notAfter = $notBefore.AddYears(3)
$serialNumber = [byte[]](0x5B, 0x3E)

$certificate = $request.Create($distinguishedName, $signatureGenerator, $notBefore, $notAfter, $serialNumber)
$certificateWithKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($certificate, $rsa)

$pfxPath = Join-Path $absoluteOutputDirectory "infoguard-dev.p12"
$cerPath = Join-Path $absoluteOutputDirectory "infoguard-dev.cer"

[System.IO.File]::WriteAllBytes(
    $pfxPath,
    $certificateWithKey.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $PfxPassword)
)
[System.IO.File]::WriteAllBytes(
    $cerPath,
    $certificateWithKey.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
)

Write-Host "Created certificate files:"
Write-Host "  PFX: $pfxPath"
Write-Host "  CER: $cerPath"
Write-Host "Serial number (decimal): 23358"
