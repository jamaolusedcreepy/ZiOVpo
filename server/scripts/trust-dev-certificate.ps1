[CmdletBinding()]
param(
    [string]$CertificatePath = "src/main/resources/certs/infoguard-dev.cer"
)

$ErrorActionPreference = "Stop"

$absoluteCertificatePath = Join-Path $PSScriptRoot "..\\$CertificatePath"
if (-not (Test-Path $absoluteCertificatePath)) {
    throw "Certificate file not found: $absoluteCertificatePath"
}

$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($absoluteCertificatePath)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

try {
    $existing = $store.Certificates | Where-Object {
        $_.Thumbprint -eq $certificate.Thumbprint
    }

    if ($existing.Count -eq 0) {
        $store.Add($certificate)
        Write-Host "Certificate imported into CurrentUser\\Root:"
        Write-Host "  Subject: $($certificate.Subject)"
        Write-Host "  Serial: 23358"
    } else {
        Write-Host "Certificate is already trusted in CurrentUser\\Root."
    }
}
finally {
    $store.Close()
}
