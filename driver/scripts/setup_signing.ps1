# setup_signing.ps1 - Create test-signing certificate for SentinelFilter.
#
# Run as Administrator inside the VM.
# Creates a self-signed code-signing certificate and installs it
# into the Trusted Root and Trusted Publishers stores.

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

$CertName = "CN=SentinelFilterTestCert"
$PfxPath  = "$PSScriptRoot\..\SentinelFilter\SentinelFilter.pfx"
$PfxPassword = ConvertTo-SecureString -String "SentinelTest2026!" -Force -AsPlainText

Write-Host "=== Sentinel Filter - Test Certificate Setup ===" -ForegroundColor Cyan

# Step 1: Create self-signed code-signing certificate.
Write-Host "`n[1/4] Creating self-signed certificate: $CertName" -ForegroundColor Yellow
$cert = New-SelfSignedCertificate `
    -Type CodeSigning `
    -KeySpec Signature `
    -Subject $CertName `
    -KeyExportPolicy Exportable `
    -HashAlgorithm SHA256 `
    -KeyLength 2048 `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears(5)

Write-Host "  Certificate thumbprint: $($cert.Thumbprint)"

# Step 2: Export to PFX for signtool.
Write-Host "`n[2/4] Exporting to PFX: $PfxPath" -ForegroundColor Yellow
Export-PfxCertificate -Cert $cert -FilePath $PfxPath -Password $PfxPassword | Out-Null
Write-Host "  PFX exported (password: SentinelTest2026!)"

# Step 3: Install into Trusted Root Certification Authorities.
Write-Host "`n[3/4] Installing into Trusted Root CA (LocalMachine)" -ForegroundColor Yellow
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    "Root", "LocalMachine")
$rootStore.Open("ReadWrite")
$rootStore.Add($cert)
$rootStore.Close()
Write-Host "  Installed into Root store"

# Step 4: Install into Trusted Publishers.
Write-Host "`n[4/4] Installing into Trusted Publishers (LocalMachine)" -ForegroundColor Yellow
$pubStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    "TrustedPublisher", "LocalMachine")
$pubStore.Open("ReadWrite")
$pubStore.Add($cert)
$pubStore.Close()
Write-Host "  Installed into TrustedPublisher store"

Write-Host "`n=== Certificate setup complete ===" -ForegroundColor Green
Write-Host "Thumbprint: $($cert.Thumbprint)"
Write-Host "PFX file:   $PfxPath"
