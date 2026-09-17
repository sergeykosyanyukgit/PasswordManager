[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Executable,

    [switch] $TestBuild
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$executablePath = [IO.Path]::GetFullPath((Join-Path $projectRoot $Executable))
$pfxPathValue = [Environment]::GetEnvironmentVariable('SIGNING_PFX_PATH', 'Process')
$pfxPassword = [Environment]::GetEnvironmentVariable('SIGNING_PFX_PASSWORD', 'Process')
if ([string]::IsNullOrWhiteSpace($pfxPathValue)) {
    $pfxPathValue = [Environment]::GetEnvironmentVariable('SIGNING_PFX_PATH', 'User')
}
if ([string]::IsNullOrWhiteSpace($pfxPassword)) {
    $pfxPassword = [Environment]::GetEnvironmentVariable('SIGNING_PFX_PASSWORD', 'User')
}

if ([string]::IsNullOrWhiteSpace($pfxPathValue) -or [string]::IsNullOrWhiteSpace($pfxPassword)) {
    throw 'Signing requires SIGNING_PFX_PATH and SIGNING_PFX_PASSWORD.'
}

$pfxPath = [IO.Path]::GetFullPath($pfxPathValue)
if ($pfxPath.StartsWith($projectRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The signing PFX must remain outside the repository.'
}
if (-not (Test-Path -LiteralPath $pfxPath -PathType Leaf)) { throw 'The configured signing PFX does not exist.' }
if (-not (Test-Path -LiteralPath $executablePath -PathType Leaf)) { throw 'The executable to sign does not exist.' }

$signTool = Get-ChildItem -LiteralPath "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Filter 'signtool.exe' -Recurse |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
if ($null -eq $signTool) { throw 'Windows SDK x64 SignTool is not installed.' }

try {
    & $signTool.FullName sign /fd SHA256 /td SHA256 /tr 'http://timestamp.digicert.com' /f $pfxPath /p $pfxPassword $executablePath
    if ($LASTEXITCODE -ne 0) { throw 'SignTool signing failed.' }
}
finally {
    $pfxPassword = $null
}

$signature = Get-AuthenticodeSignature -LiteralPath $executablePath
if ($null -eq $signature.SignerCertificate) { throw 'The executable has no Authenticode signer certificate.' }
$utcNow = [DateTime]::UtcNow
if ($signature.SignerCertificate.NotBefore.ToUniversalTime() -gt $utcNow -or $signature.SignerCertificate.NotAfter.ToUniversalTime() -le $utcNow) {
    throw 'The signing certificate is not currently valid.'
}

$ekuExtension = $signature.SignerCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
if ($null -eq $ekuExtension) { throw 'The certificate has no Enhanced Key Usage extension.' }
$enhancedKeyUsage = [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] $ekuExtension
$ekuOids = @($enhancedKeyUsage.EnhancedKeyUsages | ForEach-Object { $_.Value })
if ($ekuOids -notcontains '1.3.6.1.5.5.7.3.3') { throw 'The certificate does not contain the Code Signing EKU.' }
if ($null -eq $signature.TimeStamperCertificate) { throw 'The executable has no RFC 3161 timestamp.' }

if ($TestBuild) {
    if ($signature.SignerCertificate.Subject -ne $signature.SignerCertificate.Issuer -or $signature.SignerCertificate.Subject -notlike '*Test Build (Untrusted)*') {
        throw 'Test signing requires the explicitly labelled self-signed test certificate.'
    }
    Write-Output 'Test signature present; the self-signed chain is intentionally untrusted.'
    return
}

& $signTool.FullName verify /pa /all /v $executablePath
if ($LASTEXITCODE -ne 0 -or $signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    throw 'Production signature verification or trust-chain validation failed.'
}
