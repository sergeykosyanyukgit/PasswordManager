[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$sourceExecutable = Join-Path $repositoryRoot 'artifacts\publish\win-x64\PasswordManager.exe'
$testDirectory = Join-Path $repositoryRoot 'artifacts\test-release\win-x64'
$finalExecutable = Join-Path $testDirectory 'PasswordManager.exe'
$stagingExecutable = Join-Path $testDirectory 'PasswordManager.test-signing.tmp.exe'
$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryDirectory = [IO.Path]::GetFullPath((Join-Path $temporaryRoot ('PasswordManager-TestSign-' + [Guid]::NewGuid().ToString('N'))))

if (-not (Test-Path -LiteralPath $sourceExecutable -PathType Leaf)) {
    throw 'Run scripts/publish.ps1 or dotnet publish before creating a test-signed build.'
}

if (-not $temporaryDirectory.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The temporary signing directory is outside the system temporary directory.'
}

New-Item -ItemType Directory -Path $testDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
$temporaryPfx = Join-Path $temporaryDirectory 'test-signing.pfx'
$certificate = $null
$passwordText = $null

try {
    Copy-Item -LiteralPath $sourceExecutable -Destination $stagingExecutable -Force
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject ('CN=PasswordManager Test Signing ' + [Guid]::NewGuid().ToString('N')) `
        -FriendlyName 'PasswordManager temporary untrusted test signing' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyAlgorithm RSA `
        -KeyLength 3072 `
        -HashAlgorithm SHA256 `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddDays(30)

    if (-not $certificate.HasPrivateKey) {
        throw 'The test certificate has no private key.'
    }

    $randomPassword = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    try {
        $passwordText = [Convert]::ToBase64String($randomPassword)
    }
    finally {
        [Security.Cryptography.CryptographicOperations]::ZeroMemory($randomPassword)
    }

    $securePassword = ConvertTo-SecureString -String $passwordText -AsPlainText -Force
    Export-PfxCertificate -Cert $certificate -FilePath $temporaryPfx -Password $securePassword | Out-Null

    $signTool = Get-ChildItem -LiteralPath "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Filter 'signtool.exe' -File -Recurse |
        Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if ($null -eq $signTool) {
        throw 'Windows SDK x64 SignTool is not installed.'
    }

    & $signTool.FullName sign /fd SHA256 /td SHA256 /tr 'http://timestamp.digicert.com' /f $temporaryPfx /p $passwordText $stagingExecutable
    if ($LASTEXITCODE -ne 0) {
        throw 'Test signing failed.'
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $stagingExecutable
    if ($null -eq $signature.SignerCertificate) {
        throw 'No embedded Authenticode signer was found.'
    }

    $codeSigningOid = '1.3.6.1.5.5.7.3.3'
    $enhancedKeyUsages = @(
        $signature.SignerCertificate.Extensions |
            Where-Object { $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] } |
            ForEach-Object { $_.EnhancedKeyUsages | ForEach-Object Value }
    )
    if ($enhancedKeyUsages -notcontains $codeSigningOid) {
        throw 'The test signer lacks the Code Signing EKU.'
    }

    if ($null -eq $signature.TimeStamperCertificate) {
        throw 'The RFC 3161 timestamp is missing.'
    }

    $verificationOutput = (& $signTool.FullName verify /pa /all /v $stagingExecutable 2>&1 | Out-String)
    $verificationExitCode = $LASTEXITCODE
    if ($verificationExitCode -eq 0) {
        throw 'The disposable test certificate unexpectedly validates as trusted.'
    }

    if ($verificationOutput -notmatch '0x800B0109|root certificate.*not trusted|not trusted by the trust provider') {
        throw 'Signature verification failed for a reason other than the expected untrusted root.'
    }

    if (Test-Path -LiteralPath $finalExecutable -PathType Leaf) {
        Remove-Item -LiteralPath $finalExecutable -Force
    }

    Move-Item -LiteralPath $stagingExecutable -Destination $finalExecutable
    [pscustomobject]@{
        Executable = $finalExecutable
        Size = (Get-Item -LiteralPath $finalExecutable).Length
        SHA256 = (Get-FileHash -LiteralPath $finalExecutable -Algorithm SHA256).Hash
        SignatureStatus = $signature.Status.ToString()
        ExpectedTrustFailure = 'UntrustedRoot'
        Signer = $signature.SignerCertificate.Subject
        CodeSigningEku = $true
        TimestampPresent = $true
        CertificateExpires = $signature.SignerCertificate.NotAfter.ToString('o')
    }
}
finally {
    $passwordText = $null
    if (Test-Path -LiteralPath $stagingExecutable -PathType Leaf) {
        Remove-Item -LiteralPath $stagingExecutable -Force
    }

    if (Test-Path -LiteralPath $temporaryPfx -PathType Leaf) {
        Remove-Item -LiteralPath $temporaryPfx -Force
    }

    if ($null -ne $certificate) {
        $certificatePath = 'Cert:\CurrentUser\My\' + $certificate.Thumbprint
        if (Test-Path -LiteralPath $certificatePath) {
            Remove-Item -LiteralPath $certificatePath -Force
        }
    }

    if (Test-Path -LiteralPath $temporaryDirectory -PathType Container) {
        $remainingFiles = @(Get-ChildItem -LiteralPath $temporaryDirectory -Force)
        if ($remainingFiles.Count -eq 0) {
            Remove-Item -LiteralPath $temporaryDirectory -Force
        }
    }
}
