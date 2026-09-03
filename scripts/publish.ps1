[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$dotnet = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'
$publishDirectory = Join-Path $repositoryRoot 'artifacts\publish\win-x64'
$releaseDirectory = Join-Path $repositoryRoot 'artifacts\release\win-x64'

Push-Location $repositoryRoot
try {
    & (Join-Path $PSScriptRoot 'test.ps1')

    & $dotnet publish 'src/PasswordManager.App/PasswordManager.App.csproj' -c Release -r win-x64 --self-contained true --no-restore -o $publishDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Publishing failed.' }

    $publishedExecutable = Join-Path $publishDirectory 'PasswordManager.exe'
    $releaseExecutable = Join-Path $releaseDirectory 'PasswordManager.exe'
    & (Join-Path $PSScriptRoot 'sign.ps1') -Executable $publishedExecutable

    New-Item -ItemType Directory -Force -Path $releaseDirectory | Out-Null
    Get-ChildItem -LiteralPath $releaseDirectory -File | Remove-Item -Force
    Copy-Item -LiteralPath $publishedExecutable -Destination $releaseExecutable -Force

    $releaseFiles = @(Get-ChildItem -LiteralPath $releaseDirectory -File)
    if ($releaseFiles.Count -ne 1 -or $releaseFiles[0].Name -ne 'PasswordManager.exe') {
        throw 'The release directory must contain only PasswordManager.exe.'
    }
}
finally {
    Pop-Location
}
