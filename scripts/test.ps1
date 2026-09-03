[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$dotnet = Join-Path $env:ProgramFiles 'dotnet\dotnet.exe'

Push-Location $repositoryRoot
try {
    & npm --prefix 'src/PasswordManager.App/Terminal' ci
    if ($LASTEXITCODE -ne 0) { throw 'npm ci failed.' }

    & npm --prefix 'src/PasswordManager.App/Terminal' audit --omit=dev
    if ($LASTEXITCODE -ne 0) { throw 'npm audit failed.' }

    & npm --prefix 'src/PasswordManager.App/Terminal' audit
    if ($LASTEXITCODE -ne 0) { throw 'npm development-dependency audit failed.' }

    & npm --prefix 'src/PasswordManager.App/Terminal' run build
    if ($LASTEXITCODE -ne 0) { throw 'Terminal build failed.' }

    & $dotnet restore 'PasswordManager.slnx' --locked-mode
    if ($LASTEXITCODE -ne 0) { throw 'Locked restore failed.' }

    & $dotnet format 'PasswordManager.slnx' --verify-no-changes --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Formatting verification failed.' }

    & $dotnet build 'PasswordManager.slnx' -c Release --no-restore
    if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }

    & $dotnet test 'PasswordManager.slnx' -c Release --no-build
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed.' }
}
finally {
    Pop-Location
}
