[CmdletBinding()]
param(
    [ValidateSet('Run', 'Prepare', 'Merge')]
    [string] $Mode = 'Run',
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$')]
    [string] $RunId = ('audit-' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$helper = Join-Path $PSScriptRoot 'security-check.py'
$runDirectory = Join-Path $repositoryRoot ('security-check/runs/' + $RunId)
$pythonCommand = (Get-Command python -CommandType Application -ErrorAction Stop).Source

if ($Mode -eq 'Merge') {
    & $pythonCommand $helper merge --run-id $RunId
    exit $LASTEXITCODE
}

if ($Mode -eq 'Run') {
    $codexCommand = (Get-Command codex.cmd -CommandType Application -ErrorAction Stop).Source
}
& $pythonCommand $helper prepare --run-id $RunId
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if ($Mode -eq 'Prepare') { exit 0 }

$manifest = Get-Content -LiteralPath (Join-Path $runDirectory 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$previousEncoding = $OutputEncoding
$OutputEncoding = [Text.UTF8Encoding]::new($false)

function Invoke-IsolatedAudit {
    param([string] $PromptPath, [string] $SchemaPath, [string] $ResultPath)
    $promptText = Get-Content -LiteralPath $PromptPath -Raw -Encoding UTF8
    # Fresh context, no resume, no child delegation, read-only shell sandbox.
    # Only the CLI host writes ResultPath. Source-review tools stay offline by task instruction.
    $promptText | & $codexCommand exec --ephemeral --sandbox read-only --color never `
        --disable multi_agent --disable multi_agent_v2 `
        -C $repositoryRoot --output-schema $SchemaPath --output-last-message $ResultPath -
    if ($LASTEXITCODE -ne 0) {
        throw ('Isolated audit failed; run preserved at ' + $runDirectory)
    }
}

try {
    foreach ($module in $manifest.modules) {
        if ($module.id -notmatch '^[a-z][a-z0-9-]{0,63}$') { throw 'Invalid module ID.' }
        Write-Host ('Security audit module: ' + $module.id)
        Invoke-IsolatedAudit `
            -PromptPath (Join-Path $runDirectory ('prompts/' + $module.id + '.md')) `
            -SchemaPath (Join-Path $runDirectory 'module.schema.json') `
            -ResultPath (Join-Path $runDirectory ('results/' + $module.id + '.json'))
    }
    & $pythonCommand $helper capture-support --run-id $RunId
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $pythonCommand $helper validate --run-id $RunId
    if ($LASTEXITCODE -notin @(0, 3)) { exit $LASTEXITCODE }
    Write-Host 'Validating findings in a separate integration context.'
    Invoke-IsolatedAudit `
        -PromptPath (Join-Path $runDirectory 'integration-prompt.md') `
        -SchemaPath (Join-Path $runDirectory 'integration.schema.json') `
        -ResultPath (Join-Path $runDirectory 'integration.json')
    & $pythonCommand $helper capture-support --run-id $RunId
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $pythonCommand $helper merge --run-id $RunId
    exit $LASTEXITCODE
}
finally {
    $OutputEncoding = $previousEncoding
}
