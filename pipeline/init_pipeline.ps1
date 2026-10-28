# Dot-source this script to load the same state/timeout helper as the Bash entry.
# New run: . ./pipeline/init_pipeline.ps1 -Apk 'C:\lab\sample.apk' [-Output 'C:\lab\run']
# Same-host state: . ./pipeline/init_pipeline.ps1 -StateFile 'C:\lab\run\env.json'
[CmdletBinding(DefaultParameterSetName = 'New')]
param(
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'New')][string]$Apk,
    [Parameter(ParameterSetName = 'New')][string]$Output,
    [Parameter(Mandatory = $true, ParameterSetName = 'State')][string]$StateFile
)
$rePython = $env:RE_PYTHON
if (-not $rePython) {
    $rePythonCommand = Get-Command python, python3 -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $rePythonCommand) { throw 'Python 3.11+ is required; set RE_PYTHON to its executable.' }
    $rePython = $rePythonCommand.Source
}
$reInitArgs = @((Join-Path $PSScriptRoot 'init_pipeline.py'))
if ($PSCmdlet.ParameterSetName -eq 'State') {
    $reInitArgs += @('--state-file', $StateFile)
} else {
    $reInitArgs += $Apk
    if ($Output) { $reInitArgs += @('--output', $Output) }
}
$reInitJson = & $rePython @reInitArgs
if ($LASTEXITCODE -ne 0) { throw ('Pipeline initialization failed with exit code ' + $LASTEXITCODE) }
$rePipelineState = ($reInitJson -join "`n") | ConvertFrom-Json
foreach ($reProperty in $rePipelineState.variables.PSObject.Properties) {
    Set-Variable -Name $reProperty.Name -Value $reProperty.Value -Scope Script
}
function run_to {
    if ($args.Count -lt 2) { throw 'Usage: run_to <seconds> <command> [arguments...]' }
    $reSeconds = $args[0]
    $reCommandArgs = @($args | Select-Object -Skip 1)
    & $RE_PYTHON (Join-Path $SKILL_ROOT 'pipeline/run_with_timeout.py') `
        --deadline $RE_PIPELINE_DEADLINE --reserve $RE_REPORT_RESERVE_SECONDS $reSeconds @reCommandArgs
}
