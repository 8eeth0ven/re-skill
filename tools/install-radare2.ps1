param([string]$Destination = (Join-Path $PSScriptRoot '..\tools-env\radare2-6.2.4'))
$ErrorActionPreference = 'Stop'
$reVersion = '6.2.4'
$reExpectedHash = 'aa3454fd89e8a4ead450caff35a1d3919065744e7091540d4913a9487241799d'
$reRepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$reTarget = [System.IO.Path]::GetFullPath($Destination)
if (-not $reTarget.StartsWith($reRepoRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'The tool destination must be within this checkout.'
}
if (Test-Path -LiteralPath $reTarget) { throw 'Destination already exists; verify/reuse the installed executable.' }
$reParent = Split-Path -Parent $reTarget
New-Item -ItemType Directory -Path $reParent -Force | Out-Null
$reArchivePath = Join-Path $reParent ('radare2-' + $reVersion + '-w64.zip')
Invoke-WebRequest -Uri ('https://github.com/radareorg/radare2/releases/download/' + $reVersion + '/radare2-' + $reVersion + '-w64.zip') -OutFile $reArchivePath -TimeoutSec 60
$reActualHash = (Get-FileHash -LiteralPath $reArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($reActualHash -ne $reExpectedHash) { throw 'Official release archive checksum mismatch.' }
Expand-Archive -LiteralPath $reArchivePath -DestinationPath $reTarget
$reBinary = Get-ChildItem -LiteralPath $reTarget -Recurse -Filter 'radare2.exe' -File | Select-Object -First 1
if (-not $reBinary) { $reBinary = Get-ChildItem -LiteralPath $reTarget -Recurse -Filter 'r2.exe' -File | Select-Object -First 1 }
if (-not $reBinary) { throw 'No radare2 executable found in the official release.' }
Write-Output ('Verified radare2 ' + $reVersion + ': ' + $reBinary.FullName)
Write-Output ('Set RE_RUN_R2 to this path before running native analysis.')
