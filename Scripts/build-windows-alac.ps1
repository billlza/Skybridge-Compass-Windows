param(
    [Parameter(Mandatory)][ValidateSet('x64', 'ARM64')][string]$Architecture,
    [Parameter(Mandatory)][string]$WorkDirectory,
    [Parameter(Mandatory)][string]$MsysRoot,
    [string]$InputDirectory = '',
    [string]$Generator = 'Visual Studio 18 2026'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $IsWindows) { throw 'The ALAC native build requires Windows and MSVC.' }
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw 'Visual Studio Installer discovery is unavailable.' }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($installation) -or @($installation).Count -ne 1) {
    throw 'One installed MSVC toolchain is required.'
}
$development = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path -LiteralPath $development -PathType Leaf)) { throw 'The selected Visual Studio has no development environment.' }
$target = $Architecture.ToLowerInvariant()
# Capture the environment rather than printing it: CI variables may contain credentials.
$environment = & $env:ComSpec /d /s /c "`"$development`" -no_logo -arch=$target -host_arch=x64 >nul && set"
if ($LASTEXITCODE -ne 0) { throw 'The selected MSVC target environment could not be initialized.' }
foreach ($line in $environment) {
    if ($line -match '^([A-Za-z_][A-Za-z0-9_()]*)=(.*)$') {
        [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
    }
}
if ($env:VSCMD_ARG_TGT_ARCH -ne $target) { throw 'MSVC did not select the requested target architecture.' }
$python = (Get-Command python.exe -ErrorAction Stop).Source
$arguments = @((Join-Path $PSScriptRoot 'build-windows-alac.py'), '--architecture', $Architecture, '--work-dir', $WorkDirectory,
    '--msys-root', $MsysRoot, '--generator', $Generator)
if (-not [string]::IsNullOrWhiteSpace($InputDirectory)) { $arguments += @('--inputs-dir', $InputDirectory) }
& $python @arguments
if ($LASTEXITCODE -ne 0) { throw "The strict ALAC native build failed: $LASTEXITCODE" }
