param([switch]$PublishWindows)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
    $project = 'windows/Skybridge.AppleUsbCarrierProbe/AppleUsbCarrierProbe.csproj'
    $evidence = Join-Path $repo 'artifacts/apple-usb-carrier'
    New-Item -ItemType Directory -Force -Path $evidence | Out-Null
    if (Test-Path (Join-Path $evidence 'result.json')) {
        throw 'Use a fresh evidence directory; previous qualification results must be preserved.'
    }
    $sources = @(Get-ChildItem 'windows/Skybridge.AppleUsbCarrierProbe' -File |
        Where-Object Extension -in '.cs','.csproj' | Sort-Object Name |
        ForEach-Object { @{ path = $_.Name; sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() } })
    $sources | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $evidence 'sources.json')
    dotnet build $project -c Release -p:TreatWarningsAsErrors=true 2>&1 |
        Tee-Object -FilePath (Join-Path $evidence 'build.log')
    if ($LASTEXITCODE -ne 0) { throw 'USB carrier build failed.' }
    dotnet run --project $project -c Release --no-build --no-restore -- --self-test 2>&1 |
        Tee-Object -FilePath (Join-Path $evidence 'checks.log')
    if ($LASTEXITCODE -ne 0) { throw 'USB carrier contracts failed.' }
    if ($PublishWindows) {
        dotnet publish $project -c Release -r win-x64 --self-contained true -p:RuntimeFrameworkVersion=10.0.13 `
            -p:TreatWarningsAsErrors=true -o (Join-Path $evidence 'win-x64') 2>&1 |
            Tee-Object -FilePath (Join-Path $evidence 'publish.log')
        if ($LASTEXITCODE -ne 0) { throw 'USB carrier Windows packaging failed.' }
        $output = Join-Path $evidence 'win-x64'
        @(Get-ChildItem $output -Recurse -File | Sort-Object FullName | ForEach-Object {
            @{ path = [IO.Path]::GetRelativePath($output, $_.FullName); bytes = $_.Length;
               sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
        }) | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $evidence 'package-files.json')
    }
    foreach ($source in $sources) {
        if ((Get-FileHash (Join-Path 'windows/Skybridge.AppleUsbCarrierProbe' $source.path) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $source.sha256) {
            throw 'A qualification input changed during execution.'
        }
    }
    @{
        result = 'passed'; scope = 'isolated byte-carrier contracts';
        platform = [Environment]::OSVersion.Platform.ToString(); sdk = (& dotnet --version);
        windowsPackageProduced = [bool]$PublishWindows;
        nativeAppleWindowsServiceVerified = $false; physicalUsbVerified = $false;
        applicationAuthenticated = $false; audioPlayed = $false
    } | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $evidence 'result.json')
} finally { Pop-Location }
