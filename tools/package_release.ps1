#requires -Version 7.2
param([string]$BuildDirectory = 'out/build/windows')

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root
$component = 'asset-extractor'
$package = Join-Path $root "out/release/$component-win64"
if (Test-Path -LiteralPath $package) {
    throw "Package directory already exists: $package. Use a fresh output directory."
}
New-Item -ItemType Directory -Path $package -Force | Out-Null

function Copy-Required {
    param([string]$Source, [string]$Destination = $package)

    if (-not (Test-Path -LiteralPath $Source)) {
        throw "Required release input is missing: $Source"
    }
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -Force
}

$published = Join-Path $root 'out/publish'
& dotnet publish ChroniclesAssetExtractor.csproj -c Release --no-restore `
    -p:CUE4PARSE_SKIP_NATIVE=true "-p:DirectoryPackagesPropsPath=$root/dependency-versions.props" `
    -o $published
if ($LASTEXITCODE -ne 0) {
    throw 'Extractor publish failed.'
}
Get-ChildItem -LiteralPath $published -File | Copy-Item -Destination $package
Get-ChildItem -LiteralPath $root -Filter '*.py' -File | Copy-Item -Destination $package
Copy-Required 'requirements.txt'
Copy-Required 'out/dependencies/CUE4Parse/LICENSE' "$package/CUE4Parse-LICENSE"
Copy-Required 'out/dependencies/CUE4Parse/NOTICE' "$package/CUE4Parse-NOTICE"

Copy-Required 'README.md'
if (Test-Path -LiteralPath 'LICENSE') {
    Copy-Required 'LICENSE'
}
# Package only explicitly selected binaries, configuration examples and tool source.
# Never copy the checkout, data/generated, private configuration or research exports.
$archive = "$package.zip"
Compress-Archive -Path "$package/*" -DestinationPath $archive
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $([IO.Path]::GetFileName($archive))" | Set-Content -LiteralPath "$archive.sha256" -Encoding ascii
Write-Output $archive
