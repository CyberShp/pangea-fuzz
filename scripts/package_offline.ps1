param(
    [string]$Output = "dist\nvmetcp-tls-fuzz-offline.zip"
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$outputPath = Join-Path $root $Output
$outputDir = Split-Path -Parent $outputPath
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("nvmetcp-tls-fuzz-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $staging | Out-Null

$include = @(
    "nvmetcp_tls_fuzz",
    "field_catalog.yaml",
    "config.example.yaml",
    "pyproject.toml",
    "requirements.txt",
    "README.md",
    "OFFLINE_DEPLOYMENT.md"
)

foreach ($item in $include) {
    $source = Join-Path $root $item
    if (Test-Path -LiteralPath $source) {
        Copy-Item -LiteralPath $source -Destination $staging -Recurse -Force
    }
}

if (Test-Path -LiteralPath $outputPath) {
    Remove-Item -LiteralPath $outputPath -Force
}
Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $outputPath
Remove-Item -LiteralPath $staging -Recurse -Force

Write-Host "Created $outputPath"
