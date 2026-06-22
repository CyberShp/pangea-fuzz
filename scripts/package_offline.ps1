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
    "nvme_kv_fuzz",
    "pangea_fuzz",
    "field_catalog.yaml",
    "kv_field_catalog.yaml",
    "net_field_catalog.yaml",
    "config.example.yaml",
    "pangea.config.yaml",
    "pyproject.toml",
    "requirements.txt",
    "README.md",
    "OFFLINE_DEPLOYMENT.md"
)

foreach ($item in $include) {
    $source = Join-Path $root $item
    if (Test-Path -LiteralPath $source) {
        $target = Join-Path $staging $item
        $targetParent = Split-Path -Parent $target
        if ($targetParent) {
            New-Item -ItemType Directory -Force -Path $targetParent | Out-Null
        }
        Copy-Item -LiteralPath $source -Destination $target -Recurse -Force
    }
}

Get-ChildItem -LiteralPath $staging -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
Get-ChildItem -LiteralPath $staging -Recurse -File | Where-Object { $_.Extension -in @(".pyc", ".pyo") } | Remove-Item -Force

if (Test-Path -LiteralPath $outputPath) {
    Remove-Item -LiteralPath $outputPath -Force
}
$stagingItems = Get-ChildItem -LiteralPath $staging
Compress-Archive -Path $stagingItems.FullName -DestinationPath $outputPath
Remove-Item -LiteralPath $staging -Recurse -Force

Write-Host "Created $outputPath"
