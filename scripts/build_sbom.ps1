$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$outputDir = Join-Path $projectRoot "build"
$sbomPath = Join-Path $outputDir "shadowlab-sbom.txt"

New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
Set-Location $projectRoot

& "$projectRoot\venv\Scripts\python.exe" -m pip freeze | Set-Content -Path $sbomPath -Encoding UTF8

Write-Host "SBOM-style dependency snapshot written to $sbomPath"
