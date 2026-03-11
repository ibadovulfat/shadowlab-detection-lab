$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

& "$projectRoot\venv\Scripts\python.exe" -m PyInstaller --noconfirm "$projectRoot\desktop\shadowlab.spec"

Write-Host "Build complete. Output folder: $projectRoot\dist\ShadowLab"

