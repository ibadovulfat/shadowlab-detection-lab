$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

& "$projectRoot\venv\Scripts\python.exe" -m PyInstaller --noconfirm "$projectRoot\desktop\shadowlab.spec"
& "$projectRoot\venv\Scripts\python.exe" -m pip freeze | Set-Content -Path "$projectRoot\dist\ShadowLab-pip-freeze.txt" -Encoding UTF8
Get-ChildItem "$projectRoot\dist" -Recurse -File | Get-FileHash -Algorithm SHA256 | ForEach-Object {
    "{0}  {1}" -f $_.Hash, $_.Path
} | Set-Content -Path "$projectRoot\dist\ShadowLab-SHA256SUMS.txt" -Encoding UTF8

Write-Host "Build complete. Output folder: $projectRoot\dist\ShadowLab"

