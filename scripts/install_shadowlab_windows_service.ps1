param(
    [string]$ServiceName = "ShadowLabApi",
    [string]$DisplayName = "ShadowLab API",
    [string]$Description = "Runs the ShadowLab FastAPI backend as a Windows service through NSSM.",
    [string]$NssmPath = "nssm.exe"
)

$repoRoot = Split-Path -Parent $PSScriptRoot
$pythonExe = (Get-Command python).Source
$appPath = Join-Path $repoRoot "app.py"

& $NssmPath install $ServiceName $pythonExe $appPath
& $NssmPath set $ServiceName AppDirectory $repoRoot
& $NssmPath set $ServiceName DisplayName $DisplayName
& $NssmPath set $ServiceName Description $Description
& $NssmPath set $ServiceName Start SERVICE_AUTO_START

Write-Host "Service '$ServiceName' installed. Use 'nssm start $ServiceName' to start it."
