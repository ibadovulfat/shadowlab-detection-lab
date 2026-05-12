param(
    [string]$ApiKeysSha256 = "",
    [switch]$EnableDangerousActions,
    [switch]$EnableNetworkWarfare,
    [bool]$StartDesktop = $true
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptDir ".."))
$venvPython = Join-Path $repoRoot "venv\Scripts\python.exe"
$backendEntry = Join-Path $repoRoot "app.py"
$desktopEntry = Join-Path $repoRoot "desktop\main.py"
$backendLog = Join-Path $repoRoot "shadowlab-backend.log"
$backendErrLog = Join-Path $repoRoot "shadowlab-backend.err.log"

if (-not (Test-Path $venvPython)) {
    throw "Virtual environment interpreter not found at $venvPython. Create it first with: python -m venv venv"
}

if (-not (Test-Path $backendEntry)) {
    throw "Backend entrypoint not found at $backendEntry"
}

if ($StartDesktop -and -not (Test-Path $desktopEntry)) {
    throw "Desktop entrypoint not found at $desktopEntry"
}

function New-ShadowLabApiKey {
    $bytes = New-Object byte[] 24
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        if ($null -ne $rng) {
            $rng.Dispose()
        }
    }
    $token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    return $token
}

function Get-ShadowLabSha256([string]$Value) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($bytes)
    } finally {
        if ($null -ne $sha) {
            $sha.Dispose()
        }
    }
    return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
}

$env:SHADOWLAB_REQUIRE_AUTH = "true"
$env:SHADOWLAB_POLICY_PROFILE = "lab"
$env:SHADOWLAB_ENABLE_DANGEROUS_ACTIONS = $(if ($EnableDangerousActions) { "true" } else { "false" })
$env:SHADOWLAB_ENABLE_NETWORK_WARFARE = $(if ($EnableNetworkWarfare) { "true" } else { "false" })

if ([string]::IsNullOrWhiteSpace($ApiKeysSha256)) {
    $viewerKey = New-ShadowLabApiKey
    $analystKey = New-ShadowLabApiKey
    $adminKey = New-ShadowLabApiKey
    $ApiKeysSha256 = "viewer:$(Get-ShadowLabSha256 $viewerKey),analyst:$(Get-ShadowLabSha256 $analystKey),admin:$(Get-ShadowLabSha256 $adminKey)"

    Write-Host ""
    Write-Host "ShadowLab generated fresh API keys for this session:" -ForegroundColor Cyan
    Write-Host "viewer:  $viewerKey"
    Write-Host "analyst: $analystKey"
    Write-Host "admin:   $adminKey"
    Write-Host ""
    Write-Host "Store these keys securely. Only the SHA-256 values are exported to the backend." -ForegroundColor Yellow
    Write-Host ""
}

$env:SHADOWLAB_API_KEYS_SHA256 = $ApiKeysSha256

try {
    $listeners = Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 8000 -State Listen -ErrorAction Stop
} catch {
    $listeners = @()
}

foreach ($listener in @($listeners)) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $($listener.OwningProcess)" -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        continue
    }
    $commandLine = ""
    if ($null -ne $process.CommandLine) {
        $commandLine = [string]$process.CommandLine
    }
    $executablePath = ""
    if ($null -ne $process.ExecutablePath) {
        $executablePath = [string]$process.ExecutablePath
    }
    $looksLikeShadowLab = (
        ($commandLine -like "*$repoRoot*" -and $commandLine -like "*python*") -or
        ($commandLine -like "* app.py*" -and $executablePath -like "*python*") -or
        ($commandLine -like "*api.main:app*" -and $executablePath -like "*python*")
    )
    if ($looksLikeShadowLab) {
        Stop-Process -Id $listener.OwningProcess -Force
        Start-Sleep -Milliseconds 500
        continue
    }
    throw "Port 8000 is already in use by process $($listener.OwningProcess). Stop that service or change SHADOWLAB_PORT before starting ShadowLab."
}

$backendProcess = Start-Process -FilePath $venvPython `
    -ArgumentList 'app.py' `
    -WorkingDirectory $repoRoot `
    -RedirectStandardOutput $backendLog `
    -RedirectStandardError $backendErrLog `
    -PassThru `
    -WindowStyle Hidden

$backendHealthy = $false
for ($attempt = 0; $attempt -lt 15; $attempt++) {
    Start-Sleep -Seconds 1
    try {
        $response = Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8000/health -TimeoutSec 3
        if ($response.StatusCode -eq 200) {
            $backendHealthy = $true
            break
        }
    } catch {
        continue
    }
}

if (-not $backendHealthy) {
    try {
        Stop-Process -Id $backendProcess.Id -Force
    } catch {
    }
    throw "ShadowLab backend did not become healthy on http://127.0.0.1:8000/health. Review $backendLog and $backendErrLog."
}

Write-Host "ShadowLab backend is healthy on http://127.0.0.1:8000" -ForegroundColor Green

if ($StartDesktop) {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -eq "python.exe" -and
            $null -ne $_.CommandLine -and
            [string]$_.CommandLine -like "*$desktopEntry*"
        } |
        ForEach-Object {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 250
        }
    Start-Process -FilePath $venvPython -ArgumentList 'desktop/main.py' -WorkingDirectory $repoRoot | Out-Null
    Write-Host "ShadowLab desktop started." -ForegroundColor Green
}
