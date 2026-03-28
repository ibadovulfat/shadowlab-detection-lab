param(
    [string]$ApiKeysSha256 = "",
    [switch]$EnableDangerousActions,
    [bool]$StartDesktop = $true
)

function New-ShadowLabApiKey {
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $token = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    return $token
}

function Get-ShadowLabSha256([string]$Value) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    $hash = [System.Security.Cryptography.SHA256]::HashData($bytes)
    return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
}

$env:SHADOWLAB_REQUIRE_AUTH = "true"
$env:SHADOWLAB_POLICY_PROFILE = "lab"
$env:SHADOWLAB_ENABLE_DANGEROUS_ACTIONS = $(if ($EnableDangerousActions) { "true" } else { "false" })

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

Start-Process python -ArgumentList '-m', 'uvicorn', 'api.main:app', '--host', '127.0.0.1', '--port', '8000' -WorkingDirectory 'C:\Users\ulfat\Documents\shadowlab-detection-lab'
Start-Sleep -Seconds 3
if ($StartDesktop) {
    Start-Process python -ArgumentList 'desktop/main.py' -WorkingDirectory 'C:\Users\ulfat\Documents\shadowlab-detection-lab'
}
