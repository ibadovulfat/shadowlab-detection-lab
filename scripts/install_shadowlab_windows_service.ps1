param(
    [string]$ServiceName = "ShadowLabApi",
    [string]$DisplayName = "ShadowLab API",
    [string]$Description = "Runs the ShadowLab FastAPI backend as a Windows service through NSSM.",
    [string]$NssmPath = "nssm.exe",
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8000,
    [string]$PolicyProfile = "lab",
    [string]$ApiKeysSha256 = "",
    [string]$ApiKeys = "",
    [string]$AllowedOrigins = "",
    [string]$OssecHome = "",
    [switch]$RequireAuth,
    [switch]$EnableDangerousActions,
    [switch]$RestoreIntegrationRuntime,
    [switch]$RunPreflight
)

$repoRoot = Split-Path -Parent $PSScriptRoot
$pythonCommand = Get-Command python -ErrorAction Stop
$pythonExe = $pythonCommand.Source
$appPath = Join-Path $repoRoot "app.py"
$validationScript = Join-Path $repoRoot "scripts\validate_deployment_runtime.py"

if (-not (Get-Command $NssmPath -ErrorAction SilentlyContinue)) {
    throw "NSSM executable not found: $NssmPath"
}

$environmentPairs = @(
    "SHADOWLAB_HOST=$HostAddress",
    "SHADOWLAB_PORT=$Port",
    "SHADOWLAB_POLICY_PROFILE=$PolicyProfile",
    "SHADOWLAB_REQUIRE_AUTH=$($RequireAuth.IsPresent.ToString().ToLower())",
    "SHADOWLAB_ENABLE_DANGEROUS_ACTIONS=$($EnableDangerousActions.IsPresent.ToString().ToLower())",
    "SHADOWLAB_RESTORE_INTEGRATION_RUNTIME=$($RestoreIntegrationRuntime.IsPresent.ToString().ToLower())"
)

if ($ApiKeysSha256.Trim()) {
    $environmentPairs += "SHADOWLAB_API_KEYS_SHA256=$ApiKeysSha256"
}
if ($ApiKeys.Trim()) {
    $environmentPairs += "SHADOWLAB_API_KEYS=$ApiKeys"
}
if ($AllowedOrigins.Trim()) {
    $environmentPairs += "SHADOWLAB_ALLOWED_ORIGINS=$AllowedOrigins"
}
if ($OssecHome.Trim()) {
    $environmentPairs += "SHADOWLAB_OSSEC_HOME=$OssecHome"
}

& $NssmPath install $ServiceName $pythonExe $appPath
& $NssmPath set $ServiceName AppDirectory $repoRoot
& $NssmPath set $ServiceName DisplayName $DisplayName
& $NssmPath set $ServiceName Description $Description
& $NssmPath set $ServiceName Start SERVICE_AUTO_START
& $NssmPath set $ServiceName AppEnvironmentExtra $environmentPairs

if ($RunPreflight.IsPresent) {
    & $pythonExe $validationScript
    if ($LASTEXITCODE -ne 0) {
        throw "Deployment preflight failed. Fix the reported issues before starting the service."
    }
}

Write-Host "Service '$ServiceName' installed. Use 'nssm start $ServiceName' to start it."
