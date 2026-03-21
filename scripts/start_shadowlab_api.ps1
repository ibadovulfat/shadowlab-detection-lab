param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8000,
    [string]$PolicyProfile = "lab",
    [string]$ApiKeysSha256 = "",
    [string]$ApiKeys = "",
    [string]$AllowedOrigins = "",
    [string]$OssecHome = "",
    [switch]$RequireAuth,
    [switch]$EnableDangerousActions,
    [switch]$RestoreIntegrationRuntime
)

$env:SHADOWLAB_HOST = $HostAddress
$env:SHADOWLAB_PORT = [string]$Port
$env:SHADOWLAB_POLICY_PROFILE = $PolicyProfile
$env:SHADOWLAB_REQUIRE_AUTH = $RequireAuth.IsPresent.ToString().ToLower()
$env:SHADOWLAB_ENABLE_DANGEROUS_ACTIONS = $EnableDangerousActions.IsPresent.ToString().ToLower()
$env:SHADOWLAB_RESTORE_INTEGRATION_RUNTIME = $RestoreIntegrationRuntime.IsPresent.ToString().ToLower()

if ($ApiKeysSha256.Trim()) {
    $env:SHADOWLAB_API_KEYS_SHA256 = $ApiKeysSha256
}
if ($ApiKeys.Trim()) {
    $env:SHADOWLAB_API_KEYS = $ApiKeys
}
if ($AllowedOrigins.Trim()) {
    $env:SHADOWLAB_ALLOWED_ORIGINS = $AllowedOrigins
}
if ($OssecHome.Trim()) {
    $env:SHADOWLAB_OSSEC_HOME = $OssecHome
}

python app.py
