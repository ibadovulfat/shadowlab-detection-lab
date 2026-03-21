param(
    [string]$OssecHome = "",
    [string]$TestIp = "203.0.113.10"
)

if (-not $OssecHome.Trim()) {
    $OssecHome = $env:SHADOWLAB_OSSEC_HOME
}
if (-not $OssecHome.Trim()) {
    $OssecHome = Join-Path $HOME "Documents\ossec-hids-main"
}

$resolvedHome = (Resolve-Path $OssecHome -ErrorAction Stop).Path
$firewallScript = Join-Path $resolvedHome "active-response\win\firewall-drop.cmd"
$routeScript = Join-Path $resolvedHome "active-response\win\route-null.cmd"
$logPath = Join-Path $resolvedHome "active-response\active-responses.log"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    throw "Administrator privileges are required to validate OSSEC active-response scripts."
}
if (-not (Test-Path $firewallScript)) {
    throw "Missing OSSEC firewall script: $firewallScript"
}
if (-not (Test-Path $routeScript)) {
    throw "Missing OSSEC route script: $routeScript"
}

$env:OSSECPATH = $resolvedHome
if (-not $env:OSSECPATH.EndsWith("\")) {
    $env:OSSECPATH = "$($env:OSSECPATH)\"
}

Write-Host "Validating OSSEC active-response scripts against test IP $TestIp"

try {
    & cmd.exe /c "`"$firewallScript`" add - $TestIp"
    if ($LASTEXITCODE -ne 0) {
        throw "firewall-drop add failed with exit code $LASTEXITCODE"
    }

    & cmd.exe /c "`"$routeScript`" add - $TestIp"
    if ($LASTEXITCODE -ne 0) {
        throw "route-null add failed with exit code $LASTEXITCODE"
    }

    Write-Host "Validation add phase passed"
}
finally {
    & cmd.exe /c "`"$routeScript`" delete - $TestIp" | Out-Null
    & cmd.exe /c "`"$firewallScript`" delete - $TestIp" | Out-Null
}

if (Test-Path $logPath) {
    Get-Content -Path $logPath -Tail 6
}

Write-Host "OSSEC active-response validation completed successfully."
