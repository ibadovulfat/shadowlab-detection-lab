param(
    [string]$BuilderImage = "otel/opentelemetry-collector-builder:latest",
    [string]$ManifestPath = "config/telemetry-fabric-builder.yaml",
    [string]$OutputPath = "build/telemetry-fabric",
    [string]$BuilderExe = "$HOME\\go\\bin\\builder.exe"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $repoRoot $ManifestPath
$output = Join-Path $repoRoot $OutputPath

if (-not (Test-Path $manifest)) {
    throw "Builder manifest not found: $manifest"
}

New-Item -ItemType Directory -Force -Path $output | Out-Null

if (Test-Path $BuilderExe) {
    & $BuilderExe --config=$manifest
} else {
    $manifestDockerPath = "/build/builder-config.yaml"
    $outputDockerPath = "/build/output"

    docker run --rm `
        -v "${manifest}:${manifestDockerPath}" `
        -v "${output}:${outputDockerPath}" `
        $BuilderImage `
        --config=$manifestDockerPath
}

$binaryBase = Join-Path $output "shadowlab-telemetry-fabric"
$binaryExe = "${binaryBase}.exe"
if ((Test-Path $binaryBase) -and (-not (Test-Path $binaryExe))) {
    Copy-Item $binaryBase $binaryExe -Force
}
