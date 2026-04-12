param(
    [string[]]$SensitivePaths = @(
        "shadowlab.db",
        ".env",
        "honey/passwords.txt"
    ),
    [string]$BackupBranch = "backup/pre-history-clean"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "git is required"
}

if (-not (Get-Command git-filter-repo -ErrorAction SilentlyContinue)) {
    throw "git-filter-repo is required. Install it before running cleanup."
}

$repoRoot = git rev-parse --show-toplevel
if (-not $repoRoot) {
    throw "Not inside a git repository"
}

Set-Location $repoRoot

Write-Host "Repository root: $repoRoot"
Write-Host "Backup branch: $BackupBranch"
Write-Host ""
Write-Host "Sensitive paths configured for cleanup:"
$SensitivePaths | ForEach-Object { Write-Host " - $_" }

$tracked = git ls-files -- $SensitivePaths
Write-Host ""
Write-Host "Currently tracked matching files:"
if ($tracked) {
    $tracked | ForEach-Object { Write-Host " - $_" }
} else {
    Write-Host " - none currently tracked"
}

$historyHits = @()
foreach ($path in $SensitivePaths) {
    $matches = git log --all --oneline -- $path
    if ($matches) {
        $historyHits += [PSCustomObject]@{
            Path = $path
            Hits = ($matches | Measure-Object -Line).Lines
        }
    }
}

Write-Host ""
Write-Host "History hit summary:"
if ($historyHits.Count -eq 0) {
    Write-Host " - no matching history entries found"
} else {
    $historyHits | ForEach-Object { Write-Host (" - {0}: {1} commits" -f $_.Path, $_.Hits) }
}

$filterArgs = @()
foreach ($path in $SensitivePaths) {
    $filterArgs += "--path"
    $filterArgs += $path
}
$filterArgs += "--invert-paths"

Write-Host ""
Write-Host "Run these commands after confirming with your team:"
Write-Host "git branch $BackupBranch"
Write-Host ("git filter-repo {0}" -f ($filterArgs -join " "))
Write-Host "git push --force --all"
Write-Host "git push --force --tags"
Write-Host ""
Write-Host "After rewrite, rotate any exposed secrets and ask collaborators to re-clone."
