[CmdletBinding()]
param(
    [switch]$Build,
    [switch]$Run,
    [switch]$Test,
    [switch]$Verify,
    [switch]$Benchmark,
    [switch]$GitStatus,
    [string]$State = 'state/demo',
    [string]$Python = ''
)
$ErrorActionPreference = 'Stop'
$repoRoot = $PSScriptRoot
Set-Location -LiteralPath $repoRoot
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)

function Invoke-Checked([scriptblock]$Operation) {
    & $Operation
    if ($LASTEXITCODE -ne 0) { throw "Operation failed with exit code $LASTEXITCODE" }
}

try {
    if ($Build) { Invoke-Checked { cargo build --workspace --locked } }
    if ($Run) { Invoke-Checked { cargo run --locked -p symbiote-runtime --bin symbiote -- demo --state $State } }
    if ($Test) { Invoke-Checked { cargo test --workspace --locked } }
    if ($Verify) {
        if ([string]::IsNullOrWhiteSpace($Python)) {
            $bundledPython = Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
            if (Test-Path -LiteralPath $bundledPython) { $Python = $bundledPython }
            if ([string]::IsNullOrWhiteSpace($Python)) { $Python = 'python' }
        }
        Invoke-Checked { & $Python tools/verify.py }
    }
    if ($Benchmark) {
        $benchmarkState = Join-Path 'experiments/local' ('benchmark-' + [guid]::NewGuid().ToString('N'))
        Invoke-Checked { cargo run --locked -p symbiote-runtime --bin symbiote -- benchmark --state $benchmarkState --receipts experiments/local/benchmark.json }
    }
    if ($GitStatus) {
        Invoke-Checked { git status --short --branch }
        Invoke-Checked { git log -1 --oneline }
        Invoke-Checked { git remote -v }
    }
    if (-not ($Build -or $Run -or $Test -or $Verify -or $Benchmark -or $GitStatus)) {
        Write-Output 'SYMBIOTE-All-One.ps1 [-Build] [-Run] [-Test] [-Verify] [-Benchmark] [-GitStatus] [-State DIR] [-Python EXE]'
    }
}
finally { Set-Location -LiteralPath $repoRoot }
