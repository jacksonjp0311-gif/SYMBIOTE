[CmdletBinding()]
param(
    [switch]$Build,
    [switch]$Run,
    [switch]$Test,
    [switch]$Verify,
    [switch]$Benchmark,
    [switch]$Research,
    [switch]$NetworkResearch,
    [switch]$InspectState,
    [switch]$Recover,
    [switch]$Migrate,
    [switch]$Doctor,
    [switch]$Install,
    [switch]$Json,
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

function Invoke-Symbiote([string[]]$Arguments) {
    $commandArguments = @($Arguments)
    if ($Json) { $commandArguments += '--json' }
    Invoke-Checked { cargo run --release --locked -q -p symbiote-runtime --bin symbiote -- @commandArguments }
}

try {
    if ($Build) { Invoke-Checked { cargo build --workspace --release --locked } }
    if ($InspectState) { Invoke-Symbiote -Arguments @('inspect-state', '--state', $State) }
    if ($Recover) { Invoke-Symbiote -Arguments @('recover', '--state', $State) }
    if ($Migrate) { Invoke-Symbiote -Arguments @('migrate', '--state', $State) }
    if ($Run) { Invoke-Symbiote -Arguments @('demo', '--state', $State) }
    if ($Research) { Invoke-Symbiote -Arguments @('research', '--state', $State) }
    if ($NetworkResearch) { Invoke-Symbiote -Arguments @('network-research', '--state', $State) }
    if ($Doctor) { Invoke-Symbiote -Arguments @('doctor', '--state', $State) }
    if ($Install) { & (Join-Path $repoRoot 'tools/install.ps1') -FromSource; if ($LASTEXITCODE -ne 0) { throw 'Installation failed' } }
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
        Invoke-Symbiote -Arguments @('benchmark', '--state', $benchmarkState, '--receipts', 'experiments/local/benchmark.json')
    }
    if ($GitStatus) {
        Invoke-Checked { git status --short --branch }
        Invoke-Checked { git log -1 --oneline }
        Invoke-Checked { git remote -v }
    }
    if (-not ($Build -or $Run -or $Test -or $Verify -or $Benchmark -or $Research -or $NetworkResearch -or $InspectState -or $Recover -or $Migrate -or $Doctor -or $Install -or $GitStatus)) {
        Write-Output 'SYMBIOTE - native reasoning, evaluated learning, reciprocal exchange'
        Write-Output ''
        Write-Output 'Start:      .\SYMBIOTE-All-One.ps1 -Run'
        Write-Output 'Research:   .\SYMBIOTE-All-One.ps1 -Research'
        Write-Output 'Processes:  .\SYMBIOTE-All-One.ps1 -NetworkResearch'
        Write-Output 'Check:      .\SYMBIOTE-All-One.ps1 -Doctor'
        Write-Output 'Verify:     .\SYMBIOTE-All-One.ps1 -Verify'
        Write-Output 'Install:    .\SYMBIOTE-All-One.ps1 -Install'
        Write-Output ''
        Write-Output 'State: -InspectState -Recover -Migrate -State DIR'
        Write-Output 'Other switches: -Build -Test -Benchmark -GitStatus -Json -Python EXE'
    }
}
finally { Set-Location -LiteralPath $repoRoot }
