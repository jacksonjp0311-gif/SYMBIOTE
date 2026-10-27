[CmdletBinding()]
param(
    [string]$Version = 'latest',
    [string]$InstallDir = '',
    [string]$BundleDirectory = '',
    [switch]$FromSource,
    [switch]$AddToPath
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Use tools/install.sh on Linux or macOS.' }
if ($FromSource -and -not [string]::IsNullOrWhiteSpace($BundleDirectory)) { throw '-FromSource and -BundleDirectory cannot be combined.' }
if (-not [string]::IsNullOrWhiteSpace($BundleDirectory) -and $Version -eq 'latest') { throw '-BundleDirectory requires an explicit -Version tag.' }
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
if ([string]::IsNullOrWhiteSpace($InstallDir)) { $InstallDir = Join-Path $env:LOCALAPPDATA 'SYMBIOTE/bin' }
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$temporary = $null
try {
    if ($FromSource) {
        $manifest = Join-Path $PSScriptRoot '../crates/symbiote-runtime/Cargo.toml'
        if (-not (Test-Path -LiteralPath $manifest)) { throw 'Source installation requires a SYMBIOTE checkout.' }
        if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { throw 'Install Rust/Cargo first, or run this installer without -FromSource to use a verified release binary.' }
        $temporary = Join-Path ([System.IO.Path]::GetTempPath()) ('symbiote-install-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $temporary | Out-Null
        & cargo install --path (Split-Path -Parent $manifest) --locked --root $temporary --force
        if ($LASTEXITCODE -ne 0) { throw "Cargo installation failed ($LASTEXITCODE)." }
        & (Join-Path $temporary 'bin/symbiote.exe') --version
        if ($LASTEXITCODE -ne 0) { throw 'The staged source binary failed its version check.' }
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $temporary 'bin/symbiote.exe') -Destination (Join-Path $InstallDir 'symbiote.exe') -Force
    }
    if (-not $FromSource) {
        if ($env:OS -ne 'Windows_NT') { throw 'Use tools/install.sh on Linux or macOS.' }
        if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne [System.Runtime.InteropServices.Architecture]::X64) { throw 'The Windows release binary currently supports x64 only. Build from source on this architecture.' }
        if ($Version -eq 'latest') {
            $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/jacksonjp0311-gif/SYMBIOTE/releases/latest' -Headers @{ Accept = 'application/vnd.github+json'; 'User-Agent' = 'SYMBIOTE-installer' }
            $Version = $release.tag_name
        }
        if ($Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') { throw 'Version must be a release tag such as v0.2.0.' }
        $asset = "symbiote-$Version-x86_64-pc-windows-msvc.zip"
        $baseUri = "https://github.com/jacksonjp0311-gif/SYMBIOTE/releases/download/$Version"
        $temporary = Join-Path ([System.IO.Path]::GetTempPath()) ('symbiote-install-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $temporary | Out-Null
        $archive = Join-Path $temporary $asset
        $manifestPath = Join-Path $temporary 'SHA256SUMS'
        try {
            if ([string]::IsNullOrWhiteSpace($BundleDirectory)) {
                Invoke-WebRequest -Uri "$baseUri/$asset" -OutFile $archive
                Invoke-WebRequest -Uri "$baseUri/SHA256SUMS" -OutFile $manifestPath
            }
            if (-not [string]::IsNullOrWhiteSpace($BundleDirectory)) {
                Copy-Item -LiteralPath (Join-Path $BundleDirectory $asset) -Destination $archive
                Copy-Item -LiteralPath (Join-Path $BundleDirectory 'SHA256SUMS') -Destination $manifestPath
            }
        }
        catch { throw "Release $Version does not provide a complete verified Windows bundle, or its download failed. Use -FromSource from a checkout. $($_.Exception.Message)" }
        $expected = @()
        foreach ($line in Get-Content -LiteralPath $manifestPath -Encoding UTF8) {
            if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+)$' -and $Matches[2] -eq $asset) { $expected += $Matches[1].ToLowerInvariant() }
        }
        if ($expected.Count -ne 1) { throw 'Checksum manifest must contain exactly one matching bundle.' }
        $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected[0]) { throw 'SHA256 mismatch. No binary was installed.' }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
        try {
            $entries = @($zip.Entries)
            $executables = @($entries | Where-Object { $_.FullName -eq 'symbiote.exe' })
            if ($executables.Count -ne 1) { throw 'Bundle must contain exactly one symbiote.exe.' }
            foreach ($entry in $entries) {
                if ($entry.FullName -notin @('symbiote.exe', 'LICENSE', 'README.md')) { throw "Unsupported or unsafe archive entry: $($entry.FullName)" }
                if ($entry.Length -gt 100MB) { throw 'Archive entry exceeds installation limits.' }
            }
            $staged = Join-Path $temporary 'symbiote.exe'
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($executables[0], $staged, $false)
            $stagedVersion = & $staged --version
            if ($LASTEXITCODE -ne 0 -or ($stagedVersion -join "`n").Trim() -ne "SYMBIOTE $($Version.Substring(1))") { throw 'Staged executable version does not match its release tag; nothing installed.' }
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
            Copy-Item -LiteralPath $staged -Destination (Join-Path $InstallDir 'symbiote.exe') -Force
        }
        finally { $zip.Dispose() }
    }
    $installedBinary = Join-Path $InstallDir 'symbiote.exe'
    if (-not (Test-Path -LiteralPath $installedBinary)) { throw "Expected installed binary missing: $installedBinary" }
    & $installedBinary --version
    if ($LASTEXITCODE -ne 0) { throw 'The installed binary failed its version check.' }
    if ($AddToPath) {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        $parts = @($userPath -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($InstallDir.TrimEnd('\') -notin @($parts | ForEach-Object { $_.TrimEnd('\') })) { [Environment]::SetEnvironmentVariable('Path', (($parts + $InstallDir) -join ';'), 'User') }
        if ($InstallDir.TrimEnd('\') -notin @($env:Path -split ';' | ForEach-Object { $_.TrimEnd('\') })) { $env:Path = "$InstallDir;$env:Path" }
    }
    Write-Output "Installed: $installedBinary"
    Write-Output "Try: & '$installedBinary' demo"
    if (-not $AddToPath) { Write-Output 'Use -AddToPath to make symbiote available in future terminals.' }
}
finally {
    if ($null -ne $temporary -and (Test-Path -LiteralPath $temporary)) {
        $resolvedTemporary = [System.IO.Path]::GetFullPath($temporary)
        $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
        if (-not $resolvedTemporary.StartsWith($resolvedTempRoot, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing cleanup outside the installer temporary directory.' }
        Remove-Item -LiteralPath $resolvedTemporary -Recurse -Force
    }
}
