# ECH Proxy Build Script for Windows
# Run this script from PowerShell (not Git Bash)

$ErrorActionPreference = "Stop"

# Find Visual Studio installation
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -property installationPath
    if ($vsPath) {
        Write-Host "Found Visual Studio at: $vsPath" -ForegroundColor Green

        # Import VS environment
        $vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
        if (Test-Path $vcvars) {
            Write-Host "Setting up MSVC environment..." -ForegroundColor Yellow

            # Run vcvars64.bat and capture environment
            $envOutput = cmd /c "`"$vcvars`" && set"
            foreach ($line in $envOutput) {
                if ($line -match "^([^=]+)=(.*)$") {
                    [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
                }
            }
            Write-Host "MSVC environment ready" -ForegroundColor Green
        }
    }
}

# Check if cargo is available
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "Error: cargo not found. Please install Rust." -ForegroundColor Red
    exit 1
}

Write-Host "`nBuilding ECH Proxy..." -ForegroundColor Cyan

# Build
Set-Location $PSScriptRoot
cargo build --release

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nBuild successful!" -ForegroundColor Green
    Write-Host "Binary: target\release\ech_proxy_bin.exe" -ForegroundColor White
} else {
    Write-Host "`nBuild failed!" -ForegroundColor Red
    exit 1
}
