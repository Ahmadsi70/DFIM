#Requires -Version 5.1
<#
.SYNOPSIS
    Build Windows DFIM release artifacts (provisioner + UEFI boot guard).
.DESCRIPTION
    Produces dfim-provisioner.exe and dfim_windows_uefi.efi, staging them to
    the Ooredoo Windows bin/ directory resolved relative to the DFIM workspace.
#>
param(
    [string]$StageDir,
    [switch]$SkipUefi
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RootDir = $PSScriptRoot

function Write-Info([string]$Msg)  { Write-Host "[INFO] $Msg" -ForegroundColor Cyan }
function Write-Pass([string]$Msg)  { Write-Host "[PASS] $Msg" -ForegroundColor Green }
function Write-Fail([string]$Msg)  { Write-Host "[FAIL] $Msg" -ForegroundColor Red; exit 1 }

function Resolve-DefaultStageDir {
    if ($env:DFIM_OOREDOO_ROOT -and (Test-Path -LiteralPath $env:DFIM_OOREDOO_ROOT)) {
        return Join-Path $env:DFIM_OOREDOO_ROOT 'Ooredoo Windows\bin'
    }
    $siblingOoredoo = Join-Path (Split-Path -Parent $RootDir) 'Ooredoo'
    return Join-Path $siblingOoredoo 'Ooredoo Windows\bin'
}

if (-not $StageDir) {
    $StageDir = Resolve-DefaultStageDir
}

Write-Info "DFIM Windows release build"
Write-Info "Workspace: $RootDir"
Write-Info "Stage dir: $StageDir"

if (-not $env:DFIM_CRYPTO_KEY) {
    Write-Fail 'DFIM_CRYPTO_KEY must be set (min 16 bytes). Example: $env:DFIM_CRYPTO_KEY = -join ((1..32 | ForEach-Object { ''{0:x2}'' -f (Get-Random -Max 256) }))'
}
if ($env:DFIM_CRYPTO_KEY.Length -lt 16) {
    Write-Fail 'DFIM_CRYPTO_KEY must be at least 16 bytes'
}

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Fail 'cargo not found in PATH'
}

$env:SOURCE_DATE_EPOCH = if ($env:SOURCE_DATE_EPOCH) { $env:SOURCE_DATE_EPOCH } else { '946684800' }
$env:CARGO_INCREMENTAL = '0'

Push-Location $RootDir
try {
    Write-Info 'Building dfim-provisioner (release, production feature)'
    cargo build --release -p dfim_cli_provisioner --features production
    if ($LASTEXITCODE -ne 0) { Write-Fail "cargo build provisioner failed (exit $LASTEXITCODE)" }

    $ProvisionerSrc = Join-Path $RootDir 'target\release\dfim-provisioner.exe'
    if (-not (Test-Path -LiteralPath $ProvisionerSrc)) {
        Write-Fail "Missing release binary: $ProvisionerSrc"
    }

    if (-not $SkipUefi) {
        Write-Info 'Ensuring UEFI target: x86_64-unknown-uefi'
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        rustup target add x86_64-unknown-uefi 2>&1 | Out-Null
        $ErrorActionPreference = $prevEap

        Write-Info 'Building dfim_windows_uefi.efi (release, uefi-app feature)'
        cargo build --release -p dfim_windows_uefi --features uefi-app --target x86_64-unknown-uefi
        if ($LASTEXITCODE -ne 0) { Write-Fail "cargo build UEFI failed (exit $LASTEXITCODE)" }
    }

    if (-not (Test-Path -LiteralPath $StageDir)) {
        New-Item -ItemType Directory -Path $StageDir -Force | Out-Null
    }

    Copy-Item -LiteralPath $ProvisionerSrc -Destination (Join-Path $StageDir 'dfim-provisioner.exe') -Force
    Write-Pass "Staged dfim-provisioner.exe -> $StageDir"

    if (-not $SkipUefi) {
        $UefiSrc = Join-Path $RootDir 'target\x86_64-unknown-uefi\release\dfim_windows_uefi.efi'
        if (-not (Test-Path -LiteralPath $UefiSrc)) {
            Write-Fail "Missing UEFI binary: $UefiSrc"
        }
        Copy-Item -LiteralPath $UefiSrc -Destination (Join-Path $StageDir 'dfim_windows_uefi.efi') -Force
        Write-Pass "Staged dfim_windows_uefi.efi -> $StageDir"
    }

    Write-Pass 'Windows release build complete'
} finally {
    Pop-Location
}
