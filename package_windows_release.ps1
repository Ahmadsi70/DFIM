#Requires -Version 5.1
<#
.SYNOPSIS
    Build and package attested Windows release artifacts for CI and local release.
.DESCRIPTION
    Produces dfim-windows-x86_64.zip with provisioner, UEFI guard, LICENSE, and SHA256 sums.
#>
param(
    [string]$DistDir = "dist-windows",
    [string]$ArchiveName = "dfim-windows-x86_64.zip",
    [switch]$SkipUefi,
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RootDir = $PSScriptRoot

function Write-Info([string]$Msg)  { Write-Host "[INFO] $Msg" -ForegroundColor Cyan }
function Write-Pass([string]$Msg)  { Write-Host "[PASS] $Msg" -ForegroundColor Green }
function Write-Fail([string]$Msg)  { Write-Host "[FAIL] $Msg" -ForegroundColor Red; exit 1 }

if (-not $env:DFIM_CRYPTO_KEY) {
    Write-Fail 'DFIM_CRYPTO_KEY must be set (min 16 bytes)'
}
if ($env:DFIM_CRYPTO_KEY.Length -lt 16) {
    Write-Fail 'DFIM_CRYPTO_KEY must be at least 16 bytes'
}

$env:SOURCE_DATE_EPOCH = if ($env:SOURCE_DATE_EPOCH) { $env:SOURCE_DATE_EPOCH } else { '946684800' }
$env:CARGO_INCREMENTAL = '0'

Push-Location $RootDir
try {
    if (-not $SkipBuild) {
        $buildArgs = @(
            '-File', (Join-Path $RootDir 'build_windows_release.ps1'),
            '-StageDir', (Join-Path $RootDir $DistDir)
        )
        if ($SkipUefi) { $buildArgs += '-SkipUefi' }
        & powershell @buildArgs
        if ($LASTEXITCODE -ne 0) { Write-Fail "build_windows_release.ps1 failed (exit $LASTEXITCODE)" }
    }

    $bundleRoot = Join-Path $RootDir $DistDir
    if (-not (Test-Path -LiteralPath $bundleRoot)) {
        Write-Fail "Missing bundle directory: $bundleRoot"
    }

    Copy-Item -LiteralPath (Join-Path $RootDir 'LICENSE') -Destination (Join-Path $bundleRoot 'LICENSE') -Force

    $hashLines = @()
    Get-ChildItem -LiteralPath $bundleRoot -File |
        Where-Object { $_.Name -ne 'RELEASE_SHA256SUMS' } |
        Sort-Object Name |
        ForEach-Object {
            $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            $hashLines += "$hash  $($_.Name)"
        }
    Set-Content -LiteralPath (Join-Path $bundleRoot 'RELEASE_SHA256SUMS') -Value $hashLines -Encoding ascii

    $archivePath = Join-Path $RootDir $ArchiveName
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }
    $filesToZip = @(
        (Join-Path $bundleRoot 'LICENSE'),
        (Join-Path $bundleRoot 'RELEASE_SHA256SUMS'),
        (Join-Path $bundleRoot 'dfim-provisioner.exe')
    )
    if (-not $SkipUefi) {
        $filesToZip += (Join-Path $bundleRoot 'dfim_windows_uefi.efi')
    }
    Compress-Archive -LiteralPath $filesToZip -DestinationPath $archivePath -Force

    Write-Pass "Packaged $ArchiveName"
    Write-Output $archivePath
} finally {
    Pop-Location
}
