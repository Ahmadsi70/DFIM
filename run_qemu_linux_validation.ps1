#Requires -Version 5.1
<#
.SYNOPSIS
  One-click DFIM Linux (musl) build + QEMU validation harness for Windows hosts.

.DESCRIPTION
  Sets DFIM_CRYPTO_KEY, invokes tools/qemu_linux_harness.py, and surfaces JSONL compliance output.
#>
param(
    [int]$DiskMb = 512,
    [int]$TimeoutSec = 600,
    [string]$WorkDir = ''
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Info([string]$Message) { Write-Host "[qemu-ps1] $Message" -ForegroundColor Cyan }
function Write-Pass([string]$Message) { Write-Host "[PASS] $Message" -ForegroundColor Green }
function Write-Fail([string]$Message) { Write-Host "[FAIL] $Message" -ForegroundColor Red; exit 1 }

if (-not $env:DFIM_CRYPTO_KEY) {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $env:DFIM_CRYPTO_KEY = ([BitConverter]::ToString($bytes) -replace '-', '').ToLower()
    Write-Info 'Generated ephemeral DFIM_CRYPTO_KEY for harness run'
}

$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    $python = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $python) {
    Write-Fail 'Python 3 is required (python or python3 on PATH)'
}

foreach ($tool in @('qemu-system-x86_64', 'qemu-img', 'cargo', 'rustup')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Fail "Missing required tool: $tool"
    }
}

$argsList = @("$Root\tools\qemu_linux_harness.py", '--disk-mb', $DiskMb, '--timeout', $TimeoutSec)
if ($WorkDir) {
    $argsList += @('--work-dir', $WorkDir)
}

Write-Info "Starting QEMU harness (disk=${DiskMb}MB timeout=${TimeoutSec}s)"
& $python.Source @argsList
if ($LASTEXITCODE -ne 0) {
    Write-Fail "QEMU harness exited with code $LASTEXITCODE"
}

$jsonl = if ($WorkDir) {
    Join-Path $WorkDir 'host_share\dfim_qemu_compliance.jsonl'
} else {
    Get-ChildItem -Path (Join-Path $Root 'target') -Filter 'dfim_qemu_*' -Directory -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1 |
        ForEach-Object { Join-Path $_.FullName 'host_share\dfim_qemu_compliance.jsonl' }
}

if ($jsonl -and (Test-Path -LiteralPath $jsonl)) {
    Write-Pass "Compliance JSONL: $jsonl"
    Get-Content -LiteralPath $jsonl | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Info 'JSONL path not resolved; check target/dfim_qemu_*/host_share/'
}

Write-Pass 'Linux QEMU validation complete'
