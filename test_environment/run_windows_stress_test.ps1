#Requires -Version 5.1
<#
.SYNOPSIS
    DFIM Windows stress-test launcher — runs real verify telemetry harness.
.NOTES
    Full matrix: ..\run_full_platform_validation.ps1 -WindowsOnly (DFIM workspace root)
#>
param(
    [switch]$NonInteractive,
    [switch]$FullValidation
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$DfimRoot = Split-Path -Parent $PSScriptRoot

function Resolve-DeliveryRoot {
    if ($env:DFIM_DELIVERY_ROOT -and (Test-Path -LiteralPath $env:DFIM_DELIVERY_ROOT)) {
        return (Resolve-Path -LiteralPath $env:DFIM_DELIVERY_ROOT).Path
    }
    $sibling = Join-Path (Split-Path -Parent $DfimRoot) 'DFIM_Delivery'
    if (-not (Test-Path -LiteralPath $sibling)) {
        throw 'DFIM delivery root not found. Set DFIM_DELIVERY_ROOT.'
    }
    return (Resolve-Path -LiteralPath $sibling).Path
}

if ($FullValidation) {
    & (Join-Path $DfimRoot 'run_full_platform_validation.ps1') -WindowsOnly
    exit $LASTEXITCODE
}

$DeliveryRoot = Resolve-DeliveryRoot
$CanonicalScript = Join-Path $DeliveryRoot 'DFIM Windows\test_environment\run_stress_test.ps1'

if (-not (Test-Path -LiteralPath $CanonicalScript)) {
    Write-Error "Stress test script not found: $CanonicalScript"
    exit 1
}

if ($NonInteractive) {
    & $CanonicalScript -NonInteractive
} else {
    & $CanonicalScript
}
exit $LASTEXITCODE
