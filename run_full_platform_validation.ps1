#Requires -Version 5.1
<#
.SYNOPSIS
    Full DFIM platform validation — Windows native + optional WSL Linux on a Windows host.
.DESCRIPTION
    Builds release binaries, runs cargo test, executes Windows master suite + stress,
    then optionally delegates Linux master suite and kernel integration via WSL.
#>
param(
    [switch]$SkipBuild,
    [switch]$SkipLinux,
    [switch]$SkipUefi,
    [switch]$WindowsOnly,
    [int]$MerkleSlaMs = 5000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$DfimRoot = $PSScriptRoot

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

$DeliveryRoot   = Resolve-DeliveryRoot
$WinTestRoot   = Join-Path $DeliveryRoot 'DFIM Windows\test_environment'
$LinuxTestRoot = Join-Path $DeliveryRoot 'DFIM Linux\test_environment'
$LinuxBinDir   = Join-Path $DeliveryRoot 'DFIM Linux\bin'
$SummaryLog    = Join-Path $DfimRoot 'test_environment\logs\full_validation.jsonl'

if ($WindowsOnly) { $SkipLinux = $true }

. (Join-Path $WinTestRoot 'tools\dfim_test_lib.ps1')

function Write-Phase([string]$Title) {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
}

function Write-Pass([string]$Msg) { Write-Host "  [PASS] $Msg" -ForegroundColor Green }
function Write-Fail([string]$Msg) { Write-Host "  [FAIL] $Msg" -ForegroundColor Red; exit 1 }

function Invoke-Phase {
    param(
        [Parameter(Mandatory)][string]$PhaseId,
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    Write-Phase $Label
    $phaseExit = 0
    try {
        & $Action
        if ($null -ne $LASTEXITCODE) {
            $phaseExit = [int]$LASTEXITCODE
        }
    } catch {
        Write-DfimJsonLog -LogFile $SummaryLog -TestId $PhaseId -Status 'FAIL' -Detail $_.Exception.Message -ExitCode 1
        Write-Fail "$Label - $($_.Exception.Message)"
    }
    if ($phaseExit -ne 0) {
        Write-DfimJsonLog -LogFile $SummaryLog -TestId $PhaseId -Status 'FAIL' -Detail "exit $phaseExit" -ExitCode $phaseExit
        Write-Fail "$Label failed (exit $phaseExit)"
    }
    Write-DfimJsonLog -LogFile $SummaryLog -TestId $PhaseId -Status 'PASS' -Detail 'completed'
    Write-Pass $Label
}

function Ensure-CryptoKey {
    if (-not $env:DFIM_CRYPTO_KEY) {
        $bytes = New-Object byte[] 32
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
        $env:DFIM_CRYPTO_KEY = [BitConverter]::ToString($bytes).Replace('-', '').ToLower()
        Write-Host "  [INFO] Generated ephemeral DFIM_CRYPTO_KEY for this session" -ForegroundColor Gray
    }
    if ($env:DFIM_CRYPTO_KEY.Length -lt 16) {
        Write-Fail 'DFIM_CRYPTO_KEY must be at least 16 bytes'
    }
}

function Invoke-WslPhase {
    param(
        [Parameter(Mandatory)][string]$Command
    )
    if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
        throw 'WSL not available'
    }
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        wsl bash -lc $Command 2>&1 | ForEach-Object {
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                Write-Host $_.ToString()
            } else {
                Write-Host $_
            }
        }
        $exitCode = $LASTEXITCODE
        if ($null -eq $exitCode) { $exitCode = 0 }
        if ($exitCode -ne 0) {
            throw "WSL command failed (exit $exitCode)"
        }
    } finally {
        $ErrorActionPreference = $prevEap
    }
}

Write-Phase 'DFIM FULL PLATFORM VALIDATION (Windows Host)'
Ensure-CryptoKey

$fixturePath = Join-Path $WinTestRoot 'fixtures\demo_boot_image.bin'
Ensure-DfimBootFixture -FixturePath $fixturePath

if (-not $SkipBuild) {
    Invoke-Phase -PhaseId 'PHASE-BUILD-WIN' -Label 'Build Windows release (provisioner + UEFI)' -Action {
        if ($SkipUefi) {
            & (Join-Path $DfimRoot 'build_windows_release.ps1') -SkipUefi
        } else {
            & (Join-Path $DfimRoot 'build_windows_release.ps1')
        }
    }

    if (-not $SkipLinux) {
        Invoke-Phase -PhaseId 'PHASE-BUILD-LIN' -Label 'Build Linux release via WSL' -Action {
            $wslRoot = Convert-ToWslPath -WindowsPath $DfimRoot
            $wslBin  = Convert-ToWslPath -WindowsPath $LinuxBinDir
            $key = $env:DFIM_CRYPTO_KEY
            $cmd = "export DFIM_CRYPTO_KEY='${key}'; cd '${wslRoot}'; cargo build --release -p dfim_cli_provisioner -p dfim-ebpf-user; mkdir -p '${wslBin}'; cp target/release/dfim-provisioner '${wslBin}/'; cp target/release/dfim-ebpf-user '${wslBin}/'; chmod +x '${wslBin}/dfim-provisioner' '${wslBin}/dfim-ebpf-user'"
            Invoke-WslPhase -Command $cmd
        }
    }
}

if (-not $SkipLinux) {
    Invoke-Phase -PhaseId 'PHASE-CARGO-TEST' -Label 'cargo test (workspace, WSL)' -Action {
        $wslRoot = Convert-ToWslPath -WindowsPath $DfimRoot
        Invoke-WslPhase -Command "export DFIM_CRYPTO_KEY='$($env:DFIM_CRYPTO_KEY)'; cd '$wslRoot'; cargo test -p dfim_core_engine -p dfim_cli_provisioner -p dfim_host_init -p dfim_windows_uefi 2>&1 | tail -25"
    }
}

Invoke-Phase -PhaseId 'PHASE-WIN-MASTER' -Label 'Windows master test suite' -Action {
    & (Join-Path $WinTestRoot 'test_all_features.ps1')
}

Invoke-Phase -PhaseId 'PHASE-WIN-STRESS' -Label 'Windows real stress test (verify telemetry)' -Action {
    & (Join-Path $WinTestRoot 'run_stress_test.ps1') -NonInteractive -MerkleSlaMs $MerkleSlaMs
}

if (-not $SkipLinux) {
    Invoke-Phase -PhaseId 'PHASE-LIN-MASTER' -Label 'Linux master test (WSL)' -Action {
        $wslScript = Convert-ToWslPath -WindowsPath (Join-Path $LinuxTestRoot 'test_all_features.sh')
        $key = $env:DFIM_CRYPTO_KEY
        $cmd = "sed -i 's/\r`$//' '${wslScript}'; chmod +x '${wslScript}'; export DFIM_CRYPTO_KEY='${key}'; bash '${wslScript}'"
        Invoke-WslPhase -Command $cmd
    }

    Invoke-Phase -PhaseId 'PHASE-LIN-KERNEL' -Label 'Linux kernel integration stress (WSL)' -Action {
        & (Join-Path $LinuxTestRoot 'run_linux_stress_test.ps1')
    }
}

Write-Phase 'VALIDATION COMPLETE'
Write-Pass "All phases passed - telemetry: $SummaryLog"
if (Test-Path -LiteralPath $SummaryLog) {
    Get-Content -LiteralPath $SummaryLog | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
}
exit 0
