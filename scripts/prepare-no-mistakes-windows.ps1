<#
prepare-no-mistakes-windows.ps1

Usage:
  - Edit the $RepoPath, $BranchName, and $KeyFilePath variables at top or pass as parameters.
  - Run in an elevated PowerShell session if needed.

What it does:
  - Ensures prerequisites (git, rustup/cargo) exist and warns if no-mistakes CLI is missing
  - Creates a feature branch and ensures DFIM_CRYPTO_KEY is set from a local secret file
  - Adds the key file to .gitignore (without committing the secret)
  - Runs Windows-target checks for DFIM (core engine and UEFI crate)
  - Commits incidental safe changes (like .gitignore)
  - Pushes the branch
  - If no-mistakes CLI is present, runs `no-mistakes doctor` and then `no-mistakes axi run` (interactive)
  - Saves no-mistakes output to no-mistakes-run.txt for later inspection

IMPORTANT:
  - Do NOT store DFIM_CRYPTO_KEY in git or commit it. Use a local file excluded by .gitignore or CI secrets.
  - If your org blocks no-mistakes via policy, the `axi run` step will fail. In that case ask your GitHub admin to permit the integration or run local validation only.
#>

param(
    [string]$RepoPath = "C:\Users\badri\DFIM",
    [string]$BranchName = "feature/no-mistakes-windows",
    [string]$KeyFilePath = "C:\Users\badri\.secrets\dfim_key.txt",
    [switch]$RunNoMistakes  # set if you want the script to attempt to run the CLI
)

function Fail($msg) {
    Write-Error $msg
    exit 1
}

function Ensure-Command($name) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    return $null -ne $cmd
}

Write-Host "=== prepare-no-mistakes-windows.ps1 ==="
Write-Host "RepoPath: $RepoPath"
Write-Host "BranchName: $BranchName"
Write-Host "KeyFilePath: $KeyFilePath"

# Check basic tooling
if (-not (Ensure-Command git)) { Fail 'git is not found in PATH. Install Git and retry.' }
if (-not (Ensure-Command cargo)) { Write-Warning 'cargo not found in PATH. Ensure Rust toolchain is installed before running checks.' }
if (-not (Ensure-Command rustup)) { Write-Warning 'rustup not found in PATH. Some target operations may fail.' }

# Ensure repo exists
if (-not (Test-Path $RepoPath)) {
    Fail "Repo path $RepoPath does not exist. Clone your repo first or adjust RepoPath."
}

Set-Location -Path $RepoPath

# Read repo remote info
$remote = git remote -v 2>$null
if ($LASTEXITCODE -ne 0) { Write-Warning 'Unable to read git remotes. Ensure this folder is a git repo.' }

# Ensure no secret is accidentally committed - copy key file into place and add to .gitignore
if (Test-Path $KeyFilePath) {
    $env:DFIM_CRYPTO_KEY = Get-Content -Raw -Path $KeyFilePath
    Write-Host "DFIM_CRYPTO_KEY loaded from $KeyFilePath (in-memory only)."
    # Make sure .gitignore contains the key file
    $gi = Join-Path $RepoPath '.gitignore'
    $relKey = [IO.Path]::GetFileName($KeyFilePath)
    if (Test-Path $gi) {
        $gitignoreText = Get-Content $gi -Raw
        if ($gitignoreText -notmatch [regex]::Escape($relKey)) {
            Add-Content -Path $gi -Value "`n# local secret used for DFIM build`n$relKey`n"
            Write-Host "Appended $relKey to .gitignore"
            git add .gitignore
            git commit -m "chore: add local DFIM key file to .gitignore" --no-verify
        } else {
            Write-Host ".gitignore already contains $relKey"
        }
    } else {
        "# local secret used for DFIM build`n$relKey`n" | Out-File -FilePath $gi -Encoding utf8
        git add .gitignore
        git commit -m "chore: add .gitignore and ignore local DFIM key file" --no-verify
        Write-Host "Created .gitignore and ignored $relKey"
    }
} else {
    Write-Warning "Key file $KeyFilePath not found. You must set DFIM_CRYPTO_KEY in your environment or create this file. The build steps will fail without the key."
}

# Create and switch to feature branch
$curr = git branch --show-current
if ($curr -eq $BranchName) {
    Write-Host "Already on branch $BranchName"
} else {
    git checkout -b $BranchName
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Branch may already exist locally, attempting to checkout"
        git checkout $BranchName
        if ($LASTEXITCODE -ne 0) {
            Fail "Could not create or checkout branch $BranchName"
        }
    }
}

# Add Windows targets and recommended components
if (Ensure-Command rustup) {
    Write-Host 'Ensuring Windows targets exist (x86_64-pc-windows-msvc, x86_64-unknown-uefi)'
    rustup target add x86_64-pc-windows-msvc 2>$null
    rustup target add x86_64-unknown-uefi 2>$null
    # Add nightly if required by UEFI tools (optional)
    # rustup toolchain install nightly
} else {
    Write-Warning 'rustup not installed; skipping rustup target add steps.'
}

# Run local checks (non-destructive)
Write-Host "Running local checks (cargo check) for core and windows crates..."

if (Ensure-Command cargo) {
    Write-Host 'cargo check -p dfim_core_engine --features full'
    cargo check -p dfim_core_engine --features full
    if ($LASTEXITCODE -ne 0) { Write-Warning 'dfim_core_engine check failed. Fix local build issues before running no-mistakes.' }

    Write-Host 'cargo check --target x86_64-pc-windows-msvc -p dfim_windows_uefi'
    cargo check --target x86_64-pc-windows-msvc -p dfim_windows_uefi
    if ($LASTEXITCODE -ne 0) { Write-Warning 'dfim_windows_uefi check (msvc) failed.' }

    Write-Host 'cargo check --target x86_64-unknown-uefi -p dfim_windows_uefi'
    cargo check --target x86_64-unknown-uefi -p dfim_windows_uefi
    if ($LASTEXITCODE -ne 0) { Write-Warning 'dfim_windows_uefi check (uefi) failed. UEFI cross-toolchain may be required.' }
} else {
    Write-Warning 'cargo not available; skipping cargo checks.'
}

# Stage safe commits if any (we only committed .gitignore above)
Write-Host 'Pushing branch to origin (if remote configured)'
$push = git push -u origin $BranchName
if ($LASTEXITCODE -ne 0) { Write-Warning 'git push failed — check remote configuration and credentials (SSH key or PAT)'; }

# Optionally run no-mistakes
if ($RunNoMistakes) {
    if (-not (Ensure-Command 'no-mistakes')) {
        Write-Warning 'no-mistakes CLI not found in PATH; skipping no-mistakes steps. Install it and re-run with -RunNoMistakes to proceed.'
    } else {
        Write-Host 'Running no-mistakes doctor...'
        no-mistakes doctor
        Write-Host 'Starting no-mistakes run (this will block until the first gate or completion). Output will be saved to no-mistakes-run.txt'
        $intent = 'Validate DFIM for Windows (UEFI) and resolve platform-specific build blockers'
        no-mistakes axi run --intent "$intent" 2>&1 | Tee-Object -FilePath no-mistakes-run.txt

        # Quick heuristic: look for gate: or Access to this feature is blocked
        $out = Get-Content -Raw -Path no-mistakes-run.txt
        if ($out -match 'Access to this feature is blocked') {
            Write-Warning 'no-mistakes run failed due to organization policy blocking GitHub-side features. Contact your GitHub org admin to permit this integration.'
        } elseif ($out -match '^gate:' -or $out -match 'gate:') {
            Write-Host 'no-mistakes run reached a gate. Inspect no-mistakes-run.txt and use `no-mistakes axi status` and `no-mistakes axi respond` to continue.'
        } else {
            Write-Host 'no-mistakes run completed or returned without a gate. Check no-mistakes-run.txt for details.'
        }
    }
} else {
    Write-Host 'Skipping no-mistakes CLI run. Re-run script with -RunNoMistakes to attempt pipeline execution.'
}

Write-Host 'Done. Important next steps:'
Write-Host ' - Inspect no-mistakes-run.txt if you ran the CLI.'
Write-Host ' - If a gate appears, run: no-mistakes axi status and respond with axi respond --action <approve|fix|skip> as appropriate.'
Write-Host ' - Do NOT commit DFIM_CRYPTO_KEY or key files to git.'

# End of script
