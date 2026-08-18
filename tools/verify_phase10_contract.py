"""Enforces Phase-10 cross-platform attested release and eBPF compile-check controls."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    ".github/workflows/release.yml": {
        "linux-release",
        "windows-release",
        "uefi-release",
        "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
        "dfim-linux-x86_64.tar.gz",
        "dfim-windows-x86_64.zip",
        "dfim-uefi-x86_64.tar.gz",
        "runs-on: windows-latest",
        "--features production",
    },
    ".github/workflows/ci.yml": {
        "linux-ebpf-compile",
        "DFIM_ALLOW_UNVERIFIED_BTF_FALLBACK",
        "verify_phase10_contract.py",
    },
    "package_windows_release.ps1": {
        "dfim-windows-x86_64.zip",
        "RELEASE_SHA256SUMS",
        "build_windows_release.ps1",
    },
    "package_uefi_release.sh": {
        "dfim-uefi-x86_64.tar.gz",
        "x86_64-unknown-uefi",
        "uefi-app",
        "RELEASE_SHA256SUMS",
    },
    "build_windows_release.ps1": {
        "--features production",
    },
    "docs/security/CROSS_PLATFORM_RELEASE.md": {
        "dfim-linux-x86_64",
        "dfim-windows-x86_64",
        "dfim-uefi-x86_64",
        "gh attestation verify",
        "SLSA",
    },
    "docs/security/RELEASE_MATURITY.md": {
        "Phase 10",
        "cross-platform attested",
    },
}
ACTION_REFERENCE = re.compile(
    r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}(?:\s*#.*)?$"
)


def validate_required_controls() -> None:
    """Requires release workflows and packaging scripts to stay coupled."""
    for relative_path, tokens in REQUIRED.items():
        path = ROOT / relative_path
        if not path.is_file():
            raise ValueError(f"missing Phase-10 control: {relative_path}")
        text = path.read_text(encoding="utf-8")
        folded = text.casefold()
        missing = sorted(token for token in tokens if token.casefold() not in folded)
        if missing:
            raise ValueError(f"{relative_path} missing tokens: {missing}")


def validate_release_workflow_pinning() -> None:
    """Release workflow must not introduce mutable GitHub Action references."""
    path = ROOT / ".github" / "workflows" / "release.yml"
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip().startswith("uses:"):
            continue
        reference = line.split("uses:", 1)[1].strip()
        if reference.startswith(("./", "docker://")):
            continue
        if not ACTION_REFERENCE.match(reference):
            raise ValueError(
                f"release.yml:{line_number} mutable action reference: {reference}"
            )


def main() -> int:
    """Runs the Phase-10 contract as a dependency-free local and CI gate."""
    try:
        validate_required_controls()
        validate_release_workflow_pinning()
    except (OSError, ValueError) as error:
        print(f"PHASE10-CONTRACT: FAIL: {error}", file=sys.stderr)
        return 1
    print("PHASE10-CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
