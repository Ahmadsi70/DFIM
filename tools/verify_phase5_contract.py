"""Validates DFIM's authenticated recovery and scalability gates."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "docs/security/RECOVERY.md": {
        "NIST SP 800-193",
        "DFIMBOOT v2",
        "sidecar-first",
        "fail-closed",
        "RTO",
        "RPO",
    },
    "dfim_cli_provisioner/src/recovery.rs": {
        "recover_target_atomically",
        "validate_signed_boot_image_v2",
        "sync_all",
        "scalability_soak_recovers_many_assets",
    },
    "dfim_cli_provisioner/src/main.rs": {"RecoverV2", "DFIM-RECOVERY: PASS"},
    ".github/workflows/ci.yml": {
        "verify_phase5_contract.py",
        "scalability_soak_recovers_many_assets",
        "DFIM_SOAK_ASSETS",
        "DFIM_SOAK_CYCLES",
    },
}


def validate() -> None:
    """Requires executable controls and their operating contract."""
    for relative_path, tokens in REQUIRED.items():
        path = ROOT / relative_path
        if not path.is_file():
            raise ValueError(f"missing Phase-5 control: {relative_path}")
        text = path.read_text(encoding="utf-8")
        missing = sorted(token for token in tokens if token not in text)
        if missing:
            raise ValueError(f"{relative_path} missing tokens: {missing}")


def main() -> int:
    """Runs the Phase-5 contract as a local and CI gate."""
    try:
        validate()
    except (OSError, ValueError) as error:
        print(f"PHASE5-CONTRACT: FAIL: {error}", file=sys.stderr)
        return 1
    print("PHASE5-CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
