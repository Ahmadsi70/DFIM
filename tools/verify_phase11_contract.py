"""Enforces Phase-11 TPM CI, recovery qualification, and UEFI capsule documentation."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "dfim_cli_provisioner/src/tpm.rs": {
        "DFIM_TPM_TCTI_ENV",
        "quote_attestation",
        "TPM_DEVICE_CANDIDATES",
        "/dev/tpmrm0",
        "create_attestation_key",
    },
    "dfim_cli_provisioner/src/attestation.rs": {
        "verify_attestation",
        "verifier_rejects_replayed_nonce",
        "ATTESTED_PCRS",
    },
    "dfim_cli_provisioner/src/recovery.rs": {
        "recover_target_atomically",
        "scalability_soak_recovers_many_assets",
        "sync_all",
    },
    "tools/run_swtpm_attestation_gate.sh": {
        "swtpm",
        "DFIM_TPM_TCTI",
        "attestation-enroll",
        "attestation-quote",
        "attestation-verify",
        "AT-07",
        "replay",
    },
    "tools/qualify_at08_power_loss.sh": {
        "AT-08",
        "power-loss",
        "recover-v2",
        "at08-evidence.jsonl",
    },
    "docs/security/PLATFORM_QUALIFICATION.md": {
        "AT-07",
        "AT-08",
        "swtpm",
        "UEFI_CAPSULE_RECOVERY.md",
    },
    "docs/security/UEFI_CAPSULE_RECOVERY.md": {
        "UpdateCapsule",
        "FMP",
        "authenticated",
        "dfim-uefi-x86_64",
    },
    "docs/security/REMOTE_ATTESTATION.md": {
        "attestation-enroll",
        "attestation-quote",
        "attestation-verify",
        "clockInfo.safe",
    },
    "docs/security/RECOVERY.md": {
        "power interruption",
        "DFIM_SOAK_ASSETS",
        "authenticated UEFI FMP capsule",
    },
    "docs/security/ADVERSARIAL_ACCEPTANCE.md": {
        "AT-07",
        "AT-08",
        "swtpm",
        "destructive power-loss",
    },
    "docs/security/RELEASE_MATURITY.md": {
        "Phase 11",
        "AT-07",
        "AT-08",
    },
    ".github/workflows/ci.yml": {
        "tpm-swtpm-gate",
        "run_swtpm_attestation_gate.sh",
        "verify_phase11_contract.py",
    },
    "test_environment/install_tpm_build_deps.sh": {
        "libtss2-dev",
    },
}


def validate_required_controls() -> None:
    """Requires TPM CI scripts and qualification docs to stay wired together."""
    for relative_path, tokens in REQUIRED.items():
        path = ROOT / relative_path
        if not path.is_file():
            raise ValueError(f"missing Phase-11 control: {relative_path}")
        text = path.read_text(encoding="utf-8")
        folded = text.casefold()
        missing = sorted(token for token in tokens if token.casefold() not in folded)
        if missing:
            raise ValueError(f"{relative_path} missing tokens: {missing}")


def main() -> int:
    """Runs the Phase-11 contract as a dependency-free local and CI gate."""
    try:
        validate_required_controls()
    except (OSError, ValueError) as error:
        print(f"PHASE11-CONTRACT: FAIL: {error}", file=sys.stderr)
        return 1
    print("PHASE11-CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
