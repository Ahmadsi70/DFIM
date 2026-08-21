"""Enforces Phase-8 production packaging, audit, automation, and Windows CI controls."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "dfim_host_init/src/lib.rs": {
        "enforce_host_gate",
        "host_gate_required",
        "DFIM_PRODUCTION",
        'cfg!(feature = "production")',
    },
    "dfim_host_init/Cargo.toml": {
        "production = []",
    },
    "dfim_cli_provisioner/Cargo.toml": {
        'production = ["dfim_host_init/production"]',
    },
    "dfim_cli_provisioner/src/cli_output.rs": {
        "OutputFormat",
        "CommandJsonReport",
        "write_stdout",
        "schema_version",
    },
    "dfim_cli_provisioner/src/main.rs": {
        "mod cli_output",
        "enforce_host_gate",
        "OutputFormat::parse",
        'default_value = "text"',
        "EventType::ProvisionV1",
        "EventType::ProvisionV2",
        "emit_provision_event",
        "write_command_json",
    },
    "dfim_cli_provisioner/src/telemetry_sink.rs": {
        "ProvisionV1",
        "ProvisionV2",
        "fn provision",
        "dry_run",
    },
    "dfim_cli_provisioner/src/verify.rs": {
        "OutputFormat",
        "write_verify_json",
    },
    "dfim_linux_kernel/dfim-ebpf-user/src/main.rs": {
        "enforce_host_gate",
    },
    "docs/security/PRODUCTION_PACKAGING.md": {
        "DFIM_PRODUCTION",
        "HSM",
        "production",
        "enforce_host_gate",
        "build_windows_release.ps1",
    },
    "build_windows_release.ps1": {
        "--features production",
    },
    ".github/workflows/ci.yml": {
        "windows-quality",
        "windows-latest",
        "verify_phase8_contract.py",
    },
}


def validate_required_controls() -> None:
    """Requires production packaging semantics to stay wired across host binaries."""
    for relative_path, tokens in REQUIRED.items():
        path = ROOT / relative_path
        if not path.is_file():
            raise ValueError(f"missing Phase-8 control: {relative_path}")
        text = path.read_text(encoding="utf-8")
        folded = text.casefold()
        missing = sorted(token for token in tokens if token.casefold() not in folded)
        if missing:
            raise ValueError(f"{relative_path} missing tokens: {missing}")


def validate_eval_license_not_primary_gate() -> None:
    """Production entry must not call the evaluation license gate directly."""
    for relative_path in (
        "dfim_cli_provisioner/src/main.rs",
        "dfim_linux_kernel/dfim-ebpf-user/src/main.rs",
    ):
        path = ROOT / relative_path
        text = path.read_text(encoding="utf-8")
        if "enforce_eval_license()" in text:
            raise ValueError(f"{relative_path} still calls enforce_eval_license()")


def main() -> int:
    """Runs the Phase-8 contract as a dependency-free local and CI gate."""
    try:
        validate_required_controls()
        validate_eval_license_not_primary_gate()
    except (OSError, ValueError) as error:
        print(f"PHASE8-CONTRACT: FAIL: {error}", file=sys.stderr)
        return 1
    print("PHASE8-CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
