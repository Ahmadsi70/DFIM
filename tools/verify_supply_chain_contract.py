"""Validates DFIM's release, dependency, SBOM, and provenance controls."""

from __future__ import annotations

import sys
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = {
    "rust-toolchain.toml": {"channel = \"1.91.1\"", "clippy", "rustfmt"},
    "deny.toml": {
        "[advisories]",
        "[licenses]",
        "[sources]",
        "unknown-registry = \"deny\"",
        "unknown-git = \"deny\"",
    },
    ".github/dependabot.yml": {
        'package-ecosystem: "cargo"',
        'package-ecosystem: "github-actions"',
    },
    ".github/workflows/ci.yml": {
        "actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955",
        "cargo fmt --all -- --check",
        "cargo test --workspace",
        "cargo clippy",
        "cargo deny check",
        "cargo cyclonedx",
        "verify_phase0_contract.py",
        "verify_supply_chain_contract.py",
    },
    ".github/workflows/release.yml": {
        "id-token: write",
        "attestations: write",
        "actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955",
        "actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26",
        "sbom-path:",
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "SOURCE_DATE_EPOCH",
    },
    "build_reproducible_release.sh": {
        "cargo build --locked --release",
        "cargo-deny --version 0.19.9",
        "cargo-cyclonedx --version 0.5.9",
        "cargo deny check",
    },
    "LICENSE": {"Apache License", "Version 2.0, January 2004"},
}


def validate_required_files() -> None:
    """Requires every release control and its security-critical tokens."""
    for relative_path, required_tokens in REQUIRED_FILES.items():
        path = ROOT / relative_path
        if not path.is_file():
            raise ValueError(f"missing supply-chain control: {relative_path}")
        text = path.read_text(encoding="utf-8")
        missing = sorted(token for token in required_tokens if token not in text)
        if missing:
            raise ValueError(f"{relative_path} missing tokens: {missing}")


def validate_workflow_pinning() -> None:
    """Requires every external GitHub Action to use an immutable full commit SHA."""
    immutable_reference = re.compile(
        r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}(?:\s*#.*)?$"
    )
    workflow_dir = ROOT / ".github" / "workflows"
    for path in workflow_dir.glob("*.yml"):
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped.startswith("uses:"):
                continue
            reference = stripped.split("uses:", 1)[1].strip()
            if reference.startswith(("./", "docker://")):
                continue
            if not immutable_reference.match(reference):
                raise ValueError(f"mutable action reference in {path.name}: {reference}")


def main() -> int:
    """Runs the supply-chain contract as a local and CI release gate."""
    try:
        validate_required_files()
        validate_workflow_pinning()
    except (OSError, ValueError) as error:
        print(f"SUPPLY-CHAIN-CONTRACT: FAIL: {error}", file=sys.stderr)
        return 1
    print("SUPPLY-CHAIN-CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
