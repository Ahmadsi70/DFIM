"""Enforces the Phase-7 fuzzing, analysis, and release-maturity security gate."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    "parse_block_stream",
    "parse_authenticated_state_db",
    "parse_boot_manifest",
    "parse_rollback_baseline",
)
WORKFLOWS = (
    ROOT / ".github" / "workflows" / "ci.yml",
    ROOT / ".github" / "workflows" / "release.yml",
    ROOT / ".github" / "workflows" / "fuzz.yml",
    ROOT / ".github" / "workflows" / "codeql.yml",
    ROOT / ".github" / "workflows" / "kani.yml",
)
ACTION_REFERENCE = re.compile(
    r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+@[0-9a-f]{40}(?:\s*#.*)?$"
)


def require_tokens(relative_path: str, tokens: tuple[str, ...]) -> None:
    """Keeps each Phase-7 control coupled to the semantic claims it supports."""
    path = ROOT / relative_path
    if not path.is_file():
        raise ValueError(f"missing Phase-7 control: {relative_path}")
    text = path.read_text(encoding="utf-8")
    folded = text.casefold()
    missing = sorted(token for token in tokens if token.casefold() not in folded)
    if missing:
        raise ValueError(f"{relative_path} missing semantic controls: {missing}")


def validate_fuzz_package() -> None:
    """Requires an isolated cargo-fuzz package with locked parser targets."""
    require_tokens(
        "fuzz/Cargo.toml",
        (
            "cargo-fuzz",
            "metadata",
            "libfuzzer-sys = \"0.4.13\"",
            *TARGETS,
        ),
    )
    if not (ROOT / "fuzz" / "Cargo.lock").is_file():
        raise ValueError("fuzz/Cargo.lock must be committed for reproducible fuzz builds")
    root_manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    if re.search(r'(?m)^\s*"fuzz"\s*,?\s*$', root_manifest):
        raise ValueError("fuzz must remain outside the root workspace members")

    for target in TARGETS:
        path = ROOT / "fuzz" / "fuzz_targets" / f"{target}.rs"
        if not path.is_file():
            raise ValueError(f"missing fuzz target: {path.relative_to(ROOT)}")
        text = path.read_text(encoding="utf-8")
        forbidden = sorted(
            token for token in (".unwrap(", ".expect(", "unsafe ") if token in text
        )
        if forbidden:
            raise ValueError(f"{path.relative_to(ROOT)} uses forbidden tokens: {forbidden}")
        if "MAX_INPUT_BYTES" not in text or target not in text:
            raise ValueError(f"{path.relative_to(ROOT)} lacks a bounded parser invocation")


def validate_action_pinning() -> None:
    """Rejects every non-local action reference unless pinned to an immutable SHA."""
    for path in WORKFLOWS:
        if not path.is_file():
            raise ValueError(f"missing Phase-7 workflow: {path.relative_to(ROOT)}")
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip().startswith("uses:"):
                continue
            reference = line.split("uses:", 1)[1].strip()
            if reference.startswith(("./", "docker://")):
                continue
            if not ACTION_REFERENCE.match(reference):
                raise ValueError(
                    f"mutable action reference in {path.name}:{line_number}: {reference}"
                )


def validate_workflows() -> None:
    """Requires independently scheduled fuzz, CodeQL, and bounded Kani gates."""
    require_tokens(
        ".github/workflows/fuzz.yml",
        (
            "schedule:",
            "cron:",
            "cargo install cargo-fuzz --version 0.13.2 --locked",
            "cargo fuzz build",
            "matrix:",
            "max_total_time",
            "actions/upload-artifact@",
            "failure()",
            *TARGETS,
        ),
    )
    require_tokens(
        ".github/workflows/codeql.yml",
        (
            "github/codeql-action/init@",
            "github/codeql-action/analyze@",
            "languages:",
            "rust",
            "actions",
            "build-mode: none",
            "security-extended",
        ),
    )
    require_tokens(
        ".github/workflows/kani.yml",
        (
            "model-checking/kani-github-action@",
            "command: cargo",
            "kani -p dfim_kani_proofs",
            "--harness",
            "timeout-minutes:",
        ),
    )
    require_tokens(
        ".github/workflows/ci.yml",
        ("python tools/verify_phase7_contract.py",),
    )


def validate_release_maturity_docs() -> None:
    """Requires auditable exit criteria and explicit limits on external evidence."""
    require_tokens(
        "docs/security/RELEASE_MATURITY.md",
        (
            "exit criteria",
            "corpus",
            "artifact",
            "triage",
            "kani",
            "limitation",
            "codeql",
            "entitlement",
            "slsa v1.2",
            "verifier",
            "platform gate",
            "release blocker",
        ),
    )
    require_tokens("SECURITY.md", ("RELEASE_MATURITY.md", "Phase 7"))
    require_tokens(
        "docs/security/ADVERSARIAL_ACCEPTANCE.md",
        ("Phase 7", "fuzz", "Kani", "CodeQL", "SLSA v1.2"),
    )


def main() -> int:
    """Runs the dependency-free Phase-7 contract locally and in main CI."""
    try:
        validate_fuzz_package()
        validate_action_pinning()
        validate_workflows()
        validate_release_maturity_docs()
    except (OSError, ValueError) as error:
        print(f"PHASE7-CONTRACT: FAIL: {error}", file=sys.stderr)
        return 1
    print("PHASE7-CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
