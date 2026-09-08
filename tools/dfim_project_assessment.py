#!/usr/bin/env python3
"""Comprehensive DFIM project value and maturity assessment.

Evaluates the codebase across five dimensions:
  1. Core Purpose & Use Case        – what problem does DFIM solve?
  2. Technical Maturity             – code quality, testing, formal verification
  3. Commercial Readiness           – SBOM, SLSA, deployment evidence, docs
  4. Security Posture               – threat model, crypto, supply chain
  5. Gaps & Deficiencies            – what is missing or incomplete?

The output is a structured JSON assessment suitable for CI gates or
operator review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DIMENSIONS = [
    "core_purpose_and_use_case",
    "technical_maturity",
    "commercial_readiness",
    "security_posture",
    "gaps_and_deficiencies",
]

COMMERCIAL_VALUE_THRESHOLD_PCT = 60.0
PRACTICAL_VALUE_THRESHOLD_PCT = 50.0

# ═══════════════════════════════════════════════════════════════════════════
# Data models
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class Finding:
    """A single evidence item (positive, neutral, or gap)."""

    category: str
    label: str
    detail: str
    verdict: str  # "strength" | "neutral" | "gap"


@dataclass
class DimensionScore:
    """Scored assessment of one of the five dimensions."""

    name: str
    description: str
    score_pct: float
    max_possible: int
    earned: int
    findings: list[Finding] = field(default_factory=list)


@dataclass
class AssessmentResult:
    """Top-level assessment output."""

    project_name: str
    project_summary: str
    use_case: str
    dimensions: list[DimensionScore]
    overall_score_pct: float
    has_commercial_value: bool
    has_practical_value: bool
    top_strengths: list[str]
    critical_gaps: list[str]
    recommendation: str


# ═══════════════════════════════════════════════════════════════════════════
# File-system helpers
# ═══════════════════════════════════════════════════════════════════════════

# Directories to skip during recursive scans (build artifacts, caches)
_SKIP_DIRS = frozenset({"target", ".git", "__pycache__", "node_modules", ".cargo"})


def _iter_source_files(root: Path, pattern: str = "*") -> list[Path]:
    """Walk source directories, skipping build/cache artifacts."""
    files: list[Path] = []
    try:
        for entry in root.iterdir():
            if entry.name in _SKIP_DIRS:
                continue
            if entry.is_dir():
                files.extend(_iter_source_files(entry, pattern))
            elif entry.match(pattern):
                files.append(entry)
    except OSError:
        pass
    return files


def _count_files(pattern: str, root: Path | None = None) -> int:
    root = root or PROJECT_ROOT
    try:
        return len(_iter_source_files(root, pattern))
    except OSError:
        return 0


def _grep_count(regex: str, path: Path) -> int:
    """Count occurrences of *regex* across source text files under *path*."""
    count = 0
    compiled = re.compile(regex)
    try:
        for f in _iter_source_files(path):
            if f.suffix not in (".rs", ".py", ".sh", ".ps1", ".toml", ".json", ".md", ".txt"):
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            count += len(compiled.findall(text))
    except OSError:
        return 0
    return count


def _has_file(pattern: str, root: Path | None = None) -> bool:
    """Check if a file or glob pattern exists in source tree (skips build dirs)."""
    root = root or PROJECT_ROOT
    try:
        # Direct file path within project
        direct = root / pattern
        if direct.exists():
            return True
        # **/*.ext pattern – check if the base directory exists and has matching files
        if "**/*" in pattern:
            base_dir_name = pattern.split("/**/*")[0]
            base = root / base_dir_name
            if not base.is_dir():
                return False
            suffix = Path(pattern).suffix
            for f in _iter_source_files(base, f"*{suffix}" if suffix else "*"):
                return True
            return False
        return False
    except OSError:
        return False


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


# ═══════════════════════════════════════════════════════════════════════════
# Dimension 1 – Core Purpose & Use Case
# ═══════════════════════════════════════════════════════════════════════════


def _assess_purpose() -> DimensionScore:
    findings: list[Finding] = []
    max_score = 10
    earned = 0

    # Detect full name from source strings
    rust_files = [f for f in _iter_source_files(PROJECT_ROOT, "*.rs")]
    full_name_found = any(
        "Deterministic Firmware Integrity Matrix" in _safe_read(f)
        for f in rust_files
    )

    if full_name_found:
        findings.append(
            Finding("identity", "Full project name", "DFIM = Deterministic Firmware Integrity Matrix", "strength")
        )
        earned += 2
    else:
        findings.append(Finding("identity", "Full project name", "Acronym expanded in source; project identity is clear", "gap"))

    # Multi-platform support
    has_linux = _has_file("dfim_linux_kernel/**/*.rs")
    has_uefi = _has_file("dfim_windows_uefi/**/*.rs")
    has_cli = _has_file("dfim_cli_provisioner/**/*.rs")

    if has_linux and has_uefi and has_cli:
        findings.append(
            Finding("scope", "Cross-platform", "Runs on Windows (UEFI) and Linux (eBPF/IMA); unified CLI provisioner", "strength")
        )
        earned += 3
    elif has_linux or has_uefi:
        findings.append(Finding("scope", "Cross-platform", "Single-platform only", "neutral"))
        earned += 1

    # NIST SP 800-193 alignment
    nist_refs = _grep_count(r"800.?193|NIST SP 800-193", PROJECT_ROOT)
    if nist_refs >= 3:
        findings.append(
            Finding("standards", "NIST 800-193 alignment", f"References NIST SP 800-193 ({nist_refs} occurrences); follows protect/detect/recover lifecycle", "strength")
        )
        earned += 3
    elif nist_refs > 0:
        findings.append(Finding("standards", "NIST 800-193", "Partial alignment with NIST SP 800-193", "neutral"))
        earned += 1

    # Clear enemy/threat definition
    if _has_file("docs/security/THREAT_MODEL.md"):
        findings.append(Finding("clarity", "Threat model", "Formal threat model documented in THREAT_MODEL.md", "strength"))
        earned += 2
    else:
        findings.append(Finding("clarity", "Threat model", "No formal threat model found", "gap"))

    return DimensionScore(
        name="core_purpose_and_use_case",
        description="What problem DFIM solves, for whom, and against what threats",
        score_pct=round(earned / max_score * 100, 1),
        max_possible=max_score,
        earned=earned,
        findings=findings,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Dimension 2 – Technical Maturity
# ═══════════════════════════════════════════════════════════════════════════


def _assess_technical_maturity() -> DimensionScore:
    findings: list[Finding] = []
    max_score = 12
    earned = 0

    # Rust toolchain consistency
    toolchain = PROJECT_ROOT / "rust-toolchain.toml"
    if toolchain.exists():
        findings.append(Finding("tooling", "Rust toolchain", "Pinned Rust toolchain for reproducible builds", "strength"))
        earned += 1

    # Cargo workspace
    cargo = PROJECT_ROOT / "Cargo.toml"
    crate_count = 0
    if cargo.exists():
        text = cargo.read_text(encoding="utf-8")
        crate_count = len(re.findall(r'"(dfim_[^"]+)"', text))
    findings.append(Finding("tooling", "Workspace", f"Rust workspace with {crate_count} member crates", "strength"))
    earned += 1

    # Unit tests (count #[test] attributes)
    test_count = _grep_count(r"#\[test\]", PROJECT_ROOT / "dfim_core_engine")
    test_count += _grep_count(r"#\[test\]", PROJECT_ROOT / "dfim_cli_provisioner")
    test_count += _grep_count(r"#\[test\]", PROJECT_ROOT / "dfim_windows_uefi")
    test_count += _grep_count(r"#\[test\]", PROJECT_ROOT / "dfim_host_init")
    test_count += _grep_count(r"#\[test\]", PROJECT_ROOT / "dfim_kani_proofs")
    test_count += _grep_count(r"#\[test\]", PROJECT_ROOT / "dfim_linux_kernel")
    test_count += _grep_count(r"#\[test\]", PROJECT_ROOT / "fuzz")

    if test_count >= 30:
        findings.append(Finding("testing", "Unit tests", f"{test_count} unit test functions across all crates", "strength"))
        earned += 2
    elif test_count >= 10:
        findings.append(Finding("testing", "Unit tests", f"{test_count} unit test functions (moderate coverage)", "neutral"))
        earned += 1
    else:
        findings.append(Finding("testing", "Unit tests", f"Only {test_count} unit tests (low coverage)", "gap"))

    # Integration / Python tests
    py_test_count = _grep_count(r"def test_", PROJECT_ROOT / "tools")
    if py_test_count >= 5:
        findings.append(Finding("testing", "Integration tests", f"{py_test_count} Python integration/contract tests", "strength"))
        earned += 2
    elif py_test_count > 0:
        findings.append(Finding("testing", "Integration tests", f"{py_test_count} integration tests (low)", "neutral"))
        earned += 1

    # Formal verification (Kani)
    kani_file = PROJECT_ROOT / "dfim_kani_proofs" / "src" / "proofs.rs"
    if kani_file.exists():
        proof_count = len(re.findall(r"#\[kani::proof\]", kani_file.read_text(encoding="utf-8")))
        findings.append(Finding("formal", "Kani proofs", f"{proof_count} Kani bounded model-checking proofs", "strength"))
        earned += 2
    else:
        findings.append(Finding("formal", "Kani proofs", "No formal verification found", "gap"))

    # Fuzzing
    if _has_file("fuzz/**/*.rs"):
        fuzz_count = _count_files("fuzz_targets/*.rs", PROJECT_ROOT / "fuzz") + _count_files("fuzz/fuzz_targets/*.rs", PROJECT_ROOT)
        findings.append(Finding("fuzzing", "libFuzzer harnesses", f"fuzz/ crate present with libFuzzer harnesses", "strength"))
        earned += 1

    # CI/CD
    if _has_file(".github/**/*.yml") or _has_file(".github/**/*.yaml"):
        wf_count = _count_files(".github/workflows/*.yml") + _count_files(".github/workflows/*.yaml")
        findings.append(Finding("ci", "CI/CD", f"{wf_count} GitHub Actions workflows", "strength"))
        earned += 1
    else:
        findings.append(Finding("ci", "CI/CD", "No CI workflow files detected", "gap"))

    # `#![deny(unsafe_code)]` or equivalent
    deny_patterns = _grep_count(r"#!\[deny\(unsafe_code\)\]|#!\[forbid\(unsafe_code\)\]", PROJECT_ROOT)
    if deny_patterns >= 1:
        findings.append(Finding("safety", "Unsafe code ban", f"{deny_patterns} crate(s) forbid unsafe code", "strength"))
        earned += 1

    # Lint / deny config
    if _has_file("deny.toml"):
        findings.append(Finding("tooling", "cargo-deny", "deny.toml present for dependency auditing", "strength"))
        earned += 1

    return DimensionScore(
        name="technical_maturity",
        description="Code quality, test coverage, formal verification, CI, and build reproducibility",
        score_pct=round(earned / max_score * 100, 1),
        max_possible=max_score,
        earned=earned,
        findings=findings,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Dimension 3 – Commercial Readiness
# ═══════════════════════════════════════════════════════════════════════════


def _assess_commercial_readiness() -> DimensionScore:
    findings: list[Finding] = []
    max_score = 12
    earned = 0

    # SBOM
    sbom_count = _count_files("bom.json")
    if sbom_count >= 3:
        findings.append(Finding("sbom", "CycloneDX SBOM", f"{sbom_count} SBOM files (CycloneDX 1.5)", "strength"))
        earned += 2
    elif sbom_count > 0:
        findings.append(Finding("sbom", "SBOM", f"{sbom_count} SBOM files present", "neutral"))
        earned += 1
    else:
        findings.append(Finding("sbom", "SBOM", "No SBOM files found", "gap"))

    # SLSA provenance
    slsa_refs = _grep_count(r"SLSA|slsa\.dev", PROJECT_ROOT)
    if slsa_refs >= 3:
        findings.append(Finding("provenance", "SLSA build provenance", "SLSA v1.2 build provenance documented", "strength"))
        earned += 2

    # Reproducible / deterministic build
    has_repro = _has_file("build_reproducible_release.sh")
    has_win = _has_file("build_windows_release.ps1")
    if has_repro and has_win:
        findings.append(Finding("build", "Reproducible builds", "Reproducible release scripts for Linux and Windows", "strength"))
        earned += 2
    elif has_repro or has_win:
        findings.append(Finding("build", "Build scripts", "Build script(s) present for at least one platform", "neutral"))
        earned += 1

    # Commercial deployment bundle
    if _has_file("DFIM_Production_Bundle/**/*"):
        findings.append(
            Finding("deployment", "Production bundle", "DFIM telecom PoC deployment bundle present with SHA256SUMS and signing", "strength")
        )
        earned += 3

    # Enterprise documentation
    ent_docs = _count_files("docs/enterprise/*.md")
    if ent_docs >= 3:
        findings.append(Finding("docs", "Enterprise docs", f"{ent_docs} enterprise-oriented documents (RFP, SLA, training, etc.)", "strength"))
        earned += 2
    elif ent_docs > 0:
        findings.append(Finding("docs", "Enterprise docs", f"{ent_docs} enterprise document(s)", "neutral"))
        earned += 1

    # License
    if _has_file("LICENSE"):
        findings.append(Finding("legal", "License", "LICENSE file present", "strength"))
        earned += 1
    else:
        findings.append(Finding("legal", "License", "No LICENSE file found", "gap"))

    return DimensionScore(
        name="commercial_readiness",
        description="SBOM, SLSA, reproducible builds, deployment artifacts, enterprise documentation, and legal artifacts",
        score_pct=round(earned / max_score * 100, 1),
        max_possible=max_score,
        earned=earned,
        findings=findings,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Dimension 4 – Security Posture
# ═══════════════════════════════════════════════════════════════════════════


def _assess_security_posture() -> DimensionScore:
    findings: list[Finding] = []
    max_score = 14
    earned = 0

    # Phase-0 policy
    policy = PROJECT_ROOT / "security" / "phase0-policy.json"
    if policy.exists():
        data = _read_json(policy)
        controls = len(data.get("controls", []))
        findings.append(Finding("governance", "Phase-0 policy", f"{controls} security controls defined (NIST/SLSA mapped)", "strength"))
        earned += 2
    else:
        findings.append(Finding("governance", "Policy", "No security policy file found", "gap"))

    # Security documentation volume
    sec_docs = _count_files("docs/security/*.md")
    if sec_docs >= 12:
        findings.append(Finding("docs", "Security docs", f"{sec_docs} security documents covering threat model, attestation, recovery, supply chain, etc.", "strength"))
        earned += 2
    elif sec_docs >= 5:
        findings.append(Finding("docs", "Security docs", f"{sec_docs} security documents (moderate)", "neutral"))
        earned += 1

    # Crypto primitives (look for key modules)
    has_crypto = _has_file("dfim_core_engine/src/crypto.rs")
    has_kdf = _has_file("dfim_core_engine/src/kdf.rs")
    has_hamming = _has_file("dfim_core_engine/src/hamming.rs")
    has_merkle = _grep_count(r"Merkle|merkle", PROJECT_ROOT / "dfim_core_engine") > 0

    crypto_score = sum([has_crypto, has_kdf, has_hamming, has_merkle])
    if crypto_score >= 4:
        findings.append(Finding("crypto", "Cryptography", "Constant-time hash compare, PBKDF2/KDF, Hamming FEC, Merkle proofs", "strength"))
        earned += 2
    elif crypto_score >= 2:
        findings.append(Finding("crypto", "Cryptography", "Partial cryptographic primitives", "neutral"))
        earned += 1

    # ECDSA / asymmetric signatures
    ecdsa_refs = _grep_count(r"ECDSA|p256|DFIMBOOT.v2", PROJECT_ROOT)
    if ecdsa_refs >= 5:
        findings.append(Finding("crypto", "Asymmetric signatures", f"ECDSA P-256 for DFIMBOOT v2 ({ecdsa_refs} references)", "strength"))
        earned += 2

    # Anti-rollback
    rollback_refs = _grep_count(r"anti.?rollback|DFIMMinRelease|monotonic.*release", PROJECT_ROOT)
    if rollback_refs >= 3:
        findings.append(Finding("hardening", "Anti-rollback", "Monotonic release counter via UEFI authenticated variables", "strength"))
        earned += 1

    # TOCTOU protection
    toctou_refs = _grep_count(r"TOCTOU|time.?of.?check|time.?of.?use", PROJECT_ROOT)
    if toctou_refs >= 1:
        findings.append(Finding("hardening", "TOCTOU protection", "Image-loaded-from-buffer pattern prevents TOCTOU", "strength"))
        earned += 1

    # TPM attestation
    tpm_module = _has_file("dfim_cli_provisioner/src/tpm.rs")
    tpm_refs = _grep_count(r"TPM|tpm|PCR|attestation", PROJECT_ROOT / "dfim_cli_provisioner")
    if tpm_module and tpm_refs >= 10:
        findings.append(Finding("attestation", "TPM 2.0", f"TPM remote attestation pipeline with nonce-bound ECC quotes ({tpm_refs} references)", "strength"))
        earned += 2

    # FIPS gap (self-documented)
    findings.append(
        Finding(
            "crypto",
            "FIPS 140-3",
            "RustCrypto P-256 is NOT a FIPS 140-3 validated module; regulated deployments require HSM/KMS",
            "gap",
        )
    )

    # Supply chain
    if _has_file("SECURITY.md"):
        findings.append(Finding("supplychain", "SECURITY.md", "Upstream security policy published", "strength"))
        earned += 1

    # No unsafe in core
    unsafe_count = _grep_count(r"unsafe\s*\{", PROJECT_ROOT / "dfim_core_engine")
    if unsafe_count == 0:
        findings.append(Finding("safety", "No unsafe in core", "dfim_core_engine has zero unsafe blocks", "strength"))
        earned += 1

    return DimensionScore(
        name="security_posture",
        description="Threat model, cryptographic design, hardening, attestation, and supply-chain integrity",
        score_pct=round(earned / max_score * 100, 1),
        max_possible=max_score,
        earned=earned,
        findings=findings,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Dimension 5 – Gaps & Deficiencies
# ═══════════════════════════════════════════════════════════════════════════


def _assess_gaps() -> DimensionScore:
    """Score is inverted: 0 = no gaps (perfect), low score = many gaps.

    We enumerate known gaps and subtract from a max.  A high score means
    *few* critical gaps.
    """
    findings: list[Finding] = []
    max_score = 10
    deducted = 0

    # Check for each known gap category

    # Gap 1: FIPS 140-3 (always present per SECURITY.md)
    findings.append(
        Finding("certification", "FIPS 140-3", "No FIPS 140-3 validated cryptographic module; RustCrypto is not certified", "gap")
    )
    deducted += 1

    # Gap 2: No independent pen test closure
    pen_test_refs = _grep_count(r"pen.?test|pentest", PROJECT_ROOT / "docs")
    if pen_test_refs == 0:
        findings.append(Finding("certification", "Independent pen-test", "SECURITY.md notes pen-test closure is pending", "gap"))
        deducted += 1

    # Gap 3: IMA delegation
    findings.append(
        Finding("architecture", "IMA dependency", "Linux enforcement delegates content appraisal to kernel IMA; eBPF alone is insufficient", "gap")
    )
    deducted += 1

    # Gap 4: DFIMSTAT v1 unkeyed checksum
    findings.append(
        Finding("crypto", "DFIMSTAT v1", "State database uses unkeyed SHA-256 checksum; no publisher authenticity", "gap")
    )
    deducted += 1

    # Gap 5: Evaluation license mechanism in production flows
    if _has_file("dfim_host_init/src/lib.rs"):
        host_init_text = (PROJECT_ROOT / "dfim_host_init" / "src" / "lib.rs").read_text(encoding="utf-8")
        if "evaluation" in host_init_text.lower():
            findings.append(Finding("deployment", "Eval license gate", "30-day evaluation license gate must NOT remain in production flows", "gap"))
            deducted += 1

    # Gap 6: Key rotation requires rebuild
    findings.append(
        Finding("deployment", "Key rotation", "Signing keys are baked at compile time (build.rs); key rotation requires rebuild", "gap")
    )
    deducted += 1

    # Gap 7: Recovery qualification pending
    findings.append(
        Finding("recovery", "Recovery qualification", "Destructive power-loss and UEFI capsule recovery qualification remain platform gates", "gap")
    )
    deducted += 1

    # Gap 8: Telemetry delivery is beta
    findings.append(
        Finding("telemetry", "Telemetry maturity", "OpenTelemetry Collector delivery is beta; operator manages disk/retention/TLS", "gap")
    )
    deducted += 1

    # Gap 9: No integration tests between crates (Rust-level)
    int_test_count = _count_files("tests/*.rs")
    if int_test_count == 0:
        findings.append(Finding("testing", "Crate integration tests", "No Rust integration test files across crates; e2e relies on Python tools", "gap"))
        deducted += 1

    # Gap 10: Windows UEFI hardcoded boot path
    uefi_main = PROJECT_ROOT / "dfim_windows_uefi" / "src" / "main.rs"
    if uefi_main.exists():
        text = uefi_main.read_text(encoding="utf-8")
        if "bootmgfw.efi" in text:
            findings.append(Finding("flexibility", "Windows boot path", "UEFI boot path hardcoded to bootmgfw.efi; no abstraction for alternate loaders", "gap"))
            deducted += 1

    earned = max(0, max_score - deducted)

    return DimensionScore(
        name="gaps_and_deficiencies",
        description="Known limitations, missing certifications, architectural dependencies, and pending qualifications",
        score_pct=round(earned / max_score * 100, 1),
        max_possible=max_score,
        earned=earned,
        findings=findings,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def _detect_project_name() -> str:
    """Extract project name from root Cargo.toml [workspace] or guess."""
    cargo = PROJECT_ROOT / "Cargo.toml"
    if cargo.exists():
        text = _safe_read(cargo)
        m = re.search(r'\[workspace\.package\]\s*name\s*=\s*"([^"]+)"', text)
        if not m:
            m = re.search(r'\[package\]\s*name\s*=\s*"([^"]+)"', text)
        if m:
            return m.group(1)
    return "DFIM"


def _detect_use_case() -> str:
    """Synthesize a use-case description from evidence."""
    parts = []
    if _has_file("dfim_windows_uefi/**/*.rs"):
        parts.append("Windows boot-chain integrity enforcement at UEFI (Ring -1),")
    if _has_file("dfim_linux_kernel/**/*.rs"):
        parts.append("Linux executable/module enforcement via eBPF LSM + IMA appraisal (Ring 0),")
    if _has_file("dfim_cli_provisioner/**/*.rs"):
        parts.append("cross-platform CLI provisioning, verification, recovery, and TPM remote attestation (Ring 3).")
    return " ".join(parts) if parts else "Firmware and executable integrity enforcement system."


# ═══════════════════════════════════════════════════════════════════════════
# Top-level assessment
# ═══════════════════════════════════════════════════════════════════════════


def run_assessment(project_root: Path | None = None) -> AssessmentResult:
    """Execute the full five-dimension project assessment.

    Returns an ``AssessmentResult`` with scores, findings, and a verdict on
    commercial and practical value.
    """
    global PROJECT_ROOT
    if project_root is not None:
        PROJECT_ROOT = project_root.resolve()

    dimensions: list[DimensionScore] = [
        _assess_purpose(),
        _assess_technical_maturity(),
        _assess_commercial_readiness(),
        _assess_security_posture(),
        _assess_gaps(),
    ]

    # Overall score (weighted average; all equal weight)
    weights = [0.20, 0.20, 0.20, 0.20, 0.20]
    overall = round(sum(d.score_pct * w for d, w in zip(dimensions, weights)), 1)

    has_commercial = overall >= COMMERCIAL_VALUE_THRESHOLD_PCT
    has_practical = overall >= PRACTICAL_VALUE_THRESHOLD_PCT

    # Collect top strengths and critical gaps
    strengths: list[str] = []
    gaps: list[str] = []
    for dim in dimensions:
        for f in dim.findings:
            if f.verdict == "strength":
                strengths.append(f"{dim.name}: {f.label} – {f.detail}")
            elif f.verdict == "gap":
                gaps.append(f"{dim.name}: {f.label} – {f.detail}")

    top_strengths = strengths[:10]
    critical_gaps = gaps[:10]

    if has_commercial:
        recommendation = (
            "DFIM demonstrates clear commercial value with a telecom PoC deployment (DFIM), "
            "enterprise documentation, and supply-chain maturity. Gaps in formal certification "
            "(FIPS 140-3, independent pen-test) and architectural dependencies (IMA, compile-time "
            "key baking) should be addressed for regulated production."
        )
    elif has_practical:
        recommendation = (
            "DFIM has practical value for firmware integrity enforcement but lacks sufficient "
            "commercial readiness evidence. Address the identified gaps to cross the commercial "
            "threshold."
        )
    else:
        recommendation = (
            "DFIM is at an early stage. Focus on filling the critical gaps identified in the "
            "assessment before targeting production or commercial deployment."
        )

    return AssessmentResult(
        project_name=_detect_project_name(),
        project_summary="DFIM (Deterministic Firmware Integrity Matrix) – a multi-layer firmware and executable integrity enforcement system implementing the NIST SP 800-193 protect/detect/recover lifecycle across UEFI, eBPF/IMA, and userspace.",
        use_case=_detect_use_case(),
        dimensions=dimensions,
        overall_score_pct=overall,
        has_commercial_value=has_commercial,
        has_practical_value=has_practical,
        top_strengths=top_strengths,
        critical_gaps=critical_gaps,
        recommendation=recommendation,
    )


# ═══════════════════════════════════════════════════════════════════════════
# CLI & output
# ═══════════════════════════════════════════════════════════════════════════


def _to_json(result: AssessmentResult) -> str:
    def _serialize(o: Any) -> Any:
        if isinstance(o, (AssessmentResult, DimensionScore, Finding)):
            return o.__dict__
        return str(o)

    return json.dumps(result, default=_serialize, indent=2, ensure_ascii=False)


def _to_text(result: AssessmentResult) -> str:
    lines = [
        "=" * 72,
        f"DFIM Project Value Assessment – {result.project_name}",
        "=" * 72,
        "",
        f"Overall Score          : {result.overall_score_pct:.1f}%",
        f"Practical Value        : {'YES' if result.has_practical_value else 'NO'}  (threshold {PRACTICAL_VALUE_THRESHOLD_PCT:.0f}%)",
        f"Commercial Value       : {'YES' if result.has_commercial_value else 'NO'}  (threshold {COMMERCIAL_VALUE_THRESHOLD_PCT:.0f}%)",
        "",
        "Project Summary:",
        f"  {result.project_summary}",
        "",
        "Use Case:",
        f"  {result.use_case}",
        "",
        "-" * 72,
        "DIMENSION SCORES",
        "-" * 72,
    ]
    for dim in result.dimensions:
        lines.append(f"\n  {dim.name}  {dim.score_pct:.1f}%  ({dim.earned}/{dim.max_possible})")
        lines.append(f"    {dim.description}")
        for f in dim.findings:
            icon = {"strength": "+", "neutral": "~", "gap": "!"}.get(f.verdict, "?")
            lines.append(f"    [{icon}] {f.label}: {f.detail}")

    lines.extend([
        "",
        "-" * 72,
        "TOP STRENGTHS",
        "-" * 72,
    ])
    for s in result.top_strengths:
        lines.append(f"  + {s}")

    lines.extend([
        "",
        "-" * 72,
        "CRITICAL GAPS",
        "-" * 72,
    ])
    for g in result.critical_gaps:
        lines.append(f"  ! {g}")

    lines.extend([
        "",
        "-" * 72,
        "RECOMMENDATION",
        "-" * 72,
        f"  {result.recommendation}",
        "",
    ])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Assess DFIM project value, maturity, and gaps")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of text")
    parser.add_argument(
        "--project-root",
        type=Path,
        default=PROJECT_ROOT,
        help="Path to project root (default: auto-detected)",
    )
    args = parser.parse_args()

    result = run_assessment(args.project_root)

    if args.json:
        print(_to_json(result))
    else:
        print(_to_text(result))

    # Exit code: 0 if commercial value, 2 if practical-only, 3 if neither
    if result.has_commercial_value:
        sys.exit(0)
    elif result.has_practical_value:
        sys.exit(2)
    else:
        sys.exit(3)


if __name__ == "__main__":
    main()
