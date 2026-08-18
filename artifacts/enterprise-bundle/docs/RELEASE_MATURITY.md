# DFIM Release Maturity and Audit Gate

## Purpose

Phase 7 closes the enterprise-hardening roadmap by requiring continuous parser fuzzing, static
analysis, bounded formal proofs, and auditable consumer verification before a release is described as
enterprise-ready. This document defines the exit criteria, evidence expectations, and explicit limits
on what repository automation can prove without platform qualification.

## Exit criteria

A release candidate is eligible for an enterprise claim only when all of the following pass on the
release commit or tag:

1. **Host quality gate** — `cargo fmt`, workspace tests, strict Clippy, and Phase 0 through Phase 12
   security contracts.
2. **Dependency and SBOM gate** — locked `cargo deny`, reproducible CycloneDX SBOM, and attested
   release workflows for Linux, Windows, and UEFI bundles.
3. **Bounded fuzz gate** — all four parser targets build and run for the configured CI time budget
   without crash, panic, or sanitizer failure:
   - `parse_block_stream`
   - `parse_authenticated_state_db`
   - `parse_boot_manifest`
   - `parse_rollback_baseline`
4. **CodeQL gate** — Rust and GitHub Actions workflows analyzed with `build-mode: none` and the
   `security-extended` query suite; unresolved Critical or High findings are **release blockers**.
5. **Kani gate** — bounded memory-safety proofs for Layer-0 integrity gates and parser surfaces pass
   on the pinned Kani version.
6. **Adversarial acceptance** — AT-01 through AT-09 pass for the supported deployment profile, with
   platform-only steps documented as external gates rather than silently skipped.
7. **Consumer verification** — digest check, GitHub attestation verification, and SLSA v1.2
   provenance review against the expected workflow identity and subject digest.

## Fuzzing evidence

- Fuzz targets live in the isolated `fuzz/` package with a committed `Cargo.lock`.
- CI runs each target for 60 seconds against the checked-in or evolved `fuzz/corpus/<target>/`
  directory and uploads artifacts on failure.
- Operators regenerate deterministic seeds with `cargo run --example generate_seed_corpus` from the
  `fuzz/` directory after parser format changes.
- Crash triage requires: target name, minimized reproducer, sanitizer output, affected parser entry
  point, and a regression test or proof update before closure.

## Static analysis and formal evidence

- CodeQL results require repository **code scanning** entitlement on GitHub Advanced Security or an
  equivalent hosted analysis deployment. Without entitlement, the workflow may succeed locally but
  will not populate the security dashboard; that gap is a release maturity **limitation**, not a
  substitute for review.
- Kani proofs cover panic-freedom and selected bounds properties on a symbolic envelope smaller than
  the production 64 KiB parser cap. They do not replace fuzzing, runtime adversarial tests, or
  hardware qualification.
- Concrete playback of Kani counterexamples is optional but recommended when a proof fails during
  development.

## SLSA v1.2 consumer verification

Consumers must verify tagged Linux bundles with:

```shell
sha256sum --check RELEASE_SHA256SUMS
gh attestation verify dfim-linux-x86_64.tar.gz \
  --repo OWNER/DFIM \
  --signer-workflow OWNER/DFIM/.github/workflows/release.yml
```

Reject the release when any of the following fail:

- Subject digest mismatch against `RELEASE_SHA256SUMS`.
- Attestation signature, builder identity, or workflow reference mismatch.
- Provenance `predicateType` is not `https://slsa.dev/provenance/v1`.
- `externalParameters` or `buildType` differ from the approved release workflow contract.

## Platform gates outside repository automation

The following remain **platform gates** and must not be inferred from green CI alone:

- Linux eBPF/IMA runtime adversarial acceptance (AT-01 through AT-04).
- TPM hardware or `swtpm` quote generation and verifier enrollment (AT-07) — CI runs
  `run_swtpm_attestation_gate.sh`; hardware remains a platform gate.
- Destructive recovery power-loss and authenticated UEFI capsule qualification (AT-08) — planner in
  `qualify_at08_power_loss.sh` and `UEFI_CAPSULE_RECOVERY.md`.
- Cross-platform attested release parity for Windows/UEFI and eBPF artifacts (Phase 10).
- Phase 11 platform qualification: AT-07 swtpm CI gate and AT-08 destructive recovery planner.
- Phase 12 enterprise readiness: RFP bundle, ISO/compliance mapping, pen-test scope, SLA template,
  and `build_enterprise_sales_bundle.sh` — external pen-test closure still required for contract.

## Release blocker policy

- Any open Critical or High CodeQL finding on the release branch is a **release blocker**.
- Any fuzz crash without a fixed regression test is a **release blocker**.
- Any Kani proof failure on a pinned harness is a **release blocker**.
- Any Phase 0 through Phase 12 contract failure is a **release blocker**.
- Open **Critical or High** external pen-test findings are **release blockers** for enterprise claims.
- Medium and Low findings require documented triage with owner and target date; silent deferral is
  not acceptable for security controls mapped to P0-C1 through P0-C8.

## Operational limitations

- Bounded CI fuzz time discovers regressions quickly but does not prove absence of bugs.
- Nightly and scheduled workflows improve drift detection; they do not replace pre-release manual
  review of changed parser surfaces.
- CodeQL `build-mode: none` for Rust analyzes source structure without executing a full build; some
  build-time-only issues may require supplemental review.
- GitHub attestations prove workflow identity for published artifacts; they do not certify FIPS,
  Common Criteria, or independent third-party audit completion.
