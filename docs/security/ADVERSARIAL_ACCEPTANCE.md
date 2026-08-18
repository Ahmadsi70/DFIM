# DFIM Adversarial Acceptance Plan

**Document ID:** DFIM-SEC-AT-2026-V1.0  
**Method:** Tests are written as security contracts before implementation. A target-phase feature is not
complete until its test has failed against the old behavior (Red) and passed after the change (Green).

## Test environment requirements

- Disposable VM or QEMU guest; never run destructive cases on a production host.
- Linux kernel with BTF, BPF LSM, IMA appraisal, and audit support for Linux enforcement tests.
- UEFI VM with Secure Boot test keys for firmware-path tests.
- TPM 2.0 simulator for CI and discrete/fTPM hardware for final qualification.
- Immutable test fixtures and a clean snapshot before each run.
- Captured console, audit, JSONL, kernel, and verifier logs associated with the tested commit.

## AT-01 — Post-enrollment content tamper

**Threat:** `TM-01`  
**Target phase:** 1  
**Given:** A protected executable has valid metadata and is successfully appraised.  
**When:** One byte is changed after enrollment and before the next execution.  
**Then:** Execution returns `-EPERM`; a critical integrity event is emitted; the old eBPF snapshot cannot
authorize the modified file.  
**Current baseline:** Expected to expose the snapshot TOCTOU weakness until `P0-C1` is implemented.

## AT-02 — Unprotected executable availability

**Threat:** `TM-02`  
**Target phase:** 1  
**Given:** Enforcement is active and one unrelated executable is not enrolled in DFIM.  
**When:** The unrelated executable is launched.  
**Then:** DFIM does not deny it solely due to missing manifest data; normal operating-system controls
remain authoritative.  
**Current baseline:** Protected-scope probe returns allow when inode is absent from `DFIM_SCOPE`.

## AT-03 — Protected metadata removal

**Threat:** `TM-02`, `TM-03`  
**Target phase:** 1  
**Given:** An executable is enrolled and marked protected.  
**When:** Its userspace metadata or map entry is deleted without an authorized unenrollment transaction.  
**Then:** The protected executable remains denied; deletion cannot silently move it outside the protected
scope; unrelated executables remain available.

## AT-04 — Missing or malformed `DFIM_CONFIG`

**Threat:** `TM-03`  
**Target phase:** 1  
**Given:** At least one protected asset exists.  
**When:** `DFIM_CONFIG` is missing, has an unsupported schema version, or contains an unknown profile.  
**Then:** Protected execution is denied with a stable policy-failure reason; unprotected execution is not
globally denied; no implicit monitor downgrade occurs.  
**Current baseline:** `evaluate_enforcement` consumes `DFIM_CONFIG`; protected assets deny with
`DenyInvalidConfig` when configuration is missing or unsupported.

## AT-05 — Forged image and sidecar

**Threat:** `TM-04`  
**Target phase:** 2  
**Given:** A valid protected image and signed DFIMBOOT v2 sidecar.  
**When:** An attacker replaces the image, rebuilds Merkle metadata, and signs with no trusted key or an
untrusted key.  
**Then:** Provisioning, host verification, UEFI verification, and Linux enrollment all reject it.  
**Current baseline:** DFIMBOOT v2 host and `no_std` UEFI paths reject payload/signature/key-ID
tampering; DFIMBOOT v1 is rejected by the production trusted parser.

## AT-06 — Replay of an older valid release

**Threat:** `TM-05`  
**Target phase:** 2  
**Given:** Release 2 is accepted and its monotonic counter is committed.  
**When:** A valid release-1 image and matching sidecar are restored.  
**Then:** Verification rejects the bundle as rollback even though its Merkle proof and signature are valid.  
**Current baseline:** DFIMBOOT v2 enforces the greater of the compiled floor and a key-bound,
time-authenticated UEFI-variable floor. Unit adversarial coverage passes; deployment-firmware
variable provisioning remains a required platform acceptance step.

## AT-07 — TPM quote replay

**Threat:** `TM-06`  
**Target phase:** 3  
**Given:** A verifier sends a fresh nonce and expects the approved policy, PCR selection, and release.  
**When:** A previously valid quote or a quote bound to another nonce/device/policy is submitted.  
**Then:** Remote verification rejects it and emits an attestation failure.  
**Current baseline:** The verifier rejects nonce replay, signature substitution, PCR substitution,
selection downgrade, stale releases, and policy mismatch. Linux TPM generation is type-checked;
hardware or `swtpm` execution remains a required platform acceptance step.

## AT-09 — Release substitution or provenance replay

**Threat:** `TM-08`  
**Target phase:** 4  
**Given:** A consumer requires a DFIM release from the approved repository and release workflow.  
**When:** An attacker modifies the bundle, substitutes its SBOM, reuses provenance for another digest,
or presents an attestation from an unapproved workflow identity.  
**Then:** Digest and `gh attestation verify` checks reject the release before installation.  
**Current baseline:** CI enforces locked dependency policy and reproducible SBOM generation; tagged
release workflows attach separate build-provenance and SBOM attestations to the canonical bundle.

## AT-08 — Detect, restore, verify

**Threat:** `TM-07`  
**Target phase:** 5  
**Given:** A protected service has signed recovery artifacts and a current authorized counter.  
**When:** Its image is corrupted.  
**Then:** DFIM denies execution, restores only from the authorized source, re-appraises the restored
asset, records recovery evidence, and resumes service within the declared RTO without reducing the
minimum accepted release.
**Current baseline:** Host recovery pre-verifies DFIMBOOT v2 trust and rollback policy, performs
durable per-file replacement, and re-verifies the restored pair. Bounded multi-asset soak runs in CI;
destructive power-loss and authenticated UEFI-capsule qualification remain platform acceptance gates.

## AT-10 — Parser corruption and release maturity

**Threat:** `TM-04`, `TM-07`, `TM-08`  
**Target phase:** 7  
**Given:** Malformed, truncated, or adversarially crafted parser inputs and a tagged release candidate.  
**When:** Fuzz targets, CodeQL analysis, Kani proofs, and consumer SLSA v1.2 verification run on the
release commit.  
**Then:** No parser crash or panic occurs within the bounded fuzz budget; unresolved Critical/High
CodeQL findings block release; pinned Kani harnesses pass; digest and attestation verification reject
substituted bundles.  
**Current baseline:** Four libFuzzer targets cover Layer-0 and DFIMBOOT parsers; CodeQL runs on Rust
and Actions with `security-extended`; five Kani harnesses prove panic-freedom on a symbolic envelope;
tagged Linux releases attach GitHub provenance verifiable under SLSA v1.2 consumer rules.

## Cross-cutting parser and resource cases

Every phase additionally tests:

- Truncated, oversized, duplicate, trailing-garbage, and unsupported-version metadata.
- Integer overflow and maximum block/proof boundaries.
- Concurrent enrollment, execution, unenrollment, and policy rotation.
- Restart, power interruption, partial write, and stale map/registry state.
- Audit destination unavailable while an integrity failure occurs.

## Evidence and pass rules

- Each automated test stores command line, commit, platform identity, result, and relevant logs.
- A security test passes only when the enforcement result and the required audit event both match.
- A timeout, kernel panic, verifier rejection, missing log, or skipped destructive step is not a pass.
- Claims in audit documents must link to immutable CI artifacts; prose-only "PASS" claims are insufficient.
- All Critical and High failures block release unless a time-bounded, approved exception exists.

## Phase gates

- **Phase 1:** AT-01 through AT-04 pass.
- **Phase 2:** AT-05 and AT-06 pass across host, Linux, and UEFI consumers.
- **Phase 3:** AT-07 passes on simulator and qualified hardware.
- **Phase 4:** AT-09 passes with publisher workflow identity and artifact digest enforcement.
- **Phase 5:** AT-08 and the declared soak/recovery suite pass.
- **Phase 6:** Telemetry schema, fail-closed audit sink, and bounded soak profile pass.
- **Phase 7:** Parser fuzz targets, CodeQL, Kani proofs, and SLSA v1.2 consumer verification pass;
  platform-only AT-01 through AT-04 and AT-07 hardware steps remain external qualification gates.
