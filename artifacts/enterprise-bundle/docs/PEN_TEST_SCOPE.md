# DFIM External Penetration Test Scope

**Document ID:** DFIM-PENTEST-SCOPE-2026-V1.0  
**Audience:** Third-party assessors, customer security teams

## Objective

Validate that DFIM host, parser, and enrollment boundaries resist practical tamper and bypass
attempts without claiming antivirus or network perimeter coverage.

## In-scope assets

| Surface | Location | Focus |
|---------|----------|-------|
| Parser envelope | `dfim_core_engine`, `dfim_windows_uefi` | Memory safety, panic, bounds bypass |
| CLI provisioner | `dfim_cli_provisioner` | Subcommand authZ, sidecar injection, path traversal |
| DFIMBOOT v2 | Signed sidecar verification | Forged signature, rollback, key substitution |
| eBPF policy gate | `dfim-ebpf` + `enforcement_policy.rs` | Unprotected bypass, config downgrade |
| Attestation verifier | `attestation.rs` | Quote replay, PCR substitution, nonce reuse |
| Recovery path | `recovery.rs` | Unauthorized image, rollback, partial write abuse |
| Telemetry sink | `telemetry_sink.rs`, `siem_sink.rs` | Log injection, path exfiltration via env |

## Out of scope

- Customer network penetration, phishing, or physical datacenter access
- Windows kernel, Linux kernel, or UEFI firmware unrelated to DFIM hooks
- Denial-of-service at cloud scale ( volumetric )
- FIPS 140-3 module validation (separate regulated track)

## Required test categories

1. **Parser fuzzing confirmation** — reproduce or extend existing libFuzzer targets; no new crashes at default caps.
2. **Trust bypass** — attempt execution with tampered image, valid sidecar, invalid signature, stale release.
3. **Enrollment abuse** — delete metadata/map without authorized unenroll; confirm protected deny persists (AT-03).
4. **Policy downgrade** — malformed `DFIM_CONFIG`; confirm protected-only deny (AT-04).
5. **Attestation replay** — reuse quote with fresh nonce; must fail (AT-07).
6. **Recovery abuse** — supply rollback-valid but policy-rejected bundle; target must remain unchanged.
7. **Audit integrity** — confirm JSONL rejects raw paths and fails closed when sink unavailable.

## Severity and release policy

| Severity | Release policy |
|----------|----------------|
| Critical | Block enterprise claim until fixed and regression test added |
| High | Block until fixed or accepted risk with compensating control |
| Medium | Time-bound remediation in `RELEASE_MATURITY.md` triage |
| Low / Info | Document in pen-test appendix |

## Evidence deliverables

Assessor provides:

- Executive summary (≤ 2 pages)
- Finding list with CVSS or equivalent
- Reproduction steps and commit/tag tested
- Retest confirmation for closed Critical/High items

Customer attaches report to pilot evidence bundle referenced in `PILOT_CASE_STUDY_TEMPLATE.md`.

## Suggested duration

| Environment | Duration |
|-------------|----------|
| Repository + lab VM (no prod) | 5–10 business days |
| Pilot production segment (read-only + lab mirror) | 10–15 business days |

## Repository self-assessment already performed

- Bounded fuzz (Phase 7)
- CodeQL `security-extended` (Phase 7)
- Kani proofs on core gates (Phase 7)
- Adversarial acceptance design AT-01..09

External pen-test **supplements** but does not replace platform qualification gates.
