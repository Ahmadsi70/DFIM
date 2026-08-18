# DFIM Compliance Mapping

**Document ID:** DFIM-COMP-2026-V1.0  
**Purpose:** Map DFIM technical and process controls to ISO/IEC 27001:2022 Annex A themes and common
telecommunications procurement clauses. This is an **implementation mapping**, not a certification
statement.

## Scope boundary

| In scope | Out of scope |
|----------|--------------|
| Integrity of enrolled firmware/executables | Endpoint malware detection |
| Signed metadata, audit JSONL, attestation | Full SOC/SIEM platform |
| Supply-chain attestations and SBOM | Customer GRC program ownership |

## ISO/IEC 27001:2022 — selected Annex A mapping

| Control theme | Annex A (2022) | DFIM evidence | Residual owner action |
|---------------|----------------|---------------|------------------------|
| Configuration management | 8.9 | `phase0-policy.json`, `ENFORCEMENT_POLICY.md`, signed DFIMBOOT v2 | Change board for release counters |
| Information deletion / retention | 8.10 | `TELEMETRY.md` retention guidance, redacted JSONL | Legal retention schedule |
| Data masking | 8.11 | Pseudonymous `asset_id`, no raw paths in JSONL | Access control on audit files |
| Monitoring activities | 8.16 | JSONL + OTel Collector, Grafana ops stack | SOC alert routing |
| Clock synchronization | 8.17 | UTC timestamps in audit; TPM `clockInfo.safe` gate | NTP on hosts |
| Use of privileged utilities | 8.18 | Root required for eBPF/IMA attach only | Privileged access management |
| Software installation | 8.19 | Attested release bundles, `CROSS_PLATFORM_RELEASE.md` | Approved artifact registry |
| Network security | 8.20 | OTLP TLS/auth is operator responsibility | Network team |
| Security of network services | 8.21 | N/A — DFIM is host integrity, not network service | — |
| Segregation in networks | 8.22 | Protected-scope limits blast radius to enrolled assets | Architecture review |
| Web filtering | 8.23 | N/A | — |
| Cryptography | 8.24 | P-256 DFIMBOOT v2, SHA-256 Merkle, TPM quotes | HSM/KMS for production keys |
| Secure development lifecycle | 8.25 | CI phases 0–12, fuzz/CodeQL/Kani, contracts | Pen-test closure |
| Application security | 8.26 | Parser bounds, fail-closed CLI, AT tests | External pen-test |
| Secure system architecture | 8.27 | Layered UEFI/host/eBPF model in `THREAT_MODEL.md` | Deployment review |
| Secure coding | 8.28 | Rust `#![deny(unsafe_code)]` in core, clippy `-D warnings` | — |
| Security testing | 8.29 | Fuzz, Kani, adversarial acceptance AT-01..09 | Platform qualification |
| Change management | 8.32 | Monotonic release counters, rollback baselines | CAB approval |
| Test information | 8.33 | Synthetic fixtures only in CI; no prod data in repo | Test data policy |
| Protection against malware | 8.7 | **Partial** — integrity enforcement, not AV | AV remains separate control |
| Backup | 8.13 | Recovery artifacts + `RECOVERY.md` | Offline recovery media custody |
| Redundancy | 8.14 | Stateless verify; sidecar replay from CMDB | HA architecture |
| Logging | 8.15 | `DFIM_TELEMETRY_OUT`, SIEM mapping in `ENTERPRISE_INTEGRATION.md` | Log shipping SLA |

## Telecommunications procurement clauses (typical)

| Clause topic | DFIM response | Reference |
|--------------|---------------|-----------|
| Sub-100 ms validation SLA (controlled host) | Host verify path benchmarked; exclusions documented | `ENTERPRISE_INTEGRATION.md` §2 |
| Billing/core node integrity | Protected-scope enrollment for fixed executables | `ENFORCEMENT_POLICY.md` |
| Lawful intercept / metadata minimization | Redacted audit schema | `TELEMETRY.md` |
| Supply-chain integrity | CycloneDX SBOM + GitHub attestations | `SUPPLY_CHAIN.md`, `CROSS_PLATFORM_RELEASE.md` |
| Disaster recovery | `recover-v2` + capsule runbook | `RECOVERY.md`, `UEFI_CAPSULE_RECOVERY.md` |
| Remote attestation | TPM quote protocol | `REMOTE_ATTESTATION.md`, AT-07 evidence |
| 24×7 support | See `ENTERPRISE_SLA.md` | Commercial schedule |
| Penetration test | Scope in `PEN_TEST_SCOPE.md` | Third-party report |

## Phase 0 control cross-reference

| ID | Compliance relevance |
|----|---------------------|
| P0-C1 | ISO 8.24, 8.26 — live content enforcement |
| P0-C2 | Telecom blast-radius — scoped denial |
| P0-C3 | ISO 8.9 — fail-closed policy |
| P0-C4..C8 | See `phase0-policy.json` and linked security docs |

## Auditor checklist

1. Confirm deployment profile is **protected-scope** (not global allowlist).
2. Verify production builds use `--features production` and HSM-backed signing.
3. Collect Phase 0–12 contract PASS logs from CI for the release commit.
4. Collect platform qualification artifacts (AT-01..04, AT-07, AT-08) for the target kernel.
5. Review pen-test report against `PEN_TEST_SCOPE.md` with zero open Critical/High.
