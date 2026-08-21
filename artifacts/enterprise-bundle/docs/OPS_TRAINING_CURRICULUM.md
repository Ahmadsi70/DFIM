# DFIM Operations Training Curriculum (2 Days)

**Document ID:** DFIM-TRAIN-OPS-2026-V1.0  
**Audience:** Platform operators, SOC liaisons

## Day 1 — Deploy and verify

| Module | Duration | Content | Lab |
|--------|----------|---------|-----|
| 1. Architecture | 90 min | Threat model, protected-scope, UEFI/host/Linux layers | — |
| 2. Production packaging | 60 min | HSM signing, `--features production`, release attestation | Verify tag bundle |
| 3. Provision v2 | 120 min | Sidecar generation, release counter, key ID | Provision sample image |
| 4. Verify oracles | 90 min | `verify-v2`, `--format json`, CMDB baseline | Scheduled verify script |
| 5. Telemetry | 60 min | `DFIM_TELEMETRY_OUT`, Collector, Grafana ops stack | Tail JSONL |

## Day 2 — Respond and qualify

| Module | Duration | Content | Lab |
|--------|----------|---------|-----|
| 6. Recovery | 120 min | `recover-v2`, sidecar-first commit, RTO measurement | Authorized restore drill |
| 7. Linux runtime | 90 min | eBPF provision, IMA checklist, SIEM deny events | Review qualify script |
| 8. Attestation | 60 min | Enroll, challenge, quote, verify (TPM or swtpm) | AT-07 transcript |
| 9. Evidence bundle | 60 min | Phase contracts, platform qualification, pen-test appendix | Build sales bundle |
| 10. Exam | 60 min | Scenario: tamper alert → verify fail → recovery → audit close | Instructor sign-off |

## Prerequisites

- Linux or Windows admin access to lab VM
- `DFIM_CRYPTO_KEY` for lab builds only
- Read `OPERATIONS_MANUAL.md` (test_environment)

## Completion criteria

- Successful provision + verify + recovery on lab asset
- JSONL event observed in SIEM or local Loki dashboard
- Participant can run `build_enterprise_sales_bundle.sh` and interpret checklist
