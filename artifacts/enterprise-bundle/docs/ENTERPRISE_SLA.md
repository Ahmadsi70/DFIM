# DFIM Enterprise SLA and Support

**Document ID:** DFIM-SLA-2026-V1.0  
**Audience:** Procurement, NOC/SOC leads

## Service tiers (template)

| Tier | Coverage | Initial response | Workaround target |
|------|----------|------------------|-------------------|
| **P1 — Integrity deny on protected core** | 24×7 | 1 hour | 4 hours |
| **P2 — Verify/audit pipeline failure** | Business hours + on-call | 4 hours | 1 business day |
| **P3 — Documentation / non-production** | Business hours | 2 business days | Next maintenance window |

## Performance SLA (host validation)

Applies to `dfim-provisioner verify` / `verify-v2` on a reference host meeting:

- Windows High Performance power plan or Linux `performance` governor
- Local SSD; target image ≤ 64 MiB enrolled block stream
- No active CPU throttling (see `ENTERPRISE_INTEGRATION.md` §2.3 exclusions)

**Target:** p95 < 100 ms per verify invocation on reference hardware.

Measurements under ACPI P-state scaling or non-reference storage are **informational only**.

## Support channels

| Channel | Use |
|---------|-----|
| Private ticket queue | Production incidents |
| Security alias | Coordinated vulnerability disclosure |
| Quarterly review | Release counter, key rotation, soak results |

## Training

Two-day operator curriculum: `docs/enterprise/OPS_TRAINING_CURRICULUM.md`

## Exclusions

- Kernel/IMA misconfiguration on customer image
- Missing HSM integration for production signing
- Antivirus or EDR interference with protected executables
- Customer SIEM/backend outage (local JSONL remains authoritative)

## Pilot → production promotion

Production SLA begins after:

1. 90-day pilot report (`PILOT_CASE_STUDY_TEMPLATE.md`)
2. Zero open Critical/High pen-test findings
3. Signed compliance mapping review (`COMPLIANCE_MAPPING.md`)
