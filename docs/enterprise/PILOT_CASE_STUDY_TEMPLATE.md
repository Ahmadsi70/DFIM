# DFIM Pilot Case Study Template (Telecom / Core Infrastructure)

**Document ID:** DFIM-PILOT-TEMPLATE-2026-V1.0

## 1. Executive summary

| Field | Value |
|-------|-------|
| Customer segment | e.g. mobile core / billing / DNS |
| Pilot duration | 90 days |
| Nodes enrolled | 2–5 fixed executables |
| Outcome | Pass / Conditional / Fail |

## 2. Scope

- Assets enrolled (role only — no raw paths in external report)
- Release counter baseline
- SOC integration (JSONL → SIEM)

## 3. Metrics

| Metric | Target | Observed |
|--------|--------|----------|
| Verify success rate | > 99.9% | |
| Mean verify latency (p95) | < 100 ms | |
| Recovery RTO (host) | < 15 min | |
| False-positive denies | 0 | |
| Audit sink fail-closed events | 0 unplanned |

## 4. Incidents simulated

| Drill | Date | Result | Evidence path |
|-------|------|--------|---------------|
| Tamper detect (AT-01 style) | | | |
| Authorized recovery | | | |
| SOC alert routing | | | |

## 5. Qualification artifacts attached

- [ ] AT-01..04 lab logs (`LINUX_QUALIFY.md`)
- [ ] AT-07 swtpm or hardware TPM evidence
- [ ] AT-08 power-loss plan (if executed)
- [ ] Pen-test summary (zero Critical/High open)
- [ ] Release attestation verification (`CROSS_PLATFORM_RELEASE.md`)

## 6. Recommendation

**Expand / Hold / Exit** with conditions for production SLA (`ENTERPRISE_SLA.md`).

## 7. Approvals

| Role | Name | Date |
|------|------|------|
| Customer security | | |
| Customer operations | | |
| Vendor engineering | | |
