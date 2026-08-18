# DFIM RFP Response Bundle

**Document ID:** DFIM-RFP-2026-V1.0  
**Format:** Twenty procurement questions with evidence pointers — sales-ready baseline.

---

### Q1. What problem does DFIM solve?

DFIM provides **deterministic integrity enforcement** for explicitly enrolled firmware and executables
using Merkle proofs, signed DFIMBOOT v2 metadata, and fail-closed policy gates — not broad malware
detection.

**Evidence:** `THREAT_MODEL.md`, `ENFORCEMENT_POLICY.md`

---

### Q2. Is DFIM an antivirus replacement?

**No.** DFIM complements AV/EDR by enforcing cryptographic integrity on enrolled boot and host assets.
Unenrolled executables remain governed by OS controls only (protected-scope model).

**Evidence:** `phase0-policy.json` (`unprotected_asset_action: allow`)

---

### Q3. Which platforms are supported?

Linux (eBPF + IMA), Windows host CLI, UEFI boot guard. Attested release bundles for all three on tag
`v*`.

**Evidence:** `CROSS_PLATFORM_RELEASE.md`

---

### Q4. How is integrity metadata authenticated?

Production requires **DFIMBOOT v2** with P-256 signatures, key ID binding, and monotonic release
counters. Legacy v1 is integrity-checksum only.

**Evidence:** `DFIMBOOT_V2.md`

---

### Q5. How are signing keys protected?

Production keys must reside in **HSM/KMS** organizational custody; never in repo or operator laptops.

**Evidence:** `PRODUCTION_PACKAGING.md`

---

### Q6. What audit trail is produced?

Redacted JSONL via `DFIM_TELEMETRY_OUT` (verify, provision, recovery, SIEM deny events). Optional
OpenTelemetry Collector forward.

**Evidence:** `TELEMETRY.md`, `ENTERPRISE_INTEGRATION.md`

---

### Q7. What is the sub-100 ms validation claim?

Host verify path target on reference hardware under High Performance power settings. Exclusions
documented for throttled hosts.

**Evidence:** `ENTERPRISE_INTEGRATION.md` §2, `ENTERPRISE_SLA.md`

---

### Q8. How does Linux runtime enforcement work?

IMA appraisal is authoritative for current content; eBPF LSM applies protected-scope policy and
emits deny telemetry.

**Evidence:** `ENFORCEMENT_POLICY.md`, `LINUX_QUALIFY.md`

---

### Q9. How is rollback prevented?

UEFI variable floor + DFIMBOOT v2 release counter + verifier policy minimum release.

**Evidence:** `DFIMBOOT_V2.md`, AT-06 in `ADVERSARIAL_ACCEPTANCE.md`

---

### Q10. What recovery options exist?

Host: `recover-v2` with pre/post verification. Firmware: authenticated UEFI FMP capsule per platform
runbook.

**Evidence:** `RECOVERY.md`, `UEFI_CAPSULE_RECOVERY.md`

---

### Q11. Is TPM remote attestation supported?

Yes — ECC P-256 AK quotes over PCR 0/2/4/7/14 with nonce-bound challenges. CI gate on swtpm (AT-07).

**Evidence:** `REMOTE_ATTESTATION.md`, `PLATFORM_QUALIFICATION.md`

---

### Q12. Is the product FIPS 140-3 certified?

**Not as a standalone product.** Regulated customers must use a validated cryptographic module and
HSM for signing; mapping in compliance doc.

**Evidence:** `COMPLIANCE_MAPPING.md`, `SECURITY.md`

---

### Q13. What supply-chain assurances exist?

Locked dependencies (`cargo deny`), CycloneDX SBOM, GitHub attestations, reproducible release bundles.

**Evidence:** `SUPPLY_CHAIN.md`, `RELEASE_MATURITY.md`

---

### Q14. What security testing is automated?

Fuzz (4 parser targets), CodeQL, Kani proofs, Phase 0–12 contracts, recovery soak, swtpm attestation.

**Evidence:** `.github/workflows/ci.yml`, `RELEASE_MATURITY.md`

---

### Q15. What external testing is required before enterprise contract?

Independent pen-test per `PEN_TEST_SCOPE.md` with zero open Critical/High at signing.

---

### Q16. What telecommunications use cases fit?

Fixed core nodes: billing gateways, DNS/auth services, boot chains, OT-style static executables — **not**
consumer endpoints or dynamic serverless workloads.

**Evidence:** `COMPLIANCE_MAPPING.md` telecom table

---

### Q17. What is the pilot model?

90-day pilot on 2–5 core nodes: provision v2 → scheduled verify → SOC alerts → recovery drill →
management report.

**Evidence:** `PILOT_CASE_STUDY_TEMPLATE.md`

---

### Q18. What training is included?

Two-day ops curriculum: provision, verify, recovery, telemetry, qualification evidence collection.

**Evidence:** `OPS_TRAINING_CURRICULUM.md`

---

### Q19. What SLA is offered?

Template tiers in `ENTERPRISE_SLA.md` — P1 1h response for protected-core integrity incidents.

---

### Q20. What evidence bundle accompanies a tender response?

Run `bash tools/build_enterprise_sales_bundle.sh` to produce `artifacts/enterprise-bundle/` containing
this RFP bundle, compliance mapping, pen-test scope, SLA, security doc index, and contract checklist.

**Evidence:** `tools/verify_phase12_contract.py`
