# DFIM Product Security White Paper
## Integrity Enforcement — What DFIM Is, What It Is Not

**Document ID:** DFIM-SEC-WP-2026-V1.0  
**Audience:** Security reviewers, procurement, telecom/OT operators  
**Date:** 2026-08-14  
**Related:** `RFP_RESPONSE_BUNDLE.md`, `THREAT_MODEL.md`, `ENFORCEMENT_POLICY.md`, `PEN_TEST_SCOPE.md`

---

## 1. Position Statement

**DFIM is a deterministic integrity-enforcement system for explicitly enrolled firmware and
executables. It is not an antivirus and is not represented as one.**

DFIM answers one question, with cryptographic certainty:

> *"Has any enrolled file changed since its authorized baseline was captured?"*

It does **not** answer: *"is this new or unknown file malicious?"* That is the role of antivirus
(AV), endpoint detection and response (EDR), and behavioral analytics. The two paradigms are
complementary defense layers, not substitutes.

---

## 2. Defense Paradigms

| Attribute | Antivirus / EDR | DFIM |
|-----------|-----------------|------|
| Threat model | Identify **malicious** code (known or suspected) | Detect **any** deviation from an enrolled baseline |
| Decision basis | Signatures, heuristics, behavior, reputation, ML | Cryptographic digest + Merkle proof + signed metadata |
| Unknown/new files | Continuously evaluated (may block) | **Out of scope** unless explicitly enrolled |
| Known-good baseline | Not required | **Required** at enrollment time |
| False-positive framing | Classifies benign-but-suspicious as threat | Flags every change, including **legitimate updates** |
| Update handling | Allowed with vendor trust | Requires controlled re-provision by an operator |
| Guarantee | Probabilistic (heuristic coverage) | **Deterministic** for enrolled assets |

> **Bottom line:** AV answers *"is this thing hostile?"* DFIM answers *"is this thing what it was
> authorized to be?"* Both are needed; neither replaces the other.

---

## 3. What DFIM Actually Enforces

DFIM's enforcement chain (Windows host CLI / Linux eBPF-LSM+IMA / UEFI boot guard):

```
enroll ──► baseline (Merkle root + per-block proofs) ──► signed DFIMBOOT v2 metadata
                                                              │
                                                              ▼
                exec/open ──► scope check ──► recompute digest ──► compare vs baseline
                                                              │
                                                 ┌────────────┴───────────┐
                                                 │  match  ─────► allow   │
                                                 │  mismatch ───► deny    │
                                                 └────────────────────────┘
```

- **Protected scope:** only assets explicitly enrolled (by inode+device or path) are enforced.
  Unenrolled files are governed by OS controls only (`phase0-policy.json`:
  `unprotected_asset_action: allow`).
- **Deterministic outcome:** a changed enrolled file is denied with a fail-closed decision and an
  audit event. This is not a heuristic; it is a mathematical comparison.
- **Signed metadata:** production uses DFIMBOOT v2 (ECDSA P-256), key-ID binding, and monotonic
  release counters — so rollback and metadata forgery are rejected.

---

## 4. Empirical Evidence (Executed 2026-08-14, Lenovo i5-1235U host)

The following scenarios were executed against the release build to verify the boundary honestly:

| Scenario | What was tested | Result | Interpretation |
|----------|-----------------|--------|----------------|
| A — New unenrolled file | A 50 KB high-entropy "malware" file, never enrolled | DFIM has no baseline; file not blocked | **Out of scope.** DFIM does not prevent entry of new files. |
| B — Tamper on enrolled file | 1-bit flip in an enrolled binary (code injection) | **Denied** (`integrity verification failed`) | **Core capability.** Any change to an enrolled file is detected. |
| C — Entropy classification | 100 KB pure-random vs 100 KB all-zeros, both enrolled | Both verified **identically** | DFIM performs **no** entropy analysis; entropy is not a decision input. |
| D — Legitimate update | Enrolled app v1.0 → vendor patch v1.1 | **Denied** as tamper | **Operational cost.** Updates require authorized re-provision. |
| Dataset | 300 real Windows/ELF files: provision + verify + tamper | 300/300 provision, 300/300 verify, 100% tamper on actually-flipped files | Integrity operations are reliable at scale. |
| Fuzz | 3.5M pseudo-random + mutated inputs across 4 parsers | 0 panics, 0 crashes | Parsers are memory-safe on adversarial input. |

These results confirm: **DFIM reliably protects enrolled assets from any content modification,
including unknown/polymorphic payloads for which no signature exists — but it provides no
protection against files that are not enrolled.**

---

## 5. Where DFIM Adds Real Value (complementary to AV)

1. **Boot and firmware integrity** — detect tampering of UEFI images, kernels, and boot metadata
   that AV never sees (AV does not inspect the boot chain).
2. **Supply-chain / hostile-implant defense** — a payload injected into an enrolled binary is
   caught by DFIM even when AV has no signature and heuristic scores are low.
3. **Immutability enforcement in controlled environments** — telecom/OT nodes, kiosks, and
   appliances where software is static and updates are change-controlled; fail-closed deny on any
   drift.
4. **Post-breach detection** — evidence (JSONL audit, SIEM deny events) that an enrolled asset was
   modified, supporting incident response even if the modifying malware itself was novel.
5. **Attestation** — TPM-quote binding of enrolled baselines for remote verification (AT-07).

---

## 6. Honest Limitations (must be disclosed to customers)

| Limitation | Consequence |
|------------|-------------|
| Unenrolled files are not protected | A novel malware dropped into the system is not seen or blocked by DFIM |
| No maliciousness determination | DFIM cannot distinguish an exploit from a legitimate vendor patch |
| Baseline must be trusted | If enrollment happens after compromise, the compromised state becomes "known good" |
| Update friction | Every legitimate change requires authorized re-provisioning (recovery/re-provision flow) |
| Scope coverage | Deployment is protected-scope; DFIM is not a full-system allowlister by default |
| Platform gates still open | eBPF runtime (AT-01..04) and hardware TPM (AT-07) await real-platform qualification |

---

## 7. Recommended Deployment Model (honest positioning)

```
                  ┌─────────────────────────────────────────────┐
                  │  AV/EDR  — detects & blocks known/hostile    │
                  │  (first line for new and unknown code)       │
                  └─────────────────────────────────────────────┘
                                   +
                  ┌─────────────────────────────────────────────┐
                  │  DFIM — integrity of ENROLLED boot/host      │
                  │  (immune to signature gaps; boot-chain layer)│
                  └─────────────────────────────────────────────┘
                                   +
                  ┌─────────────────────────────────────────────┐
                  │  OS controls — Secure Boot, IMA/EVM, DAC     │
                  └─────────────────────────────────────────────┘
```

- **Do not** market or sell DFIM as "replacement for antivirus."
- **Do** sell DFIM as the integrity/anti-tamper layer for critical assets that must be immutable,
  especially in the boot chain and for firmware — where AV has no coverage.
- **Do** pair DFIM with AV/EDR for a defense-in-depth story. This combination is defensible in
  audits; a sole-product antivirus claim is not.

---

## 8. Claimed vs. Actual Capability (for internal use)

| Marketing claim to avoid | Accurate claim |
|--------------------------|----------------|
| "Detects/prevents viruses based on entropy" | Performs no entropy analysis; detects **any** change to **enrolled** files |
| "Prevents malware from entering the system" | Protects **enrolled** assets from modification; new files are out of scope |
| "Replaces antivirus" | Complements AV/EDR as the deterministic integrity layer |
| "Stops unknown attacks" | Stops unknown **modifications of enrolled assets** — without classifying intent |

---

*Approved for distribution. Questions and evidence pointers: see `THREAT_MODEL.md`,
`ENFORCEMENT_POLICY.md`, `RFP_RESPONSE_BUNDLE.md`.*
