# DFIM Enterprise Enforcement Policy

**Document ID:** DFIM-SEC-POL-2026-V1.0  
**Normative source:** `security/phase0-policy.json`

## 1. Deployment profile

The approved production profile is **protected-scope**, not global executable allowlisting.

- Assets become protected only through authenticated enrollment.
- Protected assets fail closed on content, metadata, policy, rollback, or trust-anchor failure.
- Assets outside the protected scope are not denied merely because DFIM metadata is absent.
- Monitor-only behavior is permitted in development and pilot profiles, never as an implicit fallback.

## 2. Linux enforcement architecture

### 2.1 IMA appraisal

Linux production deployments use **IMA appraisal** as the authoritative current-content enforcement
mechanism. It must appraise the file selected for execution or module loading at the kernel boundary.

The existing `DFIM_IMAGES` eBPF snapshot is useful for bounded validation experiments but is not accepted
as proof that the bytes currently on disk are the bytes being executed.

### 2.2 eBPF role

The eBPF LSM layer is retained for:

- Identifying whether an inode belongs to the protected scope.
- Applying the approved enforcement decision.
- Emitting bounded security telemetry.
- Correlating inode, policy version, release identity, and appraisal result.

It must not duplicate full-image storage in BPF maps for production enforcement.

### 2.3 `DFIM_CONFIG` contract

`DFIM_CONFIG` must become a versioned structure consumed by the probe. At minimum it carries:

- Schema version.
- Deployment profile.
- Policy generation.
- Protected-scope readiness.
- Telemetry enablement.

For protected assets, a missing, malformed, unsupported, or unresolved `DFIM_CONFIG` state is
**fail-closed**. For unprotected assets, the same condition does not create a global outage.

## 3. Decision matrix

1. **Unprotected asset + no DFIM metadata:** allow DFIM decision; normal OS controls still apply.
2. **Protected asset + valid current appraisal:** allow and optionally emit success telemetry.
3. **Protected asset + content mismatch:** deny and emit critical `dfim.integrity.failure`.
4. **Protected asset + missing/malformed metadata:** deny and emit high/critical metadata event.
5. **Protected asset + stale release counter:** deny as rollback.
6. **Protected asset + unknown policy/config:** deny protected asset and emit policy failure.
7. **Monitor profile + failure:** alert-only is allowed only when explicitly configured outside production.

## 4. Startup and lifecycle rules

- Enforcement attaches only after the policy schema, trust anchor, and protected-scope registry are ready.
- A command that loads probes without an enforcement policy is development-only and must be rejected by
  production packaging.
- Enrollment is atomic: policy and integrity metadata become visible before the asset is marked protected.
- Removal is authorized and atomic; deleting metadata alone never unprotects an enrolled asset.
- Policy updates use generation numbers and reject stale generations.
- Crash or daemon restart must not convert protected assets to unprotected assets.

## 5. Windows and UEFI policy

- UEFI remains fail-closed for enrolled boot assets.
- The image must be loaded from the same verified buffer to preserve the existing TOCTOU-safe property.
- DFIMBOOT v2 signatures must chain to a managed trust anchor compatible with the platform policy.
- Secure Boot and DFIM are complementary controls; neither is represented as a replacement for the other.
- Recovery media must enforce signature and anti-rollback checks before restoring service.

## 6. Metadata and key policy

- `DFIMBOOT v1` and `DFIMSTAT v1` are legacy integrity formats, not proof of publisher authenticity.
- Production enrollment requires signed DFIMBOOT v2 metadata.
- Signing private keys remain in HSM/KMS-backed custody and are never compiled into DFIM binaries.
- Verification keys are distributed through an authenticated platform or organizational trust store.
- Key rotation supports overlapping verification windows and explicit revocation.
- FIPS-regulated deployments use a currently validated FIPS 140-3 cryptographic module.

## 7. Audit requirements

Every deny, policy downgrade request, rollback attempt, trust-anchor failure, and recovery action records:

- Schema and policy version.
- Asset identity and enforcement layer.
- Expected and observed integrity identity.
- Release counter and key identifier when available.
- Action taken and stable reason code.
- Correlation identifier and UTC timestamp.

Audit delivery failure must not change an integrity deny into an allow.

## 8. Phase-1 implementation boundary

Phase 1 is complete only when `P0-C1`, `P0-C2`, and `P0-C3` are implemented and the corresponding
`AT-01` through `AT-04` tests pass on a supported Linux kernel. Sidecar v2, TPM quotes, and recovery
automation remain later gated phases and must not be claimed as implemented during Phase 1.
