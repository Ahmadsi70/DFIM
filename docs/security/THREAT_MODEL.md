# DFIM Enterprise Threat Model

**Document ID:** DFIM-SEC-TM-2026-V1.0  
**Status:** Approved baseline for implementation  
**Policy source:** `security/phase0-policy.json`

## 1. Security objective

DFIM protects explicitly enrolled firmware and executable assets against unauthorized modification,
metadata substitution, rollback, and execution after integrity loss. The required lifecycle follows
NIST SP 800-193: **protect, detect, recover**.

DFIM is one security control in a defense-in-depth system. It does not replace Secure Boot, operating
system access control, endpoint detection, backup, key management, or vulnerability management.

## 2. Protected assets

- Boot and firmware images enrolled in DFIM.
- Linux executables and kernel modules explicitly enrolled in the protected scope.
- `.dfim` manifests, Merkle proofs, release counters, and policy configuration.
- UEFI, eBPF, user-space loader, provisioner, and recovery artifacts.
- Signing keys, TPM authorization data, CI identities, release provenance, and audit events.

## 3. Trust boundaries

1. **Build boundary:** source and dependencies enter a controlled build; signed artifacts, SBOM, and
   provenance leave it.
2. **Provisioning boundary:** an authorized image becomes a protected asset and receives policy and
   integrity metadata.
3. **Host-to-kernel boundary:** user-space policy and enrollment data enter IMA/eBPF enforcement.
4. **Host-to-firmware boundary:** the UEFI guard consumes an image, sidecar, and trust anchor.
5. **Platform-to-TPM boundary:** measurements and counters enter TPM PCR/NV; nonce-bound quotes leave it.
6. **Recovery boundary:** an authorized recovery source replaces a failed protected asset.
7. **Audit boundary:** security events leave the enforcement layer for an append-only SIEM destination.

## 4. Adversary capabilities

The design assumes an attacker may:

- Modify, replace, truncate, or replay images and sidecars on writable storage.
- Race provisioning and execution, or modify a file after it is enrolled.
- Supply malformed parser input and oversized metadata.
- Restart a host, restore an old disk snapshot, or replay old attestation evidence.
- Execute unprivileged code and exploit a privileged service outside DFIM.
- Read public binaries and file formats.

The following are outside the initial guarantee and require platform controls: physical attacks against
the TPM, compromised CPU/firmware roots of trust, a fully compromised signing authority, and malicious
hardware below the measured boundary.

## 5. Threat register

### TM-01 — Live-file TOCTOU

**Threat:** The current Linux eBPF path validates a previously copied `DFIM_IMAGES` snapshot rather than
the bytes that will execute. An image changed after provisioning can diverge from the validated snapshot.

**Current exposure:** Critical.  
**Required control:** `P0-C1`; production Linux content enforcement uses IMA appraisal. eBPF remains
responsible for protected-scope policy and telemetry, not proof of current file contents.  
**Success evidence:** `AT-01`.

### TM-02 — Global denial of unprovisioned executables

**Threat:** The current eBPF LSM denies any inode absent from `DFIM_MANIFESTS`, which can make a general
purpose host unavailable and turn policy loss into a system-wide outage.

**Current exposure:** Critical.  
**Required control:** `P0-C2`; only explicitly enrolled assets are protected. Unprotected assets follow
the operating system's normal policy.  
**Success evidence:** `AT-02` and `AT-03`.

### TM-03 — Policy downgrade or unresolved state

**Threat:** `DFIM_CONFIG` is populated but not consumed by the probe. A missing or malformed policy can
create ambiguous enforcement behavior.

**Current exposure:** Critical.  
**Required control:** `P0-C3`; unresolved state denies protected assets only, emits a critical event, and
never silently changes to monitor mode.  
**Success evidence:** `AT-04`.

### TM-04 — Metadata forgery

**Threat:** `DFIMBOOT v1` is not signed. The `DFIMSTAT v1` envelope uses an unkeyed SHA-256 checksum, so
the term "authenticated" in current source comments must not be interpreted as organizational
authenticity.

**Current exposure:** Critical when an attacker can replace both image and metadata.  
**Required control:** `P0-C4`; DFIMBOOT v2 requires an asymmetric signature and key identifier anchored
in an organizational trust store.  
**Success evidence:** `AT-05`.

### TM-05 — Authorized-image rollback

**Threat:** A previously valid image and matching v1 sidecar can be replayed after a newer release.

**Current exposure:** Critical.  
**Required control:** `P0-C5`; bind the accepted release counter to TPM NV or an authenticated remote
baseline registry.  
**Success evidence:** `AT-06`.

### TM-06 — Attestation replay

**Threat:** Extending a Merkle root into PCR-14 does not prove freshness or identity to a remote verifier.

**Current exposure:** High.  
**Required control:** `P0-C6`; issue a TPM quote bound to a verifier nonce, device identity, selected
PCRs, policy version, and release counter.  
**Success evidence:** `AT-07`.

### TM-07 — Detection without trustworthy recovery

**Threat:** Fail-closed detection can cause prolonged outage if the authorized image, metadata, and
policy cannot be restored safely.

**Current exposure:** High.  
**Required control:** `P0-C7`; maintain signed recovery artifacts, defined RTO/RPO, tested rollback-safe
restore, and audit evidence.  
**Success evidence:** corruption is denied, restored from an authorized source, and verified before
service resumes.

### TM-08 — Compromised build or substituted release artifact

**Threat:** A dependency, CI action, build worker, SBOM, or release binary is substituted so that
consumers receive an artifact not produced from the reviewed DFIM source and lockfile.

**Current exposure:** High.  
**Required control:** `P0-C8`; pin the Rust toolchain and security tools, enforce advisory/license/source
policy, generate a reproducible CycloneDX SBOM, and attach identity-bound GitHub provenance to release
artifacts.  
**Success evidence:** `AT-09`.

## 6. Invariants

1. A protected asset is never executed after current-content appraisal fails.
2. An unprotected asset is not denied solely because it lacks DFIM metadata.
3. Missing policy cannot silently weaken enforcement for a protected asset.
4. Metadata authenticity is rooted in a managed asymmetric trust anchor.
5. A valid but older protected release cannot replace the current minimum accepted release.
6. Remote attestation evidence is fresh and verifier-bound.
7. Recovery never bypasses verification or anti-rollback policy.
8. A release is rejected when its provenance, publisher identity, artifact digest, or SBOM binding fails.

## 7. Review triggers

This threat model must be reviewed when the sidecar format, enforcement hook, supported platform,
cryptographic provider, trust anchor, TPM policy, release workflow, recovery process, or protected
asset class changes.
