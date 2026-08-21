# DFIM Authenticated Recovery

## Security contract

The recovery path follows the protection, detection, and recovery model of NIST SP 800-193. Recovery
never weakens normal verification: an artifact must pass DFIMBOOT v2 signature, key-ID, Merkle, image
bounds, and anti-rollback checks before any protected file is changed. The restored files are read back
and verified again before success is reported.

Host recovery writes a new file beside its destination with create-new semantics, copies existing
permissions, flushes file content, atomically renames it, and flushes the restored file. Unix platforms
also flush the containing directory. The signed sidecar is committed sidecar-first and the image second.
A power interruption can therefore leave either the old pair, the new pair, or a mismatched pair; the
mismatched state remains fail-closed and is safely repairable by repeating the operation.

Firmware recovery must use an authenticated UEFI FMP capsule and the platform `UpdateCapsule` flow.
The host command is not a substitute for a firmware Root of Trust for Recovery.

## Command

`dfim-provisioner recover-v2` requires the protected target, an authorized recovery image and signed
sidecar, the enrolled P-256 public key and key ID, and the current minimum release counter. Recovery
artifacts must be stored read-only outside the writable protected-asset boundary.

## Availability objectives

- RPO: zero accepted release-floor rollback; recovery never lowers the supplied minimum release.
- Host RTO: 15 minutes for one protected asset, measured from detection through successful post-restore
  verification. Platform owners must define a stricter service-specific objective where required.
- Firmware RTO: deployment-specific and measured through the authenticated capsule/RTRec procedure.

## Scalability and interruption gate

The ignored `scalability_soak_recovers_many_assets` test repeatedly corrupts and restores independent
assets. CI runs a bounded profile; qualification runs set `DFIM_SOAK_ASSETS` and `DFIM_SOAK_CYCLES`
for the declared fleet tier. Power-loss qualification remains a destructive QEMU/physical-platform
test and must demonstrate that every interrupted state denies execution or completes verified recovery.
