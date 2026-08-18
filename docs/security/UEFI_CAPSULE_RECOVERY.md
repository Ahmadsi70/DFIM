# UEFI Authenticated Capsule Recovery

## Purpose

Host `recover-v2` restores disk-resident protected images. Firmware-resident boot assets require the
platform Root of Trust for Recovery (RTRec) using authenticated UEFI Firmware Management Protocol
(FMP) capsules.

## Capsule requirements

| Field | Requirement |
|-------|-------------|
| Payload | Signed DFIMBOOT v2 boot image matching enrolled key ID |
| Authentication | `EFI_FIRMWARE_IMAGE_AUTHENTICATION` or `EFI_VARIABLE_AUTHENTICATION_2` per platform policy |
| Monotonic counter | Release floor must not decrease relative to enrolled rollback state |
| Delivery API | `UpdateCapsule()` with runtime or boot-service capsule per vendor runbook |

## Operator workflow

1. Build authorized recovery `.efi` and signed sidecar offline (HSM-backed signing).
2. Package into vendor-approved FMP capsule format with authentication wrapper.
3. Stage capsule on recovery media or management controller with read-only access controls.
4. Boot into maintenance mode; invoke platform `UpdateCapsule` tooling.
5. Reboot and confirm DFIM UEFI boot guard verifies the new image before handoff to Windows Boot Manager.
6. Run host `verify-v2` against the on-disk image if a mirrored copy exists for audit correlation.

## Failure modes

| State | Expected behavior |
|-------|-------------------|
| Capsule signature invalid | Update rejected; prior firmware remains active |
| Rollback attempt | Rejected at capsule authentication or DFIMBOOT v2 floor |
| Interrupted update | Platform RTRec policy applies; repeat from known-good capsule |

## Relationship to AT-08

Power-loss during **host** recovery is qualified with `tools/qualify_at08_power_loss.sh`.
Power-loss during **firmware** capsule application is a separate platform test recorded in the
same evidence bundle with capsule-specific logs.

## Out of scope for host CLI

`dfim-provisioner` does not emit capsules. Integration belongs to OEM/platform firmware tooling
coordinated with the DFIM release artifact `dfim-uefi-x86_64.tar.gz`.
