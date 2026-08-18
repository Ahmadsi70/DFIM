# DFIMBOOT v2

DFIMBOOT v2 authenticates sidecar metadata before Merkle validation. Production UEFI builds reject
DFIMBOOT v1.

## Canonical signed layout

All integers are little-endian. ECDSA uses P-256/SHA-256 and fixed-width IEEE P1363 `r || s`.

- Offset 0, 8 bytes: `DFIMBOOT`.
- Offset 8, 4 bytes: version `2`.
- Offset 12, 4 bytes: header length `92`.
- Offset 16, 4 bytes: block size.
- Offset 20, 4 bytes: block count.
- Offset 24, 8 bytes: monotonic release counter.
- Offset 32, 16 bytes: key ID.
- Offset 48, 4 bytes: signature algorithm `1`.
- Offset 52, 4 bytes: signature length `64`.
- Offset 56, 32 bytes: Merkle root.
- Offset 88, 4 bytes: FEC length.
- Offset 92 onward: FEC metadata, proofs, then the 64-byte signature.

The signature covers every byte before the trailing signature. Parsing rejects non-canonical trailing
data, unknown algorithms, incorrect key IDs, stale counters, malformed proofs, and legacy v1 input.

## Rollback baseline

UEFI requires a `DFIMMinRelease` variable under vendor GUID
`3f33c545-c9a7-4b1d-89ee-76f1472dfb49`. The variable must be non-volatile, boot-service accessible,
and use `TIME_BASED_AUTHENTICATED_WRITE_ACCESS`; missing or weaker attributes halt boot.

Its 36-byte data payload is `DFIMROLL || version:u32 || minimum_release:u64 || key_id:[u8;16]`.
The effective floor is:

$$\operatorname{floor}_{effective}=\max(\operatorname{floor}_{compiled},
\operatorname{floor}_{authenticated\ UEFI})$$

Generate the data payload with `dfim-provisioner rollback-payload`. Platform PK/KEK tooling must wrap
and sign it as `EFI_VARIABLE_AUTHENTICATION_2`; the private platform key must never be placed on the
boot target.

## Build and provisioning

- Build the UEFI application with `DFIM_BOOT_PUBLIC_KEY_HEX`, `DFIM_BOOT_KEY_ID_HEX`, and
  `DFIM_BOOT_MIN_RELEASE`. A production build fails if any value is absent or malformed.
- Create sidecars with `provision-v2 --signing-key ... --key-id ... --release-counter ...`.
- Independently verify with `verify-v2 --public-key ... --key-id ... --minimum-release ...`.
- Local key files are a development path. Production release signing must use an isolated HSM/KMS
  signer and must not expose private key bytes to the target or CI logs.

RustCrypto verifies the protocol but is not itself evidence of FIPS 140-3 module validation.
