#![no_std]

extern crate alloc;

pub mod manifest;
pub mod pipeline;
pub mod rollback;
pub mod signed_manifest;

pub use manifest::{
    build_boot_sidecar, parse_boot_manifest, partition_image_blocks, serialize_boot_sidecar,
    BootManifest, DFIM_BLOCK_SIZE, MANIFEST_MAGIC, MANIFEST_VERSION, MAX_PROOF_STEPS,
};
pub use pipeline::{validate_boot_image, ValidatedBootImage};
pub use rollback::{
    build_rollback_baseline, effective_minimum_release, parse_rollback_baseline,
    ROLLBACK_BASELINE_LEN, ROLLBACK_BASELINE_MAGIC, ROLLBACK_BASELINE_VERSION,
};
pub use signed_manifest::{
    build_signed_boot_sidecar_v2, parse_and_verify_boot_sidecar_v2, public_key_sec1_from_private,
    validate_signed_boot_image_v2, TrustedManifestPolicy, ValidatedSignedBootImage,
    VerifiedBootManifest, SIGNED_MANIFEST_VERSION, V2_KEY_ID_LEN, V2_PUBLIC_KEY_LEN,
    V2_SIGNATURE_ALGORITHM, V2_SIGNATURE_LEN,
};
