//! Deterministic Firmware Integrity Matrix — Layer-0 core engine.

#![no_std]
#![deny(unsafe_code)]

#[cfg(feature = "hardening")]
#[macro_use]
extern crate litcrypt2_nostd;

#[cfg(feature = "hardening")]
use_litcrypt!();

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod boot_validate;
#[cfg(feature = "bpf")]
pub mod bpf_sha256;
pub mod constants;
pub mod crypto;
pub mod digest;
pub mod enforcement_policy;
pub mod error;
#[cfg(feature = "full")]
pub mod fips;
pub mod hamming;
pub mod ima_policy;
pub mod integrity_gate;
pub mod merkle;
pub mod observer;
#[cfg(feature = "alloc")]
pub mod parser;
#[cfg(feature = "alloc")]
pub mod state_db;

pub mod secrets;

#[cfg(feature = "full")]
pub mod kdf;
#[cfg(feature = "full")]
pub mod phasor;

#[cfg(feature = "bpf")]
pub use boot_validate::resolve_metadata_into;
pub use boot_validate::{
    resolve_metadata_compact, validate_block_count, validate_image_byte_len, CompactManifest,
    CompactProof, DFIM_BLOCK_SIZE, MAX_BOOT_BLOCKS, MAX_FEC_BACKUP, MAX_IMAGE_BYTES,
    MAX_PROOF_STEPS,
};
#[cfg(feature = "bpf")]
pub use boot_validate::{
    resolve_metadata_from_scratch, validate_block_from_scratch, BpfValidateScratch,
};
#[cfg(not(feature = "bpf"))]
pub use boot_validate::{validate_block_compact, validate_boot_image_compact};
#[cfg(feature = "bpf")]
pub use bpf_sha256::Sha256Workspace;
pub use constants::*;
pub use crypto::constant_time_hash_eq;
#[cfg(not(feature = "bpf"))]
pub use digest::{
    digest_to_hex, manifest_digest, sha256_digest, sha256_digest_chunked, SHA256_LEN,
};
#[cfg(feature = "bpf")]
pub use digest::{digest_to_hex, sha256_digest, SHA256_LEN};
pub use error::{DfimError, DfimResult};
pub use hamming::{
    codeword_bit_length, decode_bits, decode_block_into, decode_block_into_strict, encode_bits,
    is_parity_position, parity_bit_count,
};
#[cfg(feature = "alloc")]
pub use hamming::{decode_block, encode_block};
pub use integrity_gate::{assert_block_index, assert_image_bounds, assert_target_path};
pub use merkle::{leaf_hash, parent_hash};
#[cfg(feature = "alloc")]
pub use merkle::{verify_proof, MerkleProof, MerkleTree};
pub use merkle::{ProofSide, ProofStep};
#[cfg(feature = "full")]
pub use observer::PatternObserver;
#[cfg(feature = "alloc")]
pub use parser::{
    parse_block_stream, parse_uefi_variable, BlockStreamManifest, BLOCK_STREAM_MAGIC,
    BLOCK_STREAM_VERSION,
};
#[cfg(feature = "alloc")]
pub use state_db::{
    parse_authenticated_state_db, wrap_authenticated_state_db, BOOT_SIDECAR_MAGIC,
    MIN_WRAPPED_STATE_LEN, WRAPPED_STATE_MAGIC,
};

#[cfg(feature = "full")]
pub use kdf::{
    authenticate_manifest, authentication_tag, canonical_manifest_bytes, derive_authentication_key,
    derive_salt, hkdf_sha256_expand, AuthKey, AuthSeed, AuthTag,
};
#[cfg(feature = "full")]
pub use phasor::{build_identity_hash, build_identity_hex, PhasorTerm};
