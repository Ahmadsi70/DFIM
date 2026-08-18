//! DFIMBOOT v2 signed metadata and anti-rollback verification.

use alloc::vec::Vec;

use dfim_core_engine::{
    constant_time_hash_eq, encode_block, validate_block_count, validate_image_byte_len, DfimError,
    DfimResult, MerkleProof, MerkleTree, ProofStep, SHA256_LEN,
};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};

use crate::manifest::{
    partition_image_blocks, BootManifest, DFIM_BLOCK_SIZE, MANIFEST_MAGIC, MAX_PROOF_STEPS,
};
use crate::pipeline::{validate_boot_image, ValidatedBootImage};

/// Signed sidecar format version.
pub const SIGNED_MANIFEST_VERSION: u32 = 2;
/// Fixed P1363 ECDSA P-256 signature size.
pub const V2_SIGNATURE_LEN: usize = 64;
/// Compressed SEC1 P-256 public key size.
pub const V2_PUBLIC_KEY_LEN: usize = 33;
/// Organizational key identifier size.
pub const V2_KEY_ID_LEN: usize = 16;
/// ECDSA P-256 with SHA-256 algorithm identifier.
pub const V2_SIGNATURE_ALGORITHM: u32 = 1;
/// Canonical fixed header size before FEC and proofs.
pub const V2_HEADER_LEN: usize = 92;
/// Offset of the signed Merkle root within the v2 header.
pub const V2_MERKLE_ROOT_OFFSET: usize = 56;

const V2_RELEASE_OFFSET: usize = 24;
const V2_KEY_ID_OFFSET: usize = 32;
const V2_ALGORITHM_OFFSET: usize = 48;
const V2_SIGNATURE_LEN_OFFSET: usize = 52;
const V2_FEC_LEN_OFFSET: usize = 88;

/// Trust anchor and monotonic release floor required for v2 verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedManifestPolicy {
    pub public_key_sec1: [u8; V2_PUBLIC_KEY_LEN],
    pub expected_key_id: [u8; V2_KEY_ID_LEN],
    pub minimum_release: u64,
}

/// Authenticated v2 metadata returned only after signature and rollback checks pass.
pub struct VerifiedBootManifest {
    pub manifest: BootManifest,
    pub release_counter: u64,
    pub key_id: [u8; V2_KEY_ID_LEN],
}

/// Complete trusted result combining v2 authenticity, rollback, and Merkle image validation.
pub struct ValidatedSignedBootImage {
    pub boot: ValidatedBootImage,
    pub release_counter: u64,
    pub key_id: [u8; V2_KEY_ID_LEN],
}

/// Derives the compressed public key used to build a deployment trust policy.
pub fn public_key_sec1_from_private(private_key: &[u8; 32]) -> DfimResult<[u8; V2_PUBLIC_KEY_LEN]> {
    let signing_key =
        SigningKey::from_bytes(&(*private_key).into()).map_err(|_| DfimError::InvalidParameter)?;
    let encoded = VerifyingKey::from(&signing_key).to_sec1_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != V2_PUBLIC_KEY_LEN {
        return Err(DfimError::IntegrityFailure);
    }
    let mut public_key = [0u8; V2_PUBLIC_KEY_LEN];
    public_key.copy_from_slice(bytes);
    Ok(public_key)
}

/// Builds and deterministically signs a canonical DFIMBOOT v2 sidecar.
pub fn build_signed_boot_sidecar_v2(
    image: &[u8],
    private_key: &[u8; 32],
    key_id: [u8; V2_KEY_ID_LEN],
    release_counter: u64,
) -> DfimResult<Vec<u8>> {
    validate_image_byte_len(image.len())?;
    if release_counter == 0 {
        return Err(DfimError::InvalidParameter);
    }

    let blocks = partition_image_blocks(image, DFIM_BLOCK_SIZE)?;
    let block_count = blocks.len() as u32;
    let refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    let tree = MerkleTree::build(&refs)?;
    let root = *tree.root();

    let mut metadata = [0u8; 40];
    metadata[..SHA256_LEN].copy_from_slice(&root);
    metadata[32..36].copy_from_slice(&(DFIM_BLOCK_SIZE as u32).to_le_bytes());
    metadata[36..40].copy_from_slice(&block_count.to_le_bytes());
    let fec_backup = encode_block(&metadata)?;

    let mut blob = Vec::new();
    blob.extend_from_slice(&MANIFEST_MAGIC);
    blob.extend_from_slice(&SIGNED_MANIFEST_VERSION.to_le_bytes());
    blob.extend_from_slice(&(V2_HEADER_LEN as u32).to_le_bytes());
    blob.extend_from_slice(&(DFIM_BLOCK_SIZE as u32).to_le_bytes());
    blob.extend_from_slice(&block_count.to_le_bytes());
    blob.extend_from_slice(&release_counter.to_le_bytes());
    blob.extend_from_slice(&key_id);
    blob.extend_from_slice(&V2_SIGNATURE_ALGORITHM.to_le_bytes());
    blob.extend_from_slice(&(V2_SIGNATURE_LEN as u32).to_le_bytes());
    blob.extend_from_slice(&root);
    blob.extend_from_slice(&(fec_backup.len() as u32).to_le_bytes());
    blob.extend_from_slice(&fec_backup);

    for index in 0..blocks.len() {
        let proof = tree.prove(index)?;
        if proof.steps.len() > MAX_PROOF_STEPS {
            return Err(DfimError::InvalidParameter);
        }
        blob.push(proof.steps.len() as u8);
        for step in proof.steps {
            blob.extend_from_slice(&step.sibling);
        }
    }

    let signing_key =
        SigningKey::from_bytes(&(*private_key).into()).map_err(|_| DfimError::InvalidParameter)?;
    let signature: Signature = signing_key.sign(&blob);
    blob.extend_from_slice(signature.to_bytes().as_slice());
    Ok(blob)
}

/// Verifies signature, key identity, release floor, and canonical v2 encoding.
pub fn parse_and_verify_boot_sidecar_v2(
    data: &[u8],
    policy: &TrustedManifestPolicy,
) -> DfimResult<VerifiedBootManifest> {
    let minimum_len = V2_HEADER_LEN
        .checked_add(V2_SIGNATURE_LEN)
        .ok_or(DfimError::ParameterOverflow)?;
    if data.len() < minimum_len {
        return Err(DfimError::BufferTooShort);
    }
    if data[..8] != MANIFEST_MAGIC {
        return Err(DfimError::IntegrityFailure);
    }
    if read_u32(&data[8..12])? != SIGNED_MANIFEST_VERSION
        || read_u32(&data[12..16])? as usize != V2_HEADER_LEN
    {
        return Err(DfimError::InvalidParameter);
    }

    let block_size = read_u32(&data[16..20])?;
    let block_count = read_u32(&data[20..24])?;
    if block_size as usize != DFIM_BLOCK_SIZE || block_count == 0 {
        return Err(DfimError::InvalidParameter);
    }
    validate_block_count(block_count)?;

    let release_counter = read_u64(&data[V2_RELEASE_OFFSET..V2_KEY_ID_OFFSET])?;
    if release_counter < policy.minimum_release || release_counter == 0 {
        return Err(DfimError::IntegrityFailure);
    }
    let mut key_id = [0u8; V2_KEY_ID_LEN];
    key_id.copy_from_slice(&data[V2_KEY_ID_OFFSET..V2_ALGORITHM_OFFSET]);
    if !constant_time_key_id_eq(&key_id, &policy.expected_key_id) {
        return Err(DfimError::IntegrityFailure);
    }
    if read_u32(&data[V2_ALGORITHM_OFFSET..V2_SIGNATURE_LEN_OFFSET])? != V2_SIGNATURE_ALGORITHM
        || read_u32(&data[V2_SIGNATURE_LEN_OFFSET..V2_MERKLE_ROOT_OFFSET])? as usize
            != V2_SIGNATURE_LEN
    {
        return Err(DfimError::InvalidParameter);
    }

    let signed_end = data
        .len()
        .checked_sub(V2_SIGNATURE_LEN)
        .ok_or(DfimError::BufferTooShort)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&policy.public_key_sec1)
        .map_err(|_| DfimError::InvalidParameter)?;
    let signature =
        Signature::from_slice(&data[signed_end..]).map_err(|_| DfimError::IntegrityFailure)?;
    verifying_key
        .verify(&data[..signed_end], &signature)
        .map_err(|_| DfimError::IntegrityFailure)?;

    let mut merkle_root = [0u8; SHA256_LEN];
    merkle_root.copy_from_slice(&data[V2_MERKLE_ROOT_OFFSET..V2_FEC_LEN_OFFSET]);
    let fec_len = read_u32(&data[V2_FEC_LEN_OFFSET..V2_HEADER_LEN])? as usize;
    let fec_end = V2_HEADER_LEN
        .checked_add(fec_len)
        .ok_or(DfimError::ParameterOverflow)?;
    if fec_end > signed_end || fec_len == 0 || !fec_len.is_multiple_of(2) {
        return Err(DfimError::BufferTooShort);
    }
    let fec_backup = data[V2_HEADER_LEN..fec_end].to_vec();

    let mut proofs = Vec::with_capacity(block_count as usize);
    let mut offset = fec_end;
    for _ in 0..block_count {
        if offset >= signed_end {
            return Err(DfimError::BufferTooShort);
        }
        let step_count = data[offset] as usize;
        offset = offset.checked_add(1).ok_or(DfimError::ParameterOverflow)?;
        if step_count > MAX_PROOF_STEPS {
            return Err(DfimError::InvalidParameter);
        }
        let mut steps = Vec::with_capacity(step_count);
        for _ in 0..step_count {
            let end = offset
                .checked_add(SHA256_LEN)
                .ok_or(DfimError::ParameterOverflow)?;
            if end > signed_end {
                return Err(DfimError::BufferTooShort);
            }
            let mut sibling = [0u8; SHA256_LEN];
            sibling.copy_from_slice(&data[offset..end]);
            steps.push(ProofStep { sibling });
            offset = end;
        }
        proofs.push(MerkleProof { steps });
    }
    if offset != signed_end {
        return Err(DfimError::IntegrityFailure);
    }

    let manifest = BootManifest {
        merkle_root,
        block_size,
        block_count,
        fec_backup,
        proofs,
    };
    let decoded = dfim_core_engine::decode_block(&manifest.fec_backup)?;
    if decoded.len() < 40 {
        return Err(DfimError::CorruptMetadata);
    }
    let mut decoded_root = [0u8; SHA256_LEN];
    decoded_root.copy_from_slice(&decoded[..SHA256_LEN]);
    if !constant_time_hash_eq(&manifest.merkle_root, &decoded_root) {
        return Err(DfimError::CorruptMetadata);
    }

    Ok(VerifiedBootManifest {
        manifest,
        release_counter,
        key_id,
    })
}

/// Enforces all production trust gates before returning executable payload bytes.
pub fn validate_signed_boot_image_v2(
    image: &[u8],
    sidecar: &[u8],
    policy: &TrustedManifestPolicy,
) -> DfimResult<ValidatedSignedBootImage> {
    let verified = parse_and_verify_boot_sidecar_v2(sidecar, policy)?;
    let boot = validate_boot_image(image, &verified.manifest)?;
    Ok(ValidatedSignedBootImage {
        boot,
        release_counter: verified.release_counter,
        key_id: verified.key_id,
    })
}

fn constant_time_key_id_eq(left: &[u8; V2_KEY_ID_LEN], right: &[u8; V2_KEY_ID_LEN]) -> bool {
    let mut difference = 0u8;
    for index in 0..V2_KEY_ID_LEN {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

fn read_u32(bytes: &[u8]) -> DfimResult<u32> {
    if bytes.len() < 4 {
        return Err(DfimError::BufferTooShort);
    }
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(bytes: &[u8]) -> DfimResult<u64> {
    if bytes.len() < 8 {
        return Err(DfimError::BufferTooShort);
    }
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DFIM_BLOCK_SIZE;
    use dfim_core_engine::DfimError;

    const PRIVATE_KEY: [u8; 32] = [0x11; 32];
    const KEY_ID: [u8; 16] = *b"DFIM-TEST-KEY-01";

    fn fixture() -> alloc::vec::Vec<u8> {
        alloc::vec![0x4D; DFIM_BLOCK_SIZE * 2]
    }

    fn policy(minimum_release: u64) -> TrustedManifestPolicy {
        TrustedManifestPolicy {
            public_key_sec1: public_key_sec1_from_private(&PRIVATE_KEY).expect("public key"),
            expected_key_id: KEY_ID,
            minimum_release,
        }
    }

    #[test]
    fn signed_v2_round_trip_is_verified() {
        let blob =
            build_signed_boot_sidecar_v2(&fixture(), &PRIVATE_KEY, KEY_ID, 7).expect("signed");
        let verified = parse_and_verify_boot_sidecar_v2(&blob, &policy(7)).expect("verified");
        assert_eq!(verified.release_counter, 7);
        assert_eq!(verified.key_id, KEY_ID);
        assert_eq!(verified.manifest.block_count, 2);
    }

    #[test]
    fn trusted_pipeline_validates_signed_image() {
        let image = fixture();
        let blob = build_signed_boot_sidecar_v2(&image, &PRIVATE_KEY, KEY_ID, 7).expect("signed");
        let validated =
            validate_signed_boot_image_v2(&image, &blob, &policy(7)).expect("validated");
        assert_eq!(validated.release_counter, 7);
        assert_eq!(validated.boot.blocks_verified, 2);
    }

    #[test]
    fn trusted_pipeline_rejects_image_tamper() {
        let image = fixture();
        let blob = build_signed_boot_sidecar_v2(&image, &PRIVATE_KEY, KEY_ID, 7).expect("signed");
        let mut tampered = image;
        tampered[3] ^= 1;
        assert_eq!(
            validate_signed_boot_image_v2(&tampered, &blob, &policy(7)).err(),
            Some(DfimError::IntegrityFailure)
        );
    }

    #[test]
    fn signed_v2_rejects_payload_tamper() {
        let mut blob =
            build_signed_boot_sidecar_v2(&fixture(), &PRIVATE_KEY, KEY_ID, 7).expect("signed");
        blob[V2_MERKLE_ROOT_OFFSET] ^= 1;
        assert_eq!(
            parse_and_verify_boot_sidecar_v2(&blob, &policy(7)).err(),
            Some(DfimError::IntegrityFailure)
        );
    }

    #[test]
    fn signed_v2_rejects_signature_tamper() {
        let mut blob =
            build_signed_boot_sidecar_v2(&fixture(), &PRIVATE_KEY, KEY_ID, 7).expect("signed");
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert_eq!(
            parse_and_verify_boot_sidecar_v2(&blob, &policy(7)).err(),
            Some(DfimError::IntegrityFailure)
        );
    }

    #[test]
    fn signed_v2_rejects_rollback() {
        let blob =
            build_signed_boot_sidecar_v2(&fixture(), &PRIVATE_KEY, KEY_ID, 6).expect("signed");
        assert_eq!(
            parse_and_verify_boot_sidecar_v2(&blob, &policy(7)).err(),
            Some(DfimError::IntegrityFailure)
        );
    }

    #[test]
    fn signed_v2_rejects_wrong_key_id() {
        let blob =
            build_signed_boot_sidecar_v2(&fixture(), &PRIVATE_KEY, [0xAA; 16], 7).expect("signed");
        assert_eq!(
            parse_and_verify_boot_sidecar_v2(&blob, &policy(7)).err(),
            Some(DfimError::IntegrityFailure)
        );
    }

    #[test]
    fn trusted_parser_rejects_legacy_v1() {
        let legacy = crate::build_boot_sidecar(&fixture()).expect("legacy");
        assert_eq!(
            parse_and_verify_boot_sidecar_v2(&legacy, &policy(1)).err(),
            Some(DfimError::InvalidParameter)
        );
    }
}
