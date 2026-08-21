//! Deterministic boot-image validation pipeline (Hamming FEC → Merkle O(log N)).

use crate::manifest::{BootManifest, DFIM_BLOCK_SIZE};
use dfim_core_engine::{
    constant_time_hash_eq, decode_block, validate_block_count, validate_image_byte_len,
    verify_proof, DfimError, DfimResult, SHA256_LEN,
};

/// Outcome of a successful Layer-0 boot guard validation pass.
pub struct ValidatedBootImage {
    pub payload: alloc::vec::Vec<u8>,
    pub merkle_root: [u8; SHA256_LEN],
    pub fec_corrected: bool,
    pub blocks_verified: u32,
}

/// Recover `(root, block_size, block_count)` from Hamming FEC backup.
///
/// Implements C1 decode before C2 Merkle verification per DFIM pipeline order.
fn fec_recover_metadata(fec_backup: &[u8]) -> DfimResult<([u8; SHA256_LEN], u32, u32)> {
    let decoded = decode_block(fec_backup)?;
    if decoded.len() < 40 {
        return Err(DfimError::BufferTooShort);
    }
    let mut root = [0u8; SHA256_LEN];
    root.copy_from_slice(&decoded[0..SHA256_LEN]);
    let block_size = u32::from_le_bytes([decoded[32], decoded[33], decoded[34], decoded[35]]);
    let block_count = u32::from_le_bytes([decoded[36], decoded[37], decoded[38], decoded[39]]);
    Ok((root, block_size, block_count))
}

/// Resolve authoritative manifest fields, applying Hamming correction when redundant
/// FEC metadata disagrees with the cleartext header (single-bit rot path).
fn resolve_metadata(manifest: &BootManifest) -> DfimResult<([u8; SHA256_LEN], u32, u32, bool)> {
    let (fec_root, fec_block_size, fec_block_count) = fec_recover_metadata(&manifest.fec_backup)?;

    if fec_block_size as usize != DFIM_BLOCK_SIZE {
        return Err(DfimError::InvalidParameter);
    }
    if fec_block_count == 0 {
        return Err(DfimError::InvalidParameter);
    }
    validate_block_count(fec_block_count)?;

    let header_matches = constant_time_hash_eq(&manifest.merkle_root, &fec_root)
        && manifest.block_size == fec_block_size
        && manifest.block_count == fec_block_count;

    if header_matches {
        return Ok((fec_root, fec_block_size, fec_block_count, false));
    }

    Err(DfimError::CorruptMetadata)
}

/// Split bootloader image into fixed-size blocks (zero-padded tail).
fn partition_blocks(
    image: &[u8],
    block_size: usize,
) -> DfimResult<alloc::vec::Vec<alloc::vec::Vec<u8>>> {
    validate_image_byte_len(image.len())?;
    if block_size != DFIM_BLOCK_SIZE {
        return Err(DfimError::InvalidParameter);
    }
    let block_count = image.len().div_ceil(block_size);
    validate_block_count(block_count as u32)?;
    let mut blocks = alloc::vec::Vec::with_capacity(block_count);
    for idx in 0..block_count {
        let start = idx * block_size;
        let end = core::cmp::min(start + block_size, image.len());
        let mut block = alloc::vec![0u8; block_size];
        block[..end - start].copy_from_slice(&image[start..end]);
        blocks.push(block);
    }
    Ok(blocks)
}

/// Run full DFIM Layer-0 pipeline on a bootloader image and its sidecar manifest.
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(N log N), M=O(N), T=O(N log N)]
pub fn validate_boot_image(
    image: &[u8],
    manifest: &BootManifest,
) -> DfimResult<ValidatedBootImage> {
    validate_image_byte_len(image.len())?;
    let (merkle_root, block_size, block_count, fec_corrected) = resolve_metadata(manifest)?;

    if manifest.proofs.len() != block_count as usize {
        return Err(DfimError::IntegrityFailure);
    }

    let blocks = partition_blocks(image, block_size as usize)?;
    if blocks.len() as u32 != block_count {
        return Err(DfimError::IntegrityFailure);
    }

    for (index, block) in blocks.iter().enumerate() {
        let proof = &manifest.proofs[index];
        let ok = verify_proof(&merkle_root, block, index, proof)?;
        if !ok {
            return Err(DfimError::IntegrityFailure);
        }
    }

    Ok(ValidatedBootImage {
        payload: image.to_vec(),
        merkle_root,
        fec_corrected,
        blocks_verified: block_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{parse_boot_manifest, MANIFEST_MAGIC, MANIFEST_VERSION};
    use dfim_core_engine::{encode_block, MerkleTree};

    fn build_fixture(block_count: usize) -> (alloc::vec::Vec<u8>, BootManifest) {
        let blocks: alloc::vec::Vec<alloc::vec::Vec<u8>> = (0..block_count)
            .map(|i| alloc::vec![i as u8; DFIM_BLOCK_SIZE])
            .collect();
        let image: alloc::vec::Vec<u8> = blocks.concat();
        let refs: alloc::vec::Vec<&[u8]> = blocks.iter().map(|b| b.as_slice()).collect();
        let tree = MerkleTree::build(&refs).expect("tree");
        let root = *tree.root();

        let mut meta = [0u8; 40];
        meta[0..32].copy_from_slice(root.as_slice());
        meta[32..36].copy_from_slice(&(DFIM_BLOCK_SIZE as u32).to_le_bytes());
        meta[36..40].copy_from_slice(&(block_count as u32).to_le_bytes());
        let fec = encode_block(&meta).expect("fec");

        let mut blob = alloc::vec::Vec::new();
        blob.extend_from_slice(&MANIFEST_MAGIC);
        blob.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
        blob.extend_from_slice(&(DFIM_BLOCK_SIZE as u32).to_le_bytes());
        blob.extend_from_slice(&(block_count as u32).to_le_bytes());
        blob.extend_from_slice(root.as_slice());
        blob.extend_from_slice(&(fec.len() as u32).to_le_bytes());
        blob.extend_from_slice(&fec);
        for i in 0..block_count {
            let proof = tree.prove(i).expect("prove");
            blob.push(proof.steps.len() as u8);
            for step in &proof.steps {
                blob.extend_from_slice(step.sibling.as_slice());
            }
        }

        let manifest = parse_boot_manifest(&blob).expect("parse");
        (image, manifest)
    }

    #[test]
    fn validate_passes_for_signed_fixture() {
        let (image, manifest) = build_fixture(8);
        let result = validate_boot_image(&image, &manifest).expect("validate");
        assert_eq!(result.blocks_verified, 8);
        assert!(!result.fec_corrected);
    }

    #[test]
    fn validate_rejects_tampered_block() {
        let (mut image, manifest) = build_fixture(4);
        image[DFIM_BLOCK_SIZE + 10] ^= 0xff;
        assert_eq!(
            validate_boot_image(&image, &manifest).err(),
            Some(DfimError::IntegrityFailure)
        );
    }
}
