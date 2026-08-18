//! DFIM boot sidecar binary layout consumed by the Windows UEFI boot guard.
//!
//! Sidecar path: `<bootloader_path>.dfim` (e.g. `\EFI\Microsoft\Boot\bootmgfw.efi.dfim`).

use dfim_core_engine::{
    parse_block_stream, validate_block_count, validate_image_byte_len, DfimError, DfimResult,
    MerkleProof, SHA256_LEN,
};
pub use dfim_core_engine::{DFIM_BLOCK_SIZE, MAX_BOOT_BLOCKS, MAX_IMAGE_BYTES, MAX_PROOF_STEPS};
pub const MANIFEST_MAGIC: [u8; 8] = *b"DFIMBOOT";
pub const MANIFEST_VERSION: u32 = 1;

/// Parsed DFIM boot integrity sidecar.
pub struct BootManifest {
    pub merkle_root: [u8; SHA256_LEN],
    pub block_size: u32,
    pub block_count: u32,
    pub fec_backup: alloc::vec::Vec<u8>,
    pub proofs: alloc::vec::Vec<MerkleProof>,
}

/// Parse a `.dfim` sidecar blob into structured manifest data.
pub fn parse_boot_manifest(data: &[u8]) -> DfimResult<BootManifest> {
    let parsed = parse_block_stream(data)?;
    Ok(BootManifest {
        merkle_root: parsed.merkle_root,
        block_size: parsed.block_size,
        block_count: parsed.block_count,
        fec_backup: parsed.fec_backup,
        proofs: parsed.proofs,
    })
}

/// Partition an image into fixed-size blocks with zero-padded tail (matches UEFI validator).
pub fn partition_image_blocks(
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

/// Serialize a boot sidecar blob matching the DFIMBOOT v1 layout.
pub fn serialize_boot_sidecar(
    merkle_root: &[u8; SHA256_LEN],
    block_size: u32,
    block_count: u32,
    fec_backup: &[u8],
    proofs: &[MerkleProof],
) -> DfimResult<alloc::vec::Vec<u8>> {
    if block_size as usize != DFIM_BLOCK_SIZE || block_count == 0 {
        return Err(DfimError::InvalidParameter);
    }
    validate_block_count(block_count)?;
    if proofs.len() != block_count as usize {
        return Err(DfimError::InvalidParameter);
    }
    if fec_backup.is_empty() || !fec_backup.len().is_multiple_of(2) {
        return Err(DfimError::InvalidParameter);
    }

    let mut blob = alloc::vec::Vec::new();
    blob.extend_from_slice(&MANIFEST_MAGIC);
    blob.extend_from_slice(&MANIFEST_VERSION.to_le_bytes());
    blob.extend_from_slice(&block_size.to_le_bytes());
    blob.extend_from_slice(&block_count.to_le_bytes());
    blob.extend_from_slice(merkle_root.as_slice());
    blob.extend_from_slice(&(fec_backup.len() as u32).to_le_bytes());
    blob.extend_from_slice(fec_backup);

    for proof in proofs {
        if proof.steps.len() > MAX_PROOF_STEPS {
            return Err(DfimError::InvalidParameter);
        }
        blob.push(proof.steps.len() as u8);
        for step in &proof.steps {
            blob.extend_from_slice(step.sibling.as_slice());
        }
    }

    Ok(blob)
}

/// Build a complete `.dfim` sidecar from a raw bootloader image.
///
/// Pipeline: 4096-byte segmentation → Merkle tree → C1 Hamming FEC metadata backup.
pub fn build_boot_sidecar(image: &[u8]) -> DfimResult<alloc::vec::Vec<u8>> {
    use dfim_core_engine::{encode_block, MerkleTree};

    validate_image_byte_len(image.len())?;
    let blocks = partition_image_blocks(image, DFIM_BLOCK_SIZE)?;
    let block_count = blocks.len() as u32;
    let refs: alloc::vec::Vec<&[u8]> = blocks.iter().map(|b| b.as_slice()).collect();
    let tree = MerkleTree::build(&refs)?;
    let root = *tree.root();

    let mut meta = [0u8; 40];
    meta[0..SHA256_LEN].copy_from_slice(root.as_slice());
    meta[32..36].copy_from_slice(&(DFIM_BLOCK_SIZE as u32).to_le_bytes());
    meta[36..40].copy_from_slice(&block_count.to_le_bytes());

    let fec_backup = encode_block(&meta)?;

    let mut proofs = alloc::vec::Vec::with_capacity(blocks.len());
    for i in 0..blocks.len() {
        proofs.push(tree.prove(i)?);
    }

    serialize_boot_sidecar(
        &root,
        DFIM_BLOCK_SIZE as u32,
        block_count,
        &fec_backup,
        &proofs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_parse_generated_manifest() {
        let blocks: alloc::vec::Vec<alloc::vec::Vec<u8>> =
            (0..4u8).map(|i| alloc::vec![i; DFIM_BLOCK_SIZE]).collect();
        let image: alloc::vec::Vec<u8> = blocks.concat();
        let blob = build_boot_sidecar(&image).expect("build");
        let parsed = parse_boot_manifest(&blob).expect("parse");
        assert_eq!(parsed.block_count as usize, blocks.len());
    }

    #[test]
    fn parse_rejects_proof_depth_above_ebpf_cap() {
        let blocks: alloc::vec::Vec<alloc::vec::Vec<u8>> =
            (0..4u8).map(|i| alloc::vec![i; DFIM_BLOCK_SIZE]).collect();
        let image: alloc::vec::Vec<u8> = blocks.concat();
        let mut blob = build_boot_sidecar(&image).expect("build");
        let fec_len = u32::from_le_bytes(blob[52..56].try_into().unwrap()) as usize;
        let proof_step_offset = 56 + fec_len;
        blob[proof_step_offset] = (MAX_PROOF_STEPS + 1) as u8;
        assert_eq!(
            parse_boot_manifest(&blob).err(),
            Some(DfimError::InvalidParameter)
        );
    }
}
