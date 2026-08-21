//! Fixed-buffer boot validation for eBPF / no-alloc environments.
//!
//! Mirrors the Windows UEFI pipeline: Hamming FEC metadata → Merkle O(log N) proofs.

#[cfg(feature = "bpf")]
use crate::bpf_sha256::{
    parent_hash as parent_hash_bpf, sha256_digest as sha256_digest_bpf, Sha256Workspace,
};
use crate::constants::SHA256_LEN;
#[cfg(not(feature = "bpf"))]
use crate::digest::sha256_digest;
use crate::error::{DfimError, DfimResult};
use crate::hamming::decode_block_into_strict;
#[cfg(not(feature = "bpf"))]
use crate::merkle::parent_hash;

/// Layer-0 block size (matches UEFI / CLI provisioner).
pub const DFIM_BLOCK_SIZE: usize = 4096;

/// Maximum blocks verifiable in a single boot / eBPF invocation (64 × 4 KiB = 262 KiB).
pub const MAX_BOOT_BLOCKS: usize = 64;

/// Maximum guarded image bytes (`MAX_BOOT_BLOCKS * DFIM_BLOCK_SIZE`).
pub const MAX_IMAGE_BYTES: usize = MAX_BOOT_BLOCKS * DFIM_BLOCK_SIZE;

const _: () = assert!(MAX_IMAGE_BYTES == 262_144);
const _: () = assert!(MAX_IMAGE_BYTES == MAX_BOOT_BLOCKS * DFIM_BLOCK_SIZE);

/// Maximum Merkle proof depth supported in kernel probes.
pub const MAX_PROOF_STEPS: usize = 16;

/// Maximum Hamming FEC backup bytes in compact manifests.
pub const MAX_FEC_BACKUP: usize = 128;

/// Reject manifests whose block count exceeds the Layer-0 cap.
pub fn validate_block_count(block_count: u32) -> DfimResult<()> {
    if block_count == 0 {
        return Err(DfimError::InvalidParameter);
    }
    if block_count as usize > MAX_BOOT_BLOCKS {
        return Err(DfimError::ParameterOverflow);
    }
    Ok(())
}

/// Reject images whose byte length exceeds the Layer-0 cap.
pub fn validate_image_byte_len(image_len: usize) -> DfimResult<()> {
    if image_len == 0 {
        return Err(DfimError::EmptyInput);
    }
    if image_len > MAX_IMAGE_BYTES {
        return Err(DfimError::BufferTooLong);
    }
    let blocks = image_len.div_ceil(DFIM_BLOCK_SIZE);
    if blocks > MAX_BOOT_BLOCKS {
        return Err(DfimError::ParameterOverflow);
    }
    Ok(())
}

/// Compact Merkle proof for eBPF maps (fixed layout).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CompactProof {
    pub step_count: u8,
    pub siblings: [[u8; SHA256_LEN]; MAX_PROOF_STEPS],
}

impl CompactProof {
    /// Verify one block against root using O(log N) sibling steps (no heap).
    #[cfg(not(feature = "bpf"))]
    pub fn verify_block(
        &self,
        root: &[u8; SHA256_LEN],
        block: &[u8],
        index: usize,
    ) -> DfimResult<bool> {
        let steps = self.step_count as usize;
        if steps > MAX_PROOF_STEPS {
            return Err(DfimError::InvalidParameter);
        }
        let mut hash = sha256_digest(block);
        let mut idx = index;
        for sibling in &self.siblings[..steps] {
            hash = if idx.is_multiple_of(2) {
                parent_hash(&hash, sibling)
            } else {
                parent_hash(sibling, &hash)
            };
            idx /= 2;
        }
        Ok(crate::crypto::constant_time_hash_eq(&hash, root))
    }
}

/// Per-CPU validation scratch — single pointer arg for BPF calling convention.
#[cfg(feature = "bpf")]
#[repr(C)]
pub struct BpfValidateScratch {
    pub block: [u8; DFIM_BLOCK_SIZE],
    pub sha256: Sha256Workspace,
    pub fec_decoded: [u8; 64],
    pub fec_len: usize,
    pub root: [u8; SHA256_LEN],
    pub index: usize,
    pub block_count: u32,
    pub proof: CompactProof,
}

/// Recover metadata into scratch (two-arg BPF-safe entry).
#[cfg(feature = "bpf")]
#[inline(never)]
pub fn resolve_metadata_from_scratch(
    scratch: &mut BpfValidateScratch,
    manifest: &CompactManifest,
) -> DfimResult<()> {
    let fec = manifest.fec_slice();
    if fec.is_empty() || !fec.len().is_multiple_of(2) {
        return Err(DfimError::InvalidParameter);
    }

    scratch.fec_len = 0;
    decode_block_into_strict(fec, &mut scratch.fec_decoded, &mut scratch.fec_len)?;
    if scratch.fec_len < 40 {
        return Err(DfimError::BufferTooShort);
    }

    scratch
        .root
        .copy_from_slice(&scratch.fec_decoded[..SHA256_LEN]);
    let block_size = u32::from_le_bytes([
        scratch.fec_decoded[32],
        scratch.fec_decoded[33],
        scratch.fec_decoded[34],
        scratch.fec_decoded[35],
    ]);
    scratch.block_count = u32::from_le_bytes([
        scratch.fec_decoded[36],
        scratch.fec_decoded[37],
        scratch.fec_decoded[38],
        scratch.fec_decoded[39],
    ]);

    if block_size as usize != DFIM_BLOCK_SIZE || scratch.block_count == 0 {
        return Err(DfimError::InvalidParameter);
    }
    validate_block_count(scratch.block_count)?;

    if crate::crypto::constant_time_hash_eq(&manifest.merkle_root, &scratch.root)
        && manifest.block_size == block_size
        && manifest.block_count == scratch.block_count
    {
        return Ok(());
    }

    Err(DfimError::CorruptMetadata)
}

/// Validate one block from map-backed scratch (BPF ABI: one pointer parameter).
#[cfg(feature = "bpf")]
#[inline(never)]
pub fn validate_block_from_scratch(scratch: &mut BpfValidateScratch) -> DfimResult<()> {
    let proof = &scratch.proof;
    let steps = proof.step_count as usize;
    if steps > MAX_PROOF_STEPS {
        return Err(DfimError::InvalidParameter);
    }
    let mut hash = sha256_digest_bpf(&scratch.block, &mut scratch.sha256);
    let mut idx = scratch.index;
    for sibling in &proof.siblings[..steps] {
        hash = if idx.is_multiple_of(2) {
            parent_hash_bpf(&hash, sibling, &mut scratch.sha256)
        } else {
            parent_hash_bpf(sibling, &hash, &mut scratch.sha256)
        };
        idx /= 2;
    }
    if crate::crypto::constant_time_hash_eq(&hash, &scratch.root) {
        Ok(())
    } else {
        Err(DfimError::IntegrityFailure)
    }
}

/// Compact manifest stored in eBPF maps (matches `.dfim` semantics).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CompactManifest {
    pub merkle_root: [u8; SHA256_LEN],
    pub block_size: u32,
    pub block_count: u32,
    pub fec_len: u16,
    pub fec_backup: [u8; MAX_FEC_BACKUP],
}

impl CompactManifest {
    pub fn fec_slice(&self) -> &[u8] {
        let len = self.fec_len as usize;
        if len > MAX_FEC_BACKUP {
            return &[];
        }
        &self.fec_backup[..len]
    }
}

/// Recover metadata via Hamming FEC (C1) before Merkle checks (C2).
pub fn resolve_metadata_compact(
    manifest: &CompactManifest,
) -> DfimResult<([u8; SHA256_LEN], u32, u32)> {
    let mut decoded = [0u8; 64];
    let mut decoded_len = 0usize;
    resolve_metadata_into(manifest, &mut decoded, &mut decoded_len)
}

/// Metadata resolve with caller-provided decode buffer (BPF map-backed scratch).
#[inline(never)]
pub fn resolve_metadata_into(
    manifest: &CompactManifest,
    decoded: &mut [u8; 64],
    decoded_len: &mut usize,
) -> DfimResult<([u8; SHA256_LEN], u32, u32)> {
    let fec = manifest.fec_slice();
    if fec.is_empty() || !fec.len().is_multiple_of(2) {
        return Err(DfimError::InvalidParameter);
    }

    *decoded_len = 0;
    decode_block_into_strict(fec, decoded, decoded_len)?;
    if *decoded_len < 40 {
        return Err(DfimError::BufferTooShort);
    }

    let mut fec_root = [0u8; SHA256_LEN];
    fec_root.copy_from_slice(&decoded[..SHA256_LEN]);
    let block_size = u32::from_le_bytes([decoded[32], decoded[33], decoded[34], decoded[35]]);
    let block_count = u32::from_le_bytes([decoded[36], decoded[37], decoded[38], decoded[39]]);

    if block_size as usize != DFIM_BLOCK_SIZE || block_count == 0 {
        return Err(DfimError::InvalidParameter);
    }
    validate_block_count(block_count)?;

    if crate::crypto::constant_time_hash_eq(&manifest.merkle_root, &fec_root)
        && manifest.block_size == block_size
        && manifest.block_count == block_count
    {
        return Ok((fec_root, block_size, block_count));
    }

    Err(DfimError::CorruptMetadata)
}

/// Validate one 4096-byte block against compact proof (no heap).
#[cfg(not(feature = "bpf"))]
pub fn validate_block_compact(
    root: &[u8; SHA256_LEN],
    block: &[u8],
    index: usize,
    proof: &CompactProof,
) -> DfimResult<()> {
    if block.len() != DFIM_BLOCK_SIZE {
        return Err(DfimError::InvalidParameter);
    }
    if proof.verify_block(root, block, index)? {
        Ok(())
    } else {
        Err(DfimError::IntegrityFailure)
    }
}

/// Validate full image from block slices (no heap beyond caller buffers).
#[cfg(not(feature = "bpf"))]
pub fn validate_boot_image_compact(
    image: &[u8],
    manifest: &CompactManifest,
    proofs: &[CompactProof],
) -> DfimResult<()> {
    validate_image_byte_len(image.len())?;

    let (root, block_size, block_count) = resolve_metadata_compact(manifest)?;
    if block_size as usize != DFIM_BLOCK_SIZE {
        return Err(DfimError::InvalidParameter);
    }
    if proofs.len() != block_count as usize {
        return Err(DfimError::IntegrityFailure);
    }
    validate_block_count(block_count)?;

    let expected_blocks = image.len().div_ceil(DFIM_BLOCK_SIZE);
    if expected_blocks as u32 != block_count {
        return Err(DfimError::IntegrityFailure);
    }

    for (index, proof) in proofs.iter().enumerate().take(block_count as usize) {
        crate::integrity_gate::assert_block_index(index, block_count)?;

        let start = index * DFIM_BLOCK_SIZE;
        let end = core::cmp::min(start + DFIM_BLOCK_SIZE, image.len());
        let mut block = [0u8; DFIM_BLOCK_SIZE];
        block[..end - start].copy_from_slice(&image[start..end]);
        validate_block_compact(&root, &block, index, proof)?;
    }

    Ok(())
}

#[cfg(all(test, feature = "alloc", not(feature = "bpf")))]
mod tests {
    use super::*;
    use crate::{encode_block, MerkleTree};

    #[test]
    fn compact_validation_matches_tree() {
        let blocks: alloc::vec::Vec<alloc::vec::Vec<u8>> =
            (0..4u8).map(|i| alloc::vec![i; DFIM_BLOCK_SIZE]).collect();
        let image: alloc::vec::Vec<u8> = blocks.concat();
        let refs: alloc::vec::Vec<&[u8]> = blocks.iter().map(|b| b.as_slice()).collect();
        let tree = MerkleTree::build(&refs).expect("tree");
        let root = *tree.root();

        let mut meta = [0u8; 40];
        meta[0..32].copy_from_slice(root.as_slice());
        meta[32..36].copy_from_slice(&(DFIM_BLOCK_SIZE as u32).to_le_bytes());
        meta[36..40].copy_from_slice(&(blocks.len() as u32).to_le_bytes());
        let fec = encode_block(&meta).expect("fec");

        let mut manifest = CompactManifest {
            merkle_root: root,
            block_size: DFIM_BLOCK_SIZE as u32,
            block_count: blocks.len() as u32,
            fec_len: fec.len() as u16,
            fec_backup: [0u8; MAX_FEC_BACKUP],
        };
        manifest.fec_backup[..fec.len()].copy_from_slice(&fec);

        let mut proofs = alloc::vec::Vec::new();
        for i in 0..blocks.len() {
            let p = tree.prove(i).expect("prove");
            let mut cp = CompactProof {
                step_count: p.steps.len() as u8,
                siblings: [[0u8; SHA256_LEN]; MAX_PROOF_STEPS],
            };
            for (j, step) in p.steps.iter().enumerate() {
                cp.siblings[j] = step.sibling;
            }
            proofs.push(cp);
        }

        validate_boot_image_compact(&image, &manifest, &proofs).expect("valid");
    }

    #[test]
    fn resolve_metadata_rejects_merkle_fec_mismatch() {
        let blocks: alloc::vec::Vec<alloc::vec::Vec<u8>> =
            (0..2u8).map(|i| alloc::vec![i; DFIM_BLOCK_SIZE]).collect();
        let refs: alloc::vec::Vec<&[u8]> = blocks.iter().map(|b| b.as_slice()).collect();
        let tree = MerkleTree::build(&refs).expect("tree");
        let root = *tree.root();

        let mut meta = [0u8; 40];
        meta[0..32].copy_from_slice(root.as_slice());
        meta[32..36].copy_from_slice(&(DFIM_BLOCK_SIZE as u32).to_le_bytes());
        meta[36..40].copy_from_slice(&(blocks.len() as u32).to_le_bytes());
        let fec = encode_block(&meta).expect("fec");

        let mut manifest = CompactManifest {
            merkle_root: root,
            block_size: DFIM_BLOCK_SIZE as u32,
            block_count: blocks.len() as u32,
            fec_len: fec.len() as u16,
            fec_backup: [0u8; MAX_FEC_BACKUP],
        };
        manifest.fec_backup[..fec.len()].copy_from_slice(&fec);
        manifest.merkle_root[0] ^= 0xff;

        assert_eq!(
            resolve_metadata_compact(&manifest).err(),
            Some(DfimError::CorruptMetadata)
        );
    }

    #[test]
    fn resolve_metadata_rejects_double_bit_fec_rot() {
        let blocks: alloc::vec::Vec<alloc::vec::Vec<u8>> =
            (0..2u8).map(|i| alloc::vec![i; DFIM_BLOCK_SIZE]).collect();
        let refs: alloc::vec::Vec<&[u8]> = blocks.iter().map(|b| b.as_slice()).collect();
        let tree = MerkleTree::build(&refs).expect("tree");
        let root = *tree.root();

        let mut meta = [0u8; 40];
        meta[0..32].copy_from_slice(root.as_slice());
        meta[32..36].copy_from_slice(&(DFIM_BLOCK_SIZE as u32).to_le_bytes());
        meta[36..40].copy_from_slice(&(blocks.len() as u32).to_le_bytes());
        let mut fec = encode_block(&meta).expect("fec");
        fec[0] ^= 0x03;
        fec[1] ^= 0x05;

        let mut manifest = CompactManifest {
            merkle_root: root,
            block_size: DFIM_BLOCK_SIZE as u32,
            block_count: blocks.len() as u32,
            fec_len: fec.len() as u16,
            fec_backup: [0u8; MAX_FEC_BACKUP],
        };
        manifest.fec_backup[..fec.len()].copy_from_slice(&fec);

        assert_eq!(
            resolve_metadata_compact(&manifest).err(),
            Some(DfimError::CorruptMetadata)
        );
    }
}

#[cfg(feature = "linux-loader")]
mod aya_pod {
    #![allow(unsafe_code)]

    use super::{CompactManifest, CompactProof};
    use aya::Pod;

    unsafe impl Pod for CompactProof {}
    unsafe impl Pod for CompactManifest {}
}
