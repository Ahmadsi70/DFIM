//! Layer-0 binary parsers for boot block streams and UEFI variable envelopes.
//!
//! All bounds checks use checked arithmetic so corrupted inputs return `Err` instead of panicking.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::{DfimError, DfimResult};
use crate::merkle::{MerkleProof, ProofStep};
use crate::{validate_block_count, DFIM_BLOCK_SIZE, MAX_PROOF_STEPS, SHA256_LEN};

pub use crate::state_db::parse_authenticated_state_db;

/// Magic prefix for DFIM boot block stream sidecars.
pub const BLOCK_STREAM_MAGIC: [u8; 8] = *b"DFIMBOOT";

/// Supported block stream format version.
pub const BLOCK_STREAM_VERSION: u32 = 1;

const HEADER_PREFIX_LEN: usize = 56;

/// Parsed DFIM boot block stream (`.dfim` sidecar layout).
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockStreamManifest {
    pub merkle_root: [u8; SHA256_LEN],
    pub block_size: u32,
    pub block_count: u32,
    pub fec_backup: Vec<u8>,
    pub proofs: Vec<MerkleProof>,
}

/// Parse an arbitrary boot block stream up to 64 KiB without panicking on corruption.
#[cfg(feature = "alloc")]
pub fn parse_block_stream(data: &[u8]) -> DfimResult<BlockStreamManifest> {
    if data.len() < HEADER_PREFIX_LEN {
        return Err(DfimError::BufferTooShort);
    }

    if data[0..8] != BLOCK_STREAM_MAGIC {
        return Err(DfimError::IntegrityFailure);
    }

    let version = read_u32(&data[8..12])?;
    if version != BLOCK_STREAM_VERSION {
        return Err(DfimError::InvalidParameter);
    }

    let block_size = read_u32(&data[12..16])?;
    let block_count = read_u32(&data[16..20])?;
    if block_size as usize != DFIM_BLOCK_SIZE || block_count == 0 {
        return Err(DfimError::InvalidParameter);
    }
    validate_block_count(block_count)?;

    let mut merkle_root = [0u8; SHA256_LEN];
    merkle_root.copy_from_slice(&data[20..52]);

    let fec_len = read_u32(&data[52..56])? as usize;
    let fec_end = HEADER_PREFIX_LEN
        .checked_add(fec_len)
        .ok_or(DfimError::ParameterOverflow)?;
    if data.len() < fec_end {
        return Err(DfimError::BufferTooShort);
    }

    let fec_backup = data[HEADER_PREFIX_LEN..fec_end].to_vec();
    if fec_backup.is_empty() || !fec_backup.len().is_multiple_of(2) {
        return Err(DfimError::InvalidParameter);
    }

    let mut offset = fec_end;
    let mut proofs = Vec::with_capacity(block_count as usize);
    for _ in 0..block_count {
        if offset >= data.len() {
            return Err(DfimError::BufferTooShort);
        }
        let step_count = data[offset] as usize;
        offset = offset.checked_add(1).ok_or(DfimError::ParameterOverflow)?;
        if step_count > MAX_PROOF_STEPS {
            return Err(DfimError::InvalidParameter);
        }
        let proof_bytes = step_count
            .checked_mul(SHA256_LEN)
            .ok_or(DfimError::ParameterOverflow)?;
        let proof_end = offset
            .checked_add(proof_bytes)
            .ok_or(DfimError::ParameterOverflow)?;
        if data.len() < proof_end {
            return Err(DfimError::BufferTooShort);
        }

        let mut steps = Vec::with_capacity(step_count);
        for step_idx in 0..step_count {
            let start = offset
                .checked_add(
                    step_idx
                        .checked_mul(SHA256_LEN)
                        .ok_or(DfimError::ParameterOverflow)?,
                )
                .ok_or(DfimError::ParameterOverflow)?;
            let end = start
                .checked_add(SHA256_LEN)
                .ok_or(DfimError::ParameterOverflow)?;
            let mut sibling = [0u8; SHA256_LEN];
            sibling.copy_from_slice(&data[start..end]);
            steps.push(ProofStep { sibling });
        }
        offset = proof_end;
        proofs.push(MerkleProof { steps });
    }

    if offset != data.len() {
        return Err(DfimError::IntegrityFailure);
    }

    Ok(BlockStreamManifest {
        merkle_root,
        block_size,
        block_count,
        fec_backup,
        proofs,
    })
}

/// Parse a UEFI NVRAM / `--state` variable envelope into authenticated sidecar bytes.
#[cfg(feature = "alloc")]
pub fn parse_uefi_variable(raw: &[u8]) -> DfimResult<Vec<u8>> {
    parse_authenticated_state_db(raw)
}

fn read_u32(bytes: &[u8]) -> DfimResult<u32> {
    if bytes.len() < 4 {
        return Err(DfimError::BufferTooShort);
    }
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::{encode_block, MerkleTree, DFIM_BLOCK_SIZE};
    use alloc::vec::Vec;

    #[test]
    fn parse_block_stream_round_trip() {
        let blocks: Vec<Vec<u8>> = (0..4u8).map(|i| alloc::vec![i; DFIM_BLOCK_SIZE]).collect();
        let refs: Vec<&[u8]> = blocks.iter().map(|b| b.as_slice()).collect();
        let tree = MerkleTree::build(&refs).expect("tree");
        let root = *tree.root();

        let mut meta = [0u8; 40];
        meta[0..32].copy_from_slice(root.as_slice());
        meta[32..36].copy_from_slice(&(DFIM_BLOCK_SIZE as u32).to_le_bytes());
        meta[36..40].copy_from_slice(&(blocks.len() as u32).to_le_bytes());
        let fec = encode_block(&meta).expect("fec");

        let mut blob = alloc::vec::Vec::new();
        blob.extend_from_slice(&BLOCK_STREAM_MAGIC);
        blob.extend_from_slice(&BLOCK_STREAM_VERSION.to_le_bytes());
        blob.extend_from_slice(&(DFIM_BLOCK_SIZE as u32).to_le_bytes());
        blob.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
        blob.extend_from_slice(root.as_slice());
        blob.extend_from_slice(&(fec.len() as u32).to_le_bytes());
        blob.extend_from_slice(&fec);
        for i in 0..blocks.len() {
            let proof = tree.prove(i).expect("prove");
            blob.push(proof.steps.len() as u8);
            for step in &proof.steps {
                blob.extend_from_slice(step.sibling.as_slice());
            }
        }

        let parsed = parse_block_stream(&blob).expect("parse");
        assert_eq!(parsed.block_count as usize, blocks.len());
    }
}
