//! Merkle tree hierarchical integrity with O(log N) membership proofs.
//!
//! Implements catalog formula C2:
//! - `h_i = H(D_i)` (leaf)
//! - `h_parent = H(h_left || h_right)`
//! - `|proof| = O(log N)`

use crate::constants::SHA256_LEN;
use crate::digest::sha256_digest;
#[cfg(feature = "alloc")]
use crate::error::{DfimError, DfimResult};
#[cfg(feature = "alloc")]
use crate::observer::PatternObserver;

/// Side of a sibling hash in a Merkle proof path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSide {
    Left,
    Right,
}

/// Single step in a Merkle membership proof (sibling hash only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofStep {
    pub sibling: [u8; SHA256_LEN],
}

/// Merkle membership proof — length O(log N).
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub steps: alloc::vec::Vec<ProofStep>,
}

/// Merkle tree over SHA-256 leaf digests.
#[cfg(feature = "alloc")]
pub struct MerkleTree {
    root: [u8; SHA256_LEN],
    layers: alloc::vec::Vec<alloc::vec::Vec<[u8; SHA256_LEN]>>,
}

#[cfg(feature = "alloc")]
impl MerkleTree {
    /// Build tree from raw leaf data units.
    ///
    /// /// [DFIM_AUDIT_LMT] Proof: [L=O(N log N), M=O(N), T=O(N log N)]
    pub fn build(leaves: &[&[u8]]) -> DfimResult<Self> {
        if leaves.is_empty() {
            return Err(DfimError::EmptyInput);
        }

        let mut observer = PatternObserver::new(leaves.len().saturating_mul(3))?;
        let mut current: alloc::vec::Vec<[u8; SHA256_LEN]> =
            alloc::vec::Vec::with_capacity(leaves.len());
        for leaf in leaves {
            observer.tick()?;
            current.push(sha256_digest(leaf));
        }

        let mut layers = alloc::vec::Vec::new();
        layers.push(current.clone());

        while current.len() > 1 {
            let mut next = alloc::vec::Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0usize;
            while i < current.len() {
                observer.tick()?;
                let left = current[i];
                let right = if i + 1 < current.len() {
                    current[i + 1]
                } else {
                    current[i]
                };
                next.push(parent_hash(&left, &right));
                i += 2;
            }
            layers.push(next.clone());
            current = next;
        }

        let root = current
            .first()
            .copied()
            .ok_or(DfimError::IntegrityFailure)?;

        Ok(Self { root, layers })
    }

    pub const fn root(&self) -> &[u8; SHA256_LEN] {
        &self.root
    }

    pub fn leaf_count(&self) -> usize {
        self.layers.first().map_or(0, alloc::vec::Vec::len)
    }

    /// Generate O(log N) membership proof for leaf at `index`.
    ///
    /// /// [DFIM_AUDIT_LMT] Proof: [L=O(log N), M=O(log N), T=O(log N)]
    pub fn prove(&self, index: usize) -> DfimResult<MerkleProof> {
        let leaf_count = self.leaf_count();
        if index >= leaf_count {
            return Err(DfimError::InvalidParameter);
        }

        let mut steps = alloc::vec::Vec::new();
        let mut idx = index;
        let mut observer = PatternObserver::new(leaf_count.max(1001))?;

        for layer in &self.layers[..self.layers.len() - 1] {
            observer.tick()?;
            let sibling_idx = if idx.is_multiple_of(2) {
                if idx + 1 < layer.len() {
                    idx + 1
                } else {
                    idx
                }
            } else {
                idx - 1
            };

            steps.push(ProofStep {
                sibling: layer[sibling_idx],
            });
            idx /= 2;
        }

        Ok(MerkleProof { steps })
    }
}

/// Compute parent hash: `H(h_left || h_right)`.
#[inline]
#[cfg(not(feature = "bpf"))]
pub fn parent_hash(left: &[u8; SHA256_LEN], right: &[u8; SHA256_LEN]) -> [u8; SHA256_LEN] {
    let mut buf = [0u8; SHA256_LEN * 2];
    buf[..SHA256_LEN].copy_from_slice(left);
    buf[SHA256_LEN..].copy_from_slice(right);
    sha256_digest(&buf)
}

/// BPF-safe parent hash using the map-backed workspace hash routine.
#[inline]
#[cfg(feature = "bpf")]
pub fn parent_hash(left: &[u8; SHA256_LEN], right: &[u8; SHA256_LEN]) -> [u8; SHA256_LEN] {
    let mut workspace = crate::bpf_sha256::Sha256Workspace::new();
    crate::bpf_sha256::parent_hash(left, right, &mut workspace)
}

/// Leaf hash: `h_i = H(D_i)`.
#[inline]
#[cfg(not(feature = "bpf"))]
pub fn leaf_hash(data: &[u8]) -> [u8; SHA256_LEN] {
    sha256_digest(data)
}

/// BPF-safe leaf hash using the kernel workspace hash routine.
#[inline]
#[cfg(feature = "bpf")]
pub fn leaf_hash(data: &[u8]) -> [u8; SHA256_LEN] {
    let mut workspace = crate::bpf_sha256::Sha256Workspace::new();
    crate::bpf_sha256::sha256_digest(data, &mut workspace)
}

/// Verify membership proof against published root.
#[cfg(feature = "full")]
pub fn verify_proof(
    root: &[u8; SHA256_LEN],
    leaf_data: &[u8],
    leaf_index: usize,
    proof: &MerkleProof,
) -> DfimResult<bool> {
    let mut hash = leaf_hash(leaf_data);
    let mut _index = leaf_index;
    let mut observer = PatternObserver::new(proof.steps.len().max(1001))?;

    for step in &proof.steps {
        observer.tick()?;
        hash = if _index.is_multiple_of(2) {
            parent_hash(&hash, &step.sibling)
        } else {
            parent_hash(&step.sibling, &hash)
        };
        _index /= 2;
    }

    Ok(crate::crypto::constant_time_hash_eq(&hash, root))
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    fn sample_leaves(n: usize) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
        (0..n)
            .map(|i| alloc::format!("leaf-{i}").into_bytes())
            .collect()
    }

    #[test]
    fn merkle_single_bit_tamper_rejected() {
        let raw = sample_leaves(8);
        let leaves: alloc::vec::Vec<&[u8]> = raw.iter().map(|v| v.as_slice()).collect();
        let tree = MerkleTree::build(&leaves).expect("build");
        let root = *tree.root();

        for (i, leaf) in leaves.iter().enumerate() {
            if leaf.is_empty() {
                continue;
            }
            for bit_byte in 0..leaf.len() {
                for bit in 0..8 {
                    let mut tampered = leaf.to_vec();
                    tampered[bit_byte] ^= 1u8 << bit;
                    let proof = tree.prove(i).expect("prove");
                    let ok = verify_proof(&root, &tampered, i, &proof).expect("verify");
                    assert!(!ok, "tampered leaf {i} bit {bit_byte}:{bit} must fail");
                }
            }
        }
    }

    #[test]
    fn merkle_forged_leaf_rejected() {
        let raw = sample_leaves(4);
        let leaves: alloc::vec::Vec<&[u8]> = raw.iter().map(|v| v.as_slice()).collect();
        let tree = MerkleTree::build(&leaves).expect("build");
        let proof = tree.prove(0).expect("prove");
        let forged = b"forged-leaf-data";
        assert!(
            !verify_proof(tree.root(), forged, 0, &proof).expect("verify"),
            "forged leaf must be rejected"
        );
    }

    #[test]
    fn merkle_proof_index_swap_rejected() {
        let raw = sample_leaves(4);
        let leaves: alloc::vec::Vec<&[u8]> = raw.iter().map(|v| v.as_slice()).collect();
        let tree = MerkleTree::build(&leaves).expect("build");
        let proof = tree.prove(0).expect("prove");
        assert!(
            !verify_proof(tree.root(), leaves[0], 1, &proof).expect("verify"),
            "proof must bind to leaf index"
        );
    }

    #[test]
    fn merkle_4096_leaves_build_verify() {
        let raw = sample_leaves(4096);
        let refs: alloc::vec::Vec<&[u8]> = raw.iter().map(|v| v.as_slice()).collect();
        let tree = MerkleTree::build(&refs).expect("build");
        assert_eq!(tree.leaf_count(), 4096);

        for idx in [0, 1, 2047, 4095] {
            let proof = tree.prove(idx).expect("prove");
            assert!(
                verify_proof(tree.root(), refs[idx], idx, &proof).expect("verify"),
                "leaf {idx} must verify"
            );
        }
    }
}
