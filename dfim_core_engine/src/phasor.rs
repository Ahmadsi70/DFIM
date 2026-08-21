//! Build-identity hash commitment.
//!
//! `BUILD_IDENTITY_HASH = SHA256(canonical bytes)` where the canonical bytes are
//! a fixed-width, endian-explicit encoding of the build terms. Floating-point
//! fields are encoded via their IEEE-754 bit patterns (`to_bits`) so the hash is
//! reproducible across platforms (no transcendental math is involved).

use crate::constants::SHA256_LEN;
use crate::digest::{digest_to_hex, sha256_digest};
use crate::error::{DfimError, DfimResult};

/// A single build-identity term.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PhasorTerm {
    pub role: &'static str,
    pub rank: u32,
    pub axis: u32,
    pub phi_rad: f32,
    pub weight: f32,
}

/// Appends a canonical, fixed-width encoding of a term to `out`.
fn append_canonical_term(term: &PhasorTerm, out: &mut alloc::vec::Vec<u8>) {
    out.extend_from_slice(term.role.as_bytes());
    out.push(0); // NUL separator
    out.extend_from_slice(&term.rank.to_le_bytes());
    out.extend_from_slice(&term.axis.to_le_bytes());
    out.extend_from_slice(&term.phi_rad.to_bits().to_le_bytes());
    out.extend_from_slice(&term.weight.to_bits().to_le_bytes());
}

/// Compute build-identity hash: `SHA256(concat(canonical_term(terms)))`.
pub fn build_identity_hash(terms: &[PhasorTerm]) -> DfimResult<[u8; SHA256_LEN]> {
    if terms.is_empty() {
        return Err(DfimError::EmptyInput);
    }
    let mut buf = alloc::vec::Vec::new();
    for term in terms {
        append_canonical_term(term, &mut buf);
    }
    Ok(sha256_digest(&buf))
}

/// 64-character lowercase hex encoding of build-identity hash.
pub fn build_identity_hex(hash: &[u8; SHA256_LEN]) -> [u8; 64] {
    digest_to_hex(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_identity_hash_rejects_empty_terms() {
        assert_eq!(build_identity_hash(&[]), Err(DfimError::EmptyInput));
    }

    #[test]
    fn build_identity_hash_is_deterministic() {
        let terms = [
            PhasorTerm {
                role: "noor",
                rank: 1,
                axis: 0,
                phi_rad: -2.016_104,
                weight: 0.039_199_937,
            },
            PhasorTerm {
                role: "hadid",
                rank: 2,
                axis: 1,
                phi_rad: 2.264_234_8,
                weight: 0.068_394_29,
            },
        ];
        let h1 = build_identity_hash(&terms).expect("hash");
        let h2 = build_identity_hash(&terms).expect("hash");
        assert_eq!(h1, h2);
    }

    #[test]
    fn build_identity_hash_distinguishes_terms() {
        let a = [PhasorTerm {
            role: "x",
            rank: 1,
            axis: 0,
            phi_rad: 0.0,
            weight: 1.0,
        }];
        let b = [PhasorTerm {
            role: "x",
            rank: 2,
            axis: 0,
            phi_rad: 0.0,
            weight: 1.0,
        }];
        assert_ne!(
            build_identity_hash(&a).expect("hash"),
            build_identity_hash(&b).expect("hash")
        );
    }
}
