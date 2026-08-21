//! Constant-time cryptographic comparisons for side-channel-resistant verification.

use subtle::ConstantTimeEq;

/// Compare two 32-byte SHA-256 digests in constant time.
///
/// Processes all 32 bytes deterministically to mitigate microarchitectural
/// timing leaks during Merkle root and sidecar baseline validation.
#[inline(never)]
pub fn constant_time_hash_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_hashes_match() {
        let h = [0xAB_u8; 32];
        assert!(constant_time_hash_eq(&h, &h));
    }

    #[test]
    fn single_bit_flip_rejects() {
        let mut b = [0u8; 32];
        b[0] = 1;
        assert!(!constant_time_hash_eq(&[0u8; 32], &b));
    }
}
