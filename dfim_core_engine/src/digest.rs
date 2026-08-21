//! SHA-256 integrity seals for manifest and raw byte streams.

#[cfg(not(feature = "bpf"))]
use crate::error::{DfimError, DfimResult};

#[cfg(not(feature = "bpf"))]
use digest::Digest;
#[cfg(not(feature = "bpf"))]
use sha2::Sha256;

pub const SHA256_LEN: usize = 32;

/// SHA-256 digest over arbitrary byte stream.
#[cfg(all(not(feature = "bpf"), kani))]
pub fn sha256_digest(_data: &[u8]) -> [u8; SHA256_LEN] {
    kani::any()
}

/// SHA-256 digest over arbitrary byte stream.
#[cfg(all(not(feature = "bpf"), not(kani)))]
pub fn sha256_digest(data: &[u8]) -> [u8; SHA256_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut digest = [0u8; SHA256_LEN];
    digest.copy_from_slice(&out);
    digest
}

/// BPF-safe SHA-256 digest using the kernel workspace implementation.
#[cfg(feature = "bpf")]
pub fn sha256_digest(data: &[u8]) -> [u8; SHA256_LEN] {
    let mut workspace = crate::bpf_sha256::Sha256Workspace::new();
    crate::bpf_sha256::sha256_digest(data, &mut workspace)
}

/// SHA-256 digest over canonical UTF-8 manifest bytes.
#[cfg(not(feature = "bpf"))]
pub fn manifest_digest(canonical_utf8: &[u8]) -> DfimResult<[u8; SHA256_LEN]> {
    if canonical_utf8.is_empty() {
        return Err(DfimError::EmptyInput);
    }
    Ok(sha256_digest(canonical_utf8))
}

/// Chunked SHA-256 over a byte stream presented as fixed-size segments.
#[cfg(not(feature = "bpf"))]
pub fn sha256_digest_chunked(chunks: &[&[u8]]) -> [u8; SHA256_LEN] {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    let out = hasher.finalize();
    let mut digest = [0u8; SHA256_LEN];
    digest.copy_from_slice(&out);
    digest
}

/// Encode digest as lowercase hexadecimal (64 characters).
pub fn digest_to_hex(digest: &[u8; SHA256_LEN]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, byte) in digest.iter().enumerate() {
        out[i * 2] = HEX[(byte >> 4) as usize];
        out[i * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    out
}

#[cfg(all(test, not(feature = "bpf")))]
mod tests {
    use super::*;

    #[test]
    fn empty_manifest_rejected() {
        assert_eq!(manifest_digest(b""), Err(DfimError::EmptyInput));
    }

    #[test]
    fn sha256_known_vector() {
        let digest = sha256_digest(b"");
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(digest, expected);
    }
}
