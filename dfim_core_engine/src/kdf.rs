//! Key derivation and HMAC authentication for enrolled-manifest commitments.
//!
//! Standard, audited primitives only:
//! - `S = SHA256(salt_label || seed)` — deterministic domain-separated salt
//! - `K = HKDF-SHA256(IKM=seed, salt=S, info=context)` — key derivation
//! - `Tag = HMAC-SHA256(K, manifest_bytes)` — authentication tag

use crate::constants::{default_salt_label_const, protocol_id_const, DK_LEN, SHA256_LEN};
use crate::digest::sha256_digest;
use crate::error::{DfimError, DfimResult};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Uniform-random authentication seed (32 bytes).
pub type AuthSeed = [u8; DK_LEN];

/// Derived authentication key material (32 bytes).
pub type AuthKey = [u8; DK_LEN];

/// HMAC-SHA256 authentication tag (32 bytes).
pub type AuthTag = [u8; DK_LEN];

/// HKDF context string separating the manifest-authentication domain.
const AUTH_INFO: &[u8] = b"dfim-manifest-auth-v1";

/// Derive a deterministic salt: `S = SHA256(salt_label || seed)`.
pub fn derive_salt(salt_label: &[u8], seed: &[u8]) -> DfimResult<[u8; SHA256_LEN]> {
    if seed.is_empty() {
        return Err(DfimError::EmptyInput);
    }
    let label_len = salt_label.len().min(200);
    let seed_len = seed.len().min(56);
    let mut buf = [0u8; 256];
    buf[..label_len].copy_from_slice(&salt_label[..label_len]);
    buf[label_len..label_len + seed_len].copy_from_slice(&seed[..seed_len]);
    Ok(sha256_digest(&buf[..label_len + seed_len]))
}

/// Derive an authentication key via HKDF-SHA256.
pub fn derive_authentication_key(seed: &AuthSeed, salt: &[u8], info: &[u8]) -> DfimResult<AuthKey> {
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(Some(salt), seed);
    let mut key = [0u8; DK_LEN];
    hk.expand(info, &mut key)
        .map_err(|_| DfimError::IntegrityFailure)?;
    Ok(key)
}

/// Compute HMAC-SHA256 authentication tag over manifest bytes.
pub fn authentication_tag(key: &AuthKey, manifest_bytes: &[u8]) -> DfimResult<AuthTag> {
    if manifest_bytes.is_empty() {
        return Err(DfimError::EmptyInput);
    }
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| DfimError::IntegrityFailure)?;
    mac.update(manifest_bytes);
    let result = mac.finalize().into_bytes();
    let mut tag = [0u8; DK_LEN];
    tag.copy_from_slice(&result);
    Ok(tag)
}

/// Build canonical manifest bytes from anchor coordinates and abjad values.
///
/// `manifest_bytes = UTF-8(PROTOCOL_ID + "\n" + "anchors" + "\n" + coords + "\n" + abjad)`
pub fn canonical_manifest_bytes(coords: &[u64], abjad: &[u64]) -> DfimResult<alloc::vec::Vec<u8>> {
    if coords.is_empty() && abjad.is_empty() {
        return Err(DfimError::EmptyInput);
    }

    let mut coords_str = alloc::string::String::new();
    for (i, c) in coords.iter().enumerate() {
        if i > 0 {
            coords_str.push('|');
        }
        coords_str.push_str(&alloc::format!("{c}"));
    }

    let mut abjad_str = alloc::string::String::new();
    for (i, a) in abjad.iter().enumerate() {
        if i > 0 {
            abjad_str.push('|');
        }
        abjad_str.push_str(&alloc::format!("{a}"));
    }

    let manifest = alloc::format!(
        "{}\n{}\n{coords_str}\n{abjad_str}",
        protocol_id_const(),
        crate::secrets::anchors_label(),
    );
    Ok(manifest.into_bytes())
}

/// Full authentication pipeline: derive HKDF key and compute HMAC tag.
pub fn authenticate_manifest(seed: &AuthSeed, manifest_bytes: &[u8]) -> DfimResult<AuthTag> {
    let salt = derive_salt(default_salt_label_const(), seed)?;
    let key = derive_authentication_key(seed, &salt, AUTH_INFO)?;
    authentication_tag(&key, manifest_bytes)
}

/// HKDF-SHA256 expand step for build-identity key material.
///
/// `HKDF-SHA256(IKM=ikm, salt=domain, info=context)`
pub fn hkdf_sha256_expand(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> DfimResult<alloc::vec::Vec<u8>> {
    if ikm.is_empty() || out_len == 0 || out_len > DK_LEN * 4 {
        return Err(DfimError::InvalidParameter);
    }
    use hkdf::Hkdf;
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = alloc::vec::Vec::new();
    okm.try_reserve(out_len)
        .map_err(|_| DfimError::ParameterOverflow)?;
    okm.resize(out_len, 0);
    hk.expand(info, &mut okm)
        .map_err(|_| DfimError::IntegrityFailure)?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> AuthSeed {
        [0x42; DK_LEN]
    }

    #[test]
    fn derive_salt_is_deterministic_and_domain_separated() {
        let a = derive_salt(b"label", &seed()).expect("salt");
        let b = derive_salt(b"label", &seed()).expect("salt");
        let c = derive_salt(b"other", &seed()).expect("salt");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn derive_salt_rejects_empty_seed() {
        assert_eq!(derive_salt(b"label", b""), Err(DfimError::EmptyInput));
    }

    #[test]
    fn derive_authentication_key_is_deterministic() {
        let a = derive_authentication_key(&seed(), b"salt", AUTH_INFO).expect("key");
        let b = derive_authentication_key(&seed(), b"salt", AUTH_INFO).expect("key");
        let c = derive_authentication_key(&seed(), b"salt", b"other").expect("key");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn authentication_tag_changes_with_manifest() {
        let key = derive_authentication_key(&seed(), b"salt", AUTH_INFO).expect("key");
        let t1 = authentication_tag(&key, b"manifest-a").expect("tag");
        let t2 = authentication_tag(&key, b"manifest-b").expect("tag");
        assert_ne!(t1, t2);
    }

    #[test]
    fn authenticate_manifest_is_deterministic_and_seed_bound() {
        let m = b"manifest-bytes";
        let t1 = authenticate_manifest(&seed(), m).expect("tag");
        let t2 = authenticate_manifest(&seed(), m).expect("tag");
        let other = authenticate_manifest(&[0x24; DK_LEN], m).expect("tag");
        assert_eq!(t1, t2);
        assert_ne!(t1, other);
    }

    #[test]
    fn hkdf_expand_produces_requested_length() {
        let out = hkdf_sha256_expand(b"ikm", b"salt", b"info", 32).expect("hkdf");
        assert_eq!(out.len(), 32);
    }
}
