//! PBKDF2-HMAC-SHA256 key derivation and HMAC authentication chain.
//!
//! Implements:
//! - `acc_0 = SHA256(concat_le64(coefficients))`
//! - `t = le64(c) || le64(i) || acc; acc = SHA256(t || SHA384(t)[:16])`
//! - `I = max(1000, 1000 + floor(crystal_index * 10000))`
//! - `S = SHA256(salt_label || le64(crystal_index))`
//! - `K = PBKDF2-HMAC-SHA256(P, S, I, 32)`
//! - `Tag = HMAC-SHA256(K, manifest_bytes)`

use crate::constants::{default_salt_label_const, pbkdf2_iterations, protocol_id_const, DK_LEN};
use crate::digest::sha256_digest;
use crate::error::{DfimError, DfimResult};
use digest::Digest;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha2::{Sha256, Sha384};

type HmacSha256 = Hmac<Sha256>;

/// Eight SU(3) coefficient seeds for nonlinear expansion.
pub type CoefficientSeed = [f64; 8];

/// Derived authentication key material.
pub type AuthKey = [u8; DK_LEN];

/// HMAC-SHA256 authentication tag.
pub type AuthTag = [u8; DK_LEN];

/// Nonlinear seed expansion: eight coefficients → 32-byte password `P`.
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(1), M=O(1), T=O(1)]
pub fn nonlinear_seed_expansion(coeffs: &CoefficientSeed) -> AuthKey {
    let mut acc = sha256_concat_f64(coeffs);
    for (i, c) in coeffs.iter().enumerate() {
        let mut t = [0u8; 8 + 8 + DK_LEN];
        t[..8].copy_from_slice(&c.to_le_bytes());
        t[8..16].copy_from_slice(&(i as u64).to_le_bytes());
        t[16..].copy_from_slice(&acc);

        let sha384_out = {
            let mut hasher = Sha384::new();
            hasher.update(t);
            hasher.finalize()
        };

        let mut mix = [0u8; 8 + 8 + DK_LEN + 16];
        mix[..t.len()].copy_from_slice(&t);
        mix[t.len()..t.len() + 16].copy_from_slice(&sha384_out[..16]);
        acc = sha256_digest(&mix[..t.len() + 16]);
    }
    acc
}

/// Derive salt: `S = SHA256(salt_label || le64(crystal_index))`.
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(1), M=O(1), T=O(1)]
pub fn derive_salt(crystal_index: f64, salt_label: &[u8]) -> DfimResult<[u8; DK_LEN]> {
    if !crystal_index.is_finite() {
        return Err(DfimError::InvalidParameter);
    }
    let mut buf = [0u8; 256];
    let label_len = salt_label.len().min(248);
    buf[..label_len].copy_from_slice(&salt_label[..label_len]);
    buf[label_len..label_len + 8].copy_from_slice(&crystal_index.to_le_bytes());
    Ok(sha256_digest(&buf[..label_len + 8]))
}

/// Derive authentication key via PBKDF2-HMAC-SHA256.
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(I), M=O(1), T=O(I)]
pub fn derive_authentication_key(
    coeffs: &CoefficientSeed,
    crystal_index: f64,
    salt_label: &[u8],
) -> DfimResult<(AuthKey, u32)> {
    let password = nonlinear_seed_expansion(coeffs);
    let iterations = pbkdf2_iterations(crystal_index)?;
    let salt = derive_salt(crystal_index, salt_label)?;

    let mut key = [0u8; DK_LEN];
    pbkdf2::<HmacSha256>(&password, &salt, iterations, &mut key)
        .map_err(|_| DfimError::IntegrityFailure)?;

    Ok((key, iterations))
}

/// Compute HMAC-SHA256 authentication tag over manifest bytes.
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(n), M=O(1), T=O(n)]
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
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(n), M=O(n), T=O(n)]
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

/// Full authentication pipeline: derive key and compute tag.
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(I+n), M=O(n), T=O(I+n)]
pub fn authenticate_manifest(
    coeffs: &CoefficientSeed,
    crystal_index: f64,
    manifest_bytes: &[u8],
) -> DfimResult<(AuthTag, u32)> {
    let (key, iterations) =
        derive_authentication_key(coeffs, crystal_index, default_salt_label_const())?;
    let tag = authentication_tag(&key, manifest_bytes)?;
    Ok((tag, iterations))
}

/// HKDF-SHA256 expand step for build-identity key material.
///
/// `HKDF-SHA256(IKM=build_identity_hash_hex_ascii, salt=domain, info=context)`
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(n), M=O(1), T=O(n)]
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

fn sha256_concat_f64(values: &[f64; 8]) -> AuthKey {
    let mut buf = [0u8; 64];
    for (i, v) in values.iter().enumerate() {
        buf[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }
    sha256_digest(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::CALIBRATED_PBKDF2_ITERATIONS;
    use crate::CRYSTAL_STABILITY_INDEX;

    #[test]
    fn pbkdf2_iteration_count_at_crystal_index() {
        let (_, iters) = derive_authentication_key(
            &[0.0; 8],
            CRYSTAL_STABILITY_INDEX,
            default_salt_label_const(),
        )
        .expect("derive");
        assert_eq!(iters, CALIBRATED_PBKDF2_ITERATIONS);
    }

    #[test]
    fn seed_expansion_is_deterministic() {
        let coeffs: CoefficientSeed = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let a = nonlinear_seed_expansion(&coeffs);
        let b = nonlinear_seed_expansion(&coeffs);
        assert_eq!(a, b);
    }

    #[test]
    fn authentication_tag_changes_with_manifest() {
        let coeffs = [0.1; 8];
        let (key, _) =
            derive_authentication_key(&coeffs, CRYSTAL_STABILITY_INDEX, default_salt_label_const())
                .expect("derive");
        let t1 = authentication_tag(&key, b"manifest-a").expect("tag");
        let t2 = authentication_tag(&key, b"manifest-b").expect("tag");
        assert_ne!(t1, t2);
    }

    #[test]
    fn hkdf_expand_produces_requested_length() {
        let out = hkdf_sha256_expand(b"ikm", b"salt", b"info", 32).expect("hkdf");
        assert_eq!(out.len(), 32);
    }
}
