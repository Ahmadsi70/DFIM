//! Authenticated `.dfim` sidecar / state-database envelope parsing.
//!
//! Rejects plaintext license blobs and unauthenticated injections before Merkle validation.

use crate::crypto::constant_time_hash_eq;
use crate::digest::sha256_digest;
use crate::error::{DfimError, DfimResult};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Magic prefix for bare boot sidecar blobs (`*.dfim`).
pub const BOOT_SIDECAR_MAGIC: [u8; 8] = *b"DFIMBOOT";

/// Magic prefix for wrapped authenticated state databases.
pub const WRAPPED_STATE_MAGIC: [u8; 8] = *b"DFIMSTAT";

const BOOT_SIDECAR_VERSION: u32 = 1;
const WRAPPED_STATE_VERSION: u32 = 1;
const BOOT_HEADER_PREFIX_LEN: usize = 56;
const WRAPPED_HEADER_LEN: usize = 16;
const WRAPPED_CHECKSUM_LEN: usize = 32;
const LEGACY_LICENSE_LEN: usize = 16;

/// Minimum on-disk size for a wrapped authenticated state database envelope.
pub const MIN_WRAPPED_STATE_LEN: usize = WRAPPED_HEADER_LEN + WRAPPED_CHECKSUM_LEN;

/// Parses and authenticates a `--state` database file into raw boot sidecar bytes.
#[cfg(feature = "alloc")]
pub fn parse_authenticated_state_db(raw: &[u8]) -> DfimResult<Vec<u8>> {
    reject_plaintext_injection(raw)?;

    if raw.len() >= 8 && raw[0..8] == WRAPPED_STATE_MAGIC {
        return unwrap_authenticated_envelope(raw);
    }

    if raw.len() >= 8 && raw[0..8] == BOOT_SIDECAR_MAGIC {
        validate_boot_sidecar_header(raw)?;
        return Ok(raw.to_vec());
    }

    Err(DfimError::CorruptMetadata)
}

/// Builds a wrapped authenticated state database around a boot sidecar payload.
#[cfg(feature = "alloc")]
pub fn wrap_authenticated_state_db(sidecar_payload: &[u8]) -> DfimResult<Vec<u8>> {
    validate_boot_sidecar_header(sidecar_payload)?;

    let payload_len = sidecar_payload.len();
    if payload_len > u32::MAX as usize {
        return Err(DfimError::ParameterOverflow);
    }

    let mut out = Vec::with_capacity(MIN_WRAPPED_STATE_LEN + payload_len);
    out.extend_from_slice(&WRAPPED_STATE_MAGIC);
    out.extend_from_slice(&WRAPPED_STATE_VERSION.to_le_bytes());
    out.extend_from_slice(&(payload_len as u32).to_le_bytes());
    out.extend_from_slice(sidecar_payload);

    let checksum = compute_wrapped_checksum(&out);
    out.extend_from_slice(&checksum);
    Ok(out)
}

#[cfg(feature = "alloc")]
fn unwrap_authenticated_envelope(raw: &[u8]) -> DfimResult<Vec<u8>> {
    if raw.len() < MIN_WRAPPED_STATE_LEN {
        return Err(DfimError::BufferTooShort);
    }

    let version = read_u32(&raw[8..12])?;
    if version != WRAPPED_STATE_VERSION {
        return Err(DfimError::InvalidParameter);
    }

    let payload_len = read_u32(&raw[12..16])? as usize;
    let payload_end = WRAPPED_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(DfimError::ParameterOverflow)?;
    if raw.len() != payload_end + WRAPPED_CHECKSUM_LEN {
        return Err(DfimError::CorruptMetadata);
    }

    let expected_checksum = compute_wrapped_checksum(&raw[..payload_end]);
    let mut stored = [0u8; WRAPPED_CHECKSUM_LEN];
    stored.copy_from_slice(&raw[payload_end..payload_end + WRAPPED_CHECKSUM_LEN]);
    if !constant_time_hash_eq(&expected_checksum, &stored) {
        return Err(DfimError::IntegrityFailure);
    }

    let payload = &raw[WRAPPED_HEADER_LEN..payload_end];
    validate_boot_sidecar_header(payload)?;
    Ok(payload.to_vec())
}

fn validate_boot_sidecar_header(data: &[u8]) -> DfimResult<()> {
    if data.len() < BOOT_HEADER_PREFIX_LEN {
        return Err(DfimError::BufferTooShort);
    }
    if data[0..8] != BOOT_SIDECAR_MAGIC {
        return Err(DfimError::IntegrityFailure);
    }
    let version = read_u32(&data[8..12])?;
    if version != BOOT_SIDECAR_VERSION {
        return Err(DfimError::InvalidParameter);
    }
    let block_size = read_u32(&data[12..16])?;
    let block_count = read_u32(&data[16..20])?;
    if block_size as usize != crate::DFIM_BLOCK_SIZE || block_count == 0 {
        return Err(DfimError::InvalidParameter);
    }
    crate::validate_block_count(block_count)?;
    Ok(())
}

fn compute_wrapped_checksum(header_and_payload: &[u8]) -> [u8; 32] {
    sha256_digest(header_and_payload)
}

fn reject_plaintext_injection(raw: &[u8]) -> DfimResult<()> {
    if raw.is_empty() {
        return Err(DfimError::EmptyInput);
    }

    if raw.len() == LEGACY_LICENSE_LEN {
        return Err(DfimError::CorruptMetadata);
    }

    if raw.starts_with(b"STATE_") || raw.starts_with(b"STATE_HASH") {
        return Err(DfimError::CorruptMetadata);
    }

    if raw.len() < 8
        && raw
            .iter()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
    {
        return Err(DfimError::CorruptMetadata);
    }

    Ok(())
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
    use crate::DFIM_BLOCK_SIZE;
    use alloc::vec;

    fn minimal_sidecar() -> Vec<u8> {
        let mut blob = vec![0u8; BOOT_HEADER_PREFIX_LEN + 4];
        blob[0..8].copy_from_slice(&BOOT_SIDECAR_MAGIC);
        blob[8..12].copy_from_slice(&BOOT_SIDECAR_VERSION.to_le_bytes());
        blob[12..16].copy_from_slice(&(DFIM_BLOCK_SIZE as u32).to_le_bytes());
        blob[16..20].copy_from_slice(&1u32.to_le_bytes());
        blob[20..52].copy_from_slice(&[0xAB; 32]);
        blob[52..56].copy_from_slice(&4u32.to_le_bytes());
        blob
    }

    #[test]
    fn rejects_plaintext_license_injection() {
        assert_eq!(
            parse_authenticated_state_db(b"STATE_HASH_CLOCK_VALID_A"),
            Err(DfimError::CorruptMetadata)
        );
    }

    #[test]
    fn rejects_sixteen_byte_clock_vector() {
        assert_eq!(
            parse_authenticated_state_db(&[0u8; 16]),
            Err(DfimError::CorruptMetadata)
        );
    }

    #[test]
    fn wrapped_round_trip() {
        let sidecar = minimal_sidecar();
        let wrapped = wrap_authenticated_state_db(&sidecar).expect("wrap");
        let parsed = parse_authenticated_state_db(&wrapped).expect("parse");
        assert_eq!(parsed, sidecar);
    }

    #[test]
    fn wrapped_checksum_tamper_fails() {
        let sidecar = minimal_sidecar();
        let mut wrapped = wrap_authenticated_state_db(&sidecar).expect("wrap");
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01;
        assert_eq!(
            parse_authenticated_state_db(&wrapped),
            Err(DfimError::IntegrityFailure)
        );
    }
}
