//! Authenticated rollback-baseline payload used by UEFI variable storage.

use dfim_core_engine::{DfimError, DfimResult};

/// Magic prefix for the payload stored in an authenticated UEFI variable.
pub const ROLLBACK_BASELINE_MAGIC: [u8; 8] = *b"DFIMROLL";
/// Current authenticated rollback payload version.
pub const ROLLBACK_BASELINE_VERSION: u32 = 1;
/// Canonical rollback payload byte length.
pub const ROLLBACK_BASELINE_LEN: usize = 36;

/// Builds the data portion of a time-authenticated UEFI rollback variable.
pub fn build_rollback_baseline(
    key_id: [u8; 16],
    minimum_release: u64,
) -> DfimResult<[u8; ROLLBACK_BASELINE_LEN]> {
    if minimum_release == 0 {
        return Err(DfimError::InvalidParameter);
    }
    let mut payload = [0u8; ROLLBACK_BASELINE_LEN];
    payload[..8].copy_from_slice(&ROLLBACK_BASELINE_MAGIC);
    payload[8..12].copy_from_slice(&ROLLBACK_BASELINE_VERSION.to_le_bytes());
    payload[12..20].copy_from_slice(&minimum_release.to_le_bytes());
    payload[20..].copy_from_slice(&key_id);
    Ok(payload)
}

/// Parses a firmware-authenticated baseline and binds it to the expected signing key.
pub fn parse_rollback_baseline(data: &[u8], expected_key_id: &[u8; 16]) -> DfimResult<u64> {
    if data.len() != ROLLBACK_BASELINE_LEN {
        return Err(DfimError::InvalidParameter);
    }
    if data[..8] != ROLLBACK_BASELINE_MAGIC {
        return Err(DfimError::IntegrityFailure);
    }
    let version = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    if version != ROLLBACK_BASELINE_VERSION {
        return Err(DfimError::InvalidParameter);
    }
    let minimum_release = u64::from_le_bytes([
        data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
    ]);
    if minimum_release == 0 {
        return Err(DfimError::IntegrityFailure);
    }
    let mut difference = 0u8;
    for index in 0..16 {
        difference |= data[20 + index] ^ expected_key_id[index];
    }
    if difference != 0 {
        return Err(DfimError::IntegrityFailure);
    }
    Ok(minimum_release)
}

/// Combines immutable and authenticated floors without permitting a downgrade.
pub fn effective_minimum_release(compiled: u64, persisted: u64) -> DfimResult<u64> {
    if compiled == 0 || persisted == 0 {
        return Err(DfimError::InvalidParameter);
    }
    Ok(core::cmp::max(compiled, persisted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dfim_core_engine::DfimError;

    const KEY_ID: [u8; 16] = *b"DFIM-ROLLBACK-01";

    #[test]
    fn rollback_baseline_round_trip() {
        let payload = build_rollback_baseline(KEY_ID, 42).expect("build");
        assert_eq!(
            parse_rollback_baseline(&payload, &KEY_ID).expect("parse"),
            42
        );
    }

    #[test]
    fn rollback_baseline_rejects_wrong_key_and_zero_counter() {
        assert_eq!(
            build_rollback_baseline(KEY_ID, 0).err(),
            Some(DfimError::InvalidParameter)
        );
        let payload = build_rollback_baseline(KEY_ID, 4).expect("build");
        assert_eq!(
            parse_rollback_baseline(&payload, &[0xAA; 16]).err(),
            Some(DfimError::IntegrityFailure)
        );
    }

    #[test]
    fn persisted_floor_can_only_raise_compiled_floor() {
        assert_eq!(effective_minimum_release(7, 9).expect("floor"), 9);
        assert_eq!(effective_minimum_release(9, 7).expect("floor"), 9);
    }
}
