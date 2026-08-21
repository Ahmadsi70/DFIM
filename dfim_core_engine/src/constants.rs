//! Governance and calibration constants for DFIM Layer-0 integrity pipelines.

/// Derived key length in bytes.
pub const DK_LEN: usize = 32;

/// SHA-256 digest length in bytes.
pub const SHA256_LEN: usize = 32;

/// Protocol identifier for canonical manifest byte construction.
pub fn protocol_id_const() -> &'static str {
    crate::secrets::protocol_id()
}

/// Default salt label for deterministic salt derivation.
pub fn default_salt_label_const() -> &'static [u8] {
    crate::secrets::default_salt_label()
}

/// Minimum Hamming data-bit width supported by the block codec.
pub const HAMMING_MIN_DATA_BITS: usize = 4;

/// Maximum Hamming data-bit width supported by the block codec.
pub const HAMMING_MAX_DATA_BITS: usize = 247;
