//! Governance and calibration constants for DFIM Layer-0 integrity pipelines.

#[cfg(feature = "full")]
use crate::error::DfimResult;

#[cfg(feature = "full")]
use libm::{floor, fmin};

/// Crystal stability index — feeds PBKDF2 iteration formula
/// `I = max(1000, 1000 + floor(crystal_index * 10000))`.
pub const CRYSTAL_STABILITY_INDEX: f64 = 0.819_897_115_062_020_6;

/// Fine-structure inverse calibration scalar (dimensionless ratio base).
pub const ALPHA_INV: f64 = 137.035_999;

/// Recursion limit, buffer scaling, and backoff reference.
pub const D_SCALING: f64 = 93.354_004_23;

/// Luminosity base for dimensionless ratio computations.
pub const T_STAR: f64 = 0.06;

/// Harmonic determinant constant (boot-guard calibration family).
pub const T_OMEGA_DET: f64 = 0.000_133_534_038_092_105_1;

/// Harmonic integration constant.
pub const K_INT: f64 = 56.264_150_967_240_03;

/// Jaccard diffusion coefficient.
pub const JACCARD_DIFFUSION: f64 = 0.040_816_326_530_612_24;

/// Beta-frequency harmonic constant.
pub const NASIYA_BETA_FREQ: f64 = 22.666_666_666_666_664;

/// Isotropic coupling constant.
pub const K_ISO: f64 = 0.700_480_062_647_212_7;

/// PBKDF2 base iteration count.
pub const PBKDF2_BASE_ITER: u32 = 1000;

/// PBKDF2 scaling factor per crystal-index unit.
pub const PBKDF2_SCALE_PER_CRYSTAL: u32 = 10_000;

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

/// Documented PBKDF2 iteration count at [`CRYSTAL_STABILITY_INDEX`].
pub const CALIBRATED_PBKDF2_ITERATIONS: u32 = 9198;

/// Minimum Hamming data-bit width supported by the block codec.
pub const HAMMING_MIN_DATA_BITS: usize = 4;

/// Maximum Hamming data-bit width (work-capped by [`D_SCALING`]).
pub const HAMMING_MAX_DATA_BITS: usize = 247;

/// Compute PBKDF2 iteration count: `I = max(1000, 1000 + floor(crystal_index * 10000))`.
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(1), M=scalar, T=O(1)]
#[cfg(feature = "full")]
pub fn pbkdf2_iterations(crystal_index: f64) -> DfimResult<u32> {
    if !crystal_index.is_finite() || crystal_index < 0.0 {
        return Err(crate::error::DfimError::InvalidParameter);
    }
    let scaled = crystal_index * f64::from(PBKDF2_SCALE_PER_CRYSTAL);
    let floored = floor(scaled);
    if !floored.is_finite() || floored > f64::from(u32::MAX) {
        return Err(crate::error::DfimError::ParameterOverflow);
    }
    let derived = PBKDF2_BASE_ITER.saturating_add(floored as u32);
    Ok(core::cmp::max(PBKDF2_BASE_ITER, derived))
}

/// MoFo-Lab trimming intensity `I(L)` for memory-heavy paths.
#[cfg(feature = "full")]
pub fn trimming_intensity(load: f64) -> f64 {
    if load <= 0.20 {
        (load / 0.20) * 0.15
    } else if load < 0.88 {
        0.15 + ((load - 0.20) / 0.68) * 0.55
    } else {
        0.70 + fmin((load - 0.88) / 0.12, 1.0) * 0.30
    }
}

#[cfg(all(test, feature = "full"))]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_iterations_matches_calibrated_constant() {
        let i = pbkdf2_iterations(CRYSTAL_STABILITY_INDEX).expect("valid index");
        assert_eq!(i, CALIBRATED_PBKDF2_ITERATIONS);
    }

    #[test]
    fn pbkdf2_iterations_floor_at_minimum() {
        assert_eq!(pbkdf2_iterations(0.0).expect("valid"), PBKDF2_BASE_ITER);
    }
}
