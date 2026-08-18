//! Phasor aggregate build-identity hash.
//!
//! Implements:
//! - `z = Σ_k w_k · exp(i·φ_k)`
//! - `R = |z|`, `θ = arg(z)`
//! - `BUILD_IDENTITY_HASH = SHA256(UTF-8(canon_lines))`

use crate::constants::SHA256_LEN;
use crate::digest::{digest_to_hex, sha256_digest};
use crate::error::{DfimError, DfimResult};
use libm::{atan2f, cosf, sinf, sqrtf};

/// Single phasor term in the build-identity aggregate.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PhasorTerm {
    pub role: &'static str,
    pub rank: u32,
    pub axis: u32,
    pub phi_rad: f32,
    pub weight: f32,
}

/// Resultant phasor aggregate metrics.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PhasorAggregate {
    pub resultant_re: f32,
    pub resultant_im: f32,
    pub magnitude_r: f32,
    pub theta_rad: f32,
    pub crystalline_ratio_l1: f32,
}

/// Compute phasor sum `z = Σ_k w_k · exp(i·φ_k)`.
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(k), M=O(1), T=O(k)]
pub fn phasor_aggregate(terms: &[PhasorTerm]) -> DfimResult<PhasorAggregate> {
    if terms.is_empty() {
        return Err(DfimError::EmptyInput);
    }

    let mut re = 0.0f32;
    let mut im = 0.0f32;
    let mut weight_l1 = 0.0f32;
    let mut _weight_sum = 0.0f32;

    for term in terms {
        if !term.weight.is_finite() || !term.phi_rad.is_finite() {
            return Err(DfimError::InvalidParameter);
        }
        re += term.weight * cosf(term.phi_rad);
        im += term.weight * sinf(term.phi_rad);
        weight_l1 += libm::fabsf(term.weight);
        _weight_sum += term.weight;
    }

    let magnitude_r = sqrtf(re * re + im * im);
    let theta_rad = atan2f(im, re);
    let crystalline_ratio_l1 = if weight_l1 > 0.0 {
        magnitude_r / weight_l1
    } else {
        0.0
    };

    Ok(PhasorAggregate {
        resultant_re: re,
        resultant_im: im,
        magnitude_r,
        theta_rad,
        crystalline_ratio_l1,
    })
}

/// Build canonical line sequence for build-identity hash commitment.
pub fn canonical_phasor_lines(
    aggregate: &PhasorAggregate,
    terms: &[PhasorTerm],
) -> DfimResult<alloc::vec::Vec<alloc::string::String>> {
    let mut lines = alloc::vec::Vec::with_capacity(terms.len() + 5);
    lines.push(alloc::string::String::from("phase_31_d_v1"));
    lines.push(alloc::format!("{}", aggregate.resultant_re));
    lines.push(alloc::format!("{}", aggregate.resultant_im));
    lines.push(alloc::format!("{}", aggregate.magnitude_r));
    lines.push(alloc::format!("{}", aggregate.theta_rad));

    for term in terms {
        lines.push(alloc::format!(
            "{}|r={}|ax={}|p={}|w={}",
            term.role,
            term.rank,
            term.axis,
            term.phi_rad,
            term.weight
        ));
    }
    Ok(lines)
}

/// Compute build-identity hash: `SHA256(UTF-8("\n".join(canon_lines)))`.
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(k), M=O(k), T=O(k)]
pub fn build_identity_hash(terms: &[PhasorTerm]) -> DfimResult<[u8; SHA256_LEN]> {
    let aggregate = phasor_aggregate(terms)?;
    let lines = canonical_phasor_lines(&aggregate, terms)?;
    let joined = lines.join("\n");
    Ok(sha256_digest(joined.as_bytes()))
}

/// 64-character lowercase hex encoding of build-identity hash.
pub fn build_identity_hex(hash: &[u8; SHA256_LEN]) -> [u8; 64] {
    digest_to_hex(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phasor_single_term_magnitude_equals_weight() {
        let terms = [PhasorTerm {
            role: "noor",
            rank: 1,
            axis: 0,
            phi_rad: 0.0,
            weight: 0.5,
        }];
        let agg = phasor_aggregate(&terms).expect("aggregate");
        assert!((agg.magnitude_r - 0.5).abs() < 1e-6);
        assert!((agg.crystalline_ratio_l1 - 1.0).abs() < 1e-6);
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
}
