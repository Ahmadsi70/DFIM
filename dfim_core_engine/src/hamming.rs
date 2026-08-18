//! Hamming linear block code — single-bit error correction.
//!
//! Implements catalog formula C1:
//! - `2^r >= n + r + 1`, `r = ceil(log2(n+1))`
//! - `P_j = XOR_{i: bit j of i = 1} D_i`
//! - `ECC(D, r)` — 0-error or 1-error correctable

use crate::constants::{HAMMING_MAX_DATA_BITS, HAMMING_MIN_DATA_BITS};
use crate::error::{DfimError, DfimResult};
use crate::observer::PatternObserver;

/// Minimum parity bits `r` satisfying `2^r >= n + r + 1`.
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(log n), M=O(1), T=O(log n)]
pub fn parity_bit_count(n_data: usize) -> DfimResult<usize> {
    if !(HAMMING_MIN_DATA_BITS..=HAMMING_MAX_DATA_BITS).contains(&n_data) {
        return Err(DfimError::InvalidParameter);
    }
    let mut r = ceil_log2(n_data + 1);
    let mut observer = PatternObserver::new(64)?;
    while (1usize << r) < n_data + r + 1 {
        observer.tick()?;
        r += 1;
        if r > 64 {
            return Err(DfimError::ParameterOverflow);
        }
    }
    Ok(r)
}

/// Total codeword bit length `n + r`.
pub fn codeword_bit_length(n_data: usize) -> DfimResult<usize> {
    let r = parity_bit_count(n_data)?;
    n_data.checked_add(r).ok_or(DfimError::ParameterOverflow)
}

/// Returns true when position (1-indexed) is a parity bit location (power of two).
#[inline]
pub fn is_parity_position(pos: usize) -> bool {
    pos != 0 && (pos & (pos - 1)) == 0
}

/// Encode `n_data` data bits into a Hamming codeword.
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(n+r), M=O(n+r) stack, T=O(n+r)]
pub fn encode_bits(data: u64, n_data: usize) -> DfimResult<u64> {
    if !(HAMMING_MIN_DATA_BITS..=HAMMING_MAX_DATA_BITS).contains(&n_data) {
        return Err(DfimError::InvalidParameter);
    }
    let mask = data_mask(n_data);
    if data & !mask != 0 {
        return Err(DfimError::InvalidParameter);
    }

    let r = parity_bit_count(n_data)?;
    let total = n_data + r;

    let mut cw = 0u64;
    let mut data_idx = 0usize;
    for pos in 1..=total {
        if is_parity_position(pos) {
            continue;
        }
        let bit = (data >> data_idx) & 1;
        cw |= bit << (pos - 1);
        data_idx += 1;
    }

    for p in 0..r {
        let parity_pos = 1usize << p;
        let mut parity = 0u64;
        for pos in 1..=total {
            if (pos >> p) & 1 == 1 {
                parity ^= (cw >> (pos - 1)) & 1;
            }
        }
        cw |= parity << (parity_pos - 1);
    }

    Ok(cw & data_mask(total))
}

/// Decode a Hamming codeword, correcting a single-bit error when possible.
///
/// Returns `(data, syndrome)`. When two or more bits are flipped, output may differ
/// from the original data (documented adversarial behavior).
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(n+r), M=O(n+r), T=O(n+r)]
pub fn decode_bits(codeword: u64, n_data: usize) -> DfimResult<(u64, u32)> {
    if !(HAMMING_MIN_DATA_BITS..=HAMMING_MAX_DATA_BITS).contains(&n_data) {
        return Err(DfimError::InvalidParameter);
    }
    let r = parity_bit_count(n_data)?;
    let total = n_data + r;
    let mask = data_mask(total);
    let mut cw = codeword & mask;

    let mut syndrome = 0u32;
    for p in 0..r {
        let _parity_pos = 1usize << p;
        let mut parity = 0u64;
        for pos in 1..=total {
            if (pos >> p) & 1 == 1 {
                parity ^= (cw >> (pos - 1)) & 1;
            }
        }
        if parity != 0 {
            syndrome |= 1 << p;
        }
    }

    if syndrome != 0 {
        let err_pos = syndrome as usize;
        if err_pos <= total {
            cw ^= 1u64 << (err_pos - 1);
        }
    }

    let mut data = 0u64;
    let mut data_idx = 0usize;
    for pos in 1..=total {
        if is_parity_position(pos) {
            continue;
        }
        let bit = (cw >> (pos - 1)) & 1;
        data |= bit << data_idx;
        data_idx += 1;
    }

    Ok((data & data_mask(n_data), syndrome))
}

/// Decode with syndrome verification — rejects multi-bit (uncorrectable) corruptions.
pub fn decode_bits_strict(codeword: u64, n_data: usize) -> DfimResult<u64> {
    if !(HAMMING_MIN_DATA_BITS..=HAMMING_MAX_DATA_BITS).contains(&n_data) {
        return Err(DfimError::InvalidParameter);
    }
    let r = parity_bit_count(n_data)?;
    let total = n_data + r;
    let mask = data_mask(total);
    let received = codeword & mask;

    let (data, syndrome) = decode_bits(received, n_data)?;
    let reencoded = encode_bits(data, n_data)?;

    if reencoded == received {
        return Ok(data);
    }

    if syndrome == 0 {
        return Err(DfimError::CorruptMetadata);
    }

    let err_pos = syndrome as usize;
    if err_pos == 0 || err_pos > total {
        return Err(DfimError::CorruptMetadata);
    }

    let corrected = received ^ (1u64 << (err_pos - 1));
    if reencoded == corrected {
        return Ok(data);
    }

    Err(DfimError::CorruptMetadata)
}

/// Encode a byte slice using Hamming(7,4) nibble packing.
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(n), M=O(n), T=O(n)]
#[cfg(feature = "alloc")]
pub fn encode_block(data: &[u8]) -> DfimResult<alloc::vec::Vec<u8>> {
    if data.is_empty() {
        return Err(DfimError::EmptyInput);
    }
    let mut out = alloc::vec::Vec::with_capacity(data.len() * 2);
    let mut observer = PatternObserver::new(data.len().saturating_mul(2))?;
    for &byte in data {
        observer.tick()?;
        let hi = (byte >> 4) & 0x0f;
        let lo = byte & 0x0f;
        let cw_hi = encode_bits(u64::from(hi), 4)?;
        let cw_lo = encode_bits(u64::from(lo), 4)?;
        out.push((cw_hi & 0x7f) as u8);
        out.push((cw_lo & 0x7f) as u8);
    }
    Ok(out)
}

/// Decode Hamming(7,4) packed data into a caller-provided buffer (no heap).
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(n), M=O(1), T=O(n)]
pub fn decode_block_into(encoded: &[u8], out: &mut [u8], written: &mut usize) -> DfimResult<()> {
    if encoded.is_empty() || !encoded.len().is_multiple_of(2) {
        return Err(DfimError::InvalidParameter);
    }
    let pairs = encoded.len() / 2;
    if out.len() < pairs {
        return Err(DfimError::BufferTooShort);
    }
    let mut observer = PatternObserver::new(pairs)?;
    *written = 0;
    for chunk in encoded.chunks_exact(2) {
        observer.tick()?;
        let (hi, _) = decode_bits(u64::from(chunk[0] & 0x7f), 4)?;
        let (lo, _) = decode_bits(u64::from(chunk[1] & 0x7f), 4)?;
        out[*written] = ((hi as u8) << 4) | (lo as u8);
        *written += 1;
    }
    Ok(())
}

/// Strict Hamming(7,4) decode into a caller buffer — fails on uncorrectable multi-bit rot.
pub fn decode_block_into_strict(
    encoded: &[u8],
    out: &mut [u8],
    written: &mut usize,
) -> DfimResult<()> {
    if encoded.is_empty() || !encoded.len().is_multiple_of(2) {
        return Err(DfimError::InvalidParameter);
    }
    let pairs = encoded.len() / 2;
    if out.len() < pairs {
        return Err(DfimError::BufferTooShort);
    }
    let mut observer = PatternObserver::new(pairs)?;
    *written = 0;
    for chunk in encoded.chunks_exact(2) {
        observer.tick()?;
        let hi = decode_bits_strict(u64::from(chunk[0] & 0x7f), 4)?;
        let lo = decode_bits_strict(u64::from(chunk[1] & 0x7f), 4)?;
        out[*written] = ((hi as u8) << 4) | (lo as u8);
        *written += 1;
    }
    Ok(())
}

/// Decode a Hamming(7,4) packed block.
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(n), M=O(n), T=O(n)]
#[cfg(feature = "alloc")]
pub fn decode_block(encoded: &[u8]) -> DfimResult<alloc::vec::Vec<u8>> {
    if encoded.is_empty() || !encoded.len().is_multiple_of(2) {
        return Err(DfimError::InvalidParameter);
    }
    let mut out = alloc::vec::Vec::with_capacity(encoded.len() / 2);
    let pairs = encoded.len() / 2;
    let mut observer = PatternObserver::new(pairs)?;
    for chunk in encoded.chunks_exact(2) {
        observer.tick()?;
        let hi = decode_bits_strict(u64::from(chunk[0] & 0x7f), 4)?;
        let lo = decode_bits_strict(u64::from(chunk[1] & 0x7f), 4)?;
        out.push(((hi as u8) << 4) | (lo as u8));
    }
    Ok(out)
}

#[inline]
fn data_mask(bits: usize) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

#[inline]
fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    let mut r = 0usize;
    let mut v = n - 1;
    while v > 0 {
        r += 1;
        v >>= 1;
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_count_hamming_7_4() {
        assert_eq!(parity_bit_count(4).expect("valid"), 3);
        assert_eq!(codeword_bit_length(4).expect("valid"), 7);
    }

    #[test]
    fn parity_count_hamming_15_11() {
        assert_eq!(parity_bit_count(11).expect("valid"), 4);
        assert_eq!(codeword_bit_length(11).expect("valid"), 15);
    }

    #[test]
    fn hamming_7_4_single_bit_correction() {
        let data = 0b1011u64;
        let cw = encode_bits(data, 4).expect("encode");
        for bit in 0..7 {
            let flipped = cw ^ (1u64 << bit);
            let (decoded, syndrome) = decode_bits(flipped, 4).expect("decode");
            assert_eq!(decoded, data, "failed correcting bit {bit}");
            assert_ne!(syndrome, 0, "syndrome should be non-zero for bit {bit}");
        }
    }

    #[test]
    fn hamming_double_bit_not_restored() {
        let data = 0xbu64;
        let cw = encode_bits(data, 4).expect("encode");
        let mut found = false;
        for mask in 1u64..(1u64 << 7) {
            if mask.count_ones() != 2 {
                continue;
            }
            let flipped = cw ^ mask;
            let (decoded, _syndrome) = decode_bits(flipped, 4).expect("decode");
            if decoded != data {
                found = true;
                break;
            }
        }
        assert!(found, "some 2-bit flip must not restore original data");
    }

    #[test]
    fn round_trip_block_codec() {
        let input = b"DFIM Layer-0 FEC";
        let encoded = encode_block(input).expect("encode");
        let decoded = decode_block(&encoded).expect("decode");
        assert_eq!(decoded, input);
    }
}
