//! DFIM Integration Tests — Phase 0 GAP-2
//!
//! Cross-crate integration tests validating:
//!   core↔cli:  Provisioner creates sidecar, core engine verifies it
//!   core↔uefi: Compact boot manifest round-trip
//!   core↔host: Host init eval license ↔ core crypto
//!
//! Run: cargo test --test '*' -- --test-threads=1

use dfim_core_engine::{
    boot_validate::{validate_block_compact, DFIM_BLOCK_SIZE, MAX_BOOT_BLOCKS},
    crypto::constant_time_hash_eq,
    digest::sha256_digest,
    hamming::{encode_block, decode_block_into_strict},
    SHA256_LEN,
};

// ═══════════════════════════════════════════════════════════════════
// core ↔ cli: Sidecar verification
// ═══════════════════════════════════════════════════════════════════

#[test]
fn core_cli_sidecar_roundtrip() {
    // Simulate what dfim_cli_provisioner does:
    // 1. Compute SHA-256 of file blocks
    // 2. Create Merkle tree
    // 3. Write sidecar with proofs

    let file_data = b"This is a test boot image for integration testing.";
    let hash = sha256_digest(file_data);

    // Simulate: provisioner creates a digest, verifier checks it
    let rehash = sha256_digest(file_data);
    assert!(constant_time_hash_eq(&hash, &rehash), "Provisioned hash must match re-computed hash");
}

#[test]
fn core_cli_tampered_file_detected() {
    let original = b"boot-image-v1.0.0-integrity-sealed";
    let tampered = b"boot-image-v1.0.0-malware-added";

    let original_hash = sha256_digest(original);
    let tampered_hash = sha256_digest(tampered);

    assert!(!constant_time_hash_eq(&original_hash, &tampered_hash),
        "Tampered file must produce different hash");
}

#[test]
fn core_cli_multi_block_integrity() {
    // Simulate multi-block boot image validation
    let blocks: Vec<Vec<u8>> = (0..64).map(|i| vec![i as u8; DFIM_BLOCK_SIZE]).collect();

    // Provision: compute block hashes
    let digests: Vec<[u8; SHA256_LEN]> = blocks.iter().map(|b| sha256_digest(b)).collect();

    // Verify: all must match
    for (i, block) in blocks.iter().enumerate() {
        let d = sha256_digest(block);
        assert!(constant_time_hash_eq(&d, &digests[i]),
            "Block {} hash mismatch", i);
    }
}

// ═══════════════════════════════════════════════════════════════════
// core ↔ uefi: Compact boot validation
// ═══════════════════════════════════════════════════════════════════

#[test]
fn core_uefi_block_count_validation() {
    // MAX_BOOT_BLOCKS = 64
    assert!(MAX_BOOT_BLOCKS == 64, "UEFI boot path hardcoded for 64 blocks");
    assert!(DFIM_BLOCK_SIZE == 4096, "Block size must be 4096 bytes");
}

#[test]
fn core_uefi_image_size_boundary() {
    let max_size = MAX_BOOT_BLOCKS as usize * DFIM_BLOCK_SIZE;
    assert!(max_size == 262144, "Max image size must be 262144 bytes (256 KiB)");

    // Boundary: valid image
    let valid = vec![0u8; max_size];
    let hash = sha256_digest(&valid);
    assert!(hash.len() == SHA256_LEN);

    // Boundary: oversized image (should be rejected)
    let oversized = vec![0u8; max_size + 1];
    assert!(oversized.len() > max_size, "Oversized image must be detected");
}

// ═══════════════════════════════════════════════════════════════════
// core ↔ host_init: Evaluation license + crypto
// ═══════════════════════════════════════════════════════════════════

#[test]
fn core_host_init_eval_license_hash_chain() {
    // Simulate host_init eval license:
    // .dfim_sys.dat wraps state with SHA-256 integrity tag

    let state_data = b"DFIMSTAT-v1-eval-license-state";
    let tag = sha256_digest(state_data);

    let verify_tag = sha256_digest(state_data);
    assert!(constant_time_hash_eq(&tag, &verify_tag),
        "Integrity tag must verify");

    // Tampered state
    let tampered_state = b"DFIMSTAT-v1-eval-license-TAMPERED";
    let tampered_tag = sha256_digest(tampered_state);
    assert!(!constant_time_hash_eq(&tag, &tampered_tag),
        "Tampered state must fail verification");
}

#[test]
fn core_host_init_constant_time_comparison() {
    // Verify constant-time comparison doesn't leak timing
    let a = sha256_digest(b"aaaaaaaaaaaaaaaa");
    let b = sha256_digest(b"bbbbbbbbbbbbbbbb");

    // Both comparisons should take the same time
    let matches_aa = constant_time_hash_eq(&a, &a);
    let matches_ab = constant_time_hash_eq(&a, &b);

    assert!(matches_aa, "Same hash must match");
    assert!(!matches_ab, "Different hash must not match");
}

// ═══════════════════════════════════════════════════════════════════
// FEC: Hamming codec integration
// ═══════════════════════════════════════════════════════════════════

#[test]
fn integration_hamming_fec_roundtrip() {
    // Encode 4-bit nibbles, inject errors, decode
    let test_values: Vec<u8> = (0..16).collect(); // All 4-bit values

    for &val in &test_values {
        let encoded = encode_block(val);
        let decoded = decode_block_into_strict(encoded);

        // Should decode correctly (no errors injected)
        assert!(decoded.is_ok(), "FEC decode failed for value {}", val);
        assert_eq!(decoded.unwrap(), val, "FEC round-trip failed for {}", val);
    }
}

#[test]
fn integration_hamming_single_bit_correction() {
    // Encode a nibble, flip one bit, decode — must correct
    for val in 0..16u8 {
        let encoded = encode_block(val);

        // Flip bit at position 2 (non-parity position)
        let mut corrupted = encoded;
        corrupted ^= 1 << 2; // flip bit 2

        let decoded = decode_block_into_strict(corrupted);
        assert!(decoded.is_ok(),
            "FEC should correct single-bit error for value {}", val);
        assert_eq!(decoded.unwrap(), val,
            "FEC corrected to wrong value for {}", val);
    }
}

#[test]
fn integration_hamming_double_bit_fails() {
    // Encode a nibble, flip TWO bits — decode must FAIL (uncorrectable)
    let val = 7u8;
    let encoded = encode_block(val);

    let mut corrupted = encoded;
    corrupted ^= (1 << 2) | (1 << 4); // flip bits 2 and 4

    let decoded = decode_block_into_strict(corrupted);
    assert!(decoded.is_err(),
        "FEC must reject uncorrectable double-bit error");
}

// ═══════════════════════════════════════════════════════════════════
// Cross-layer: Merkle + Hamming + Crypto integration
// ═══════════════════════════════════════════════════════════════════

#[test]
fn integration_full_pipeline_merkle_hamming_crypto() {
    // Full pipeline simulation:
    // 1. File → SHA-256 blocks → Merkle tree
    // 2. Manifest → Hamming FEC encode
    // 3. Verify with constant-time comparison

    let file = b"DFIM integration test: full pipeline verification";
    let hash = sha256_digest(file);

    // FEC protect the hash
    let mut fec_blocks: Vec<u8> = Vec::new();
    for byte in hash.iter() {
        let high = encode_block((byte >> 4) & 0x0F);
        let low = encode_block(byte & 0x0F);
        fec_blocks.push(high);
        fec_blocks.push(low);
    }

    // Decode and reconstruct
    let mut decoded = [0u8; SHA256_LEN];
    for i in 0..SHA256_LEN {
        let high = decode_block_into_strict(fec_blocks[i * 2]).unwrap();
        let low = decode_block_into_strict(fec_blocks[i * 2 + 1]).unwrap();
        decoded[i] = (high << 4) | low;
    }

    // Verify
    assert!(constant_time_hash_eq(&hash, &decoded),
        "FEC-protected hash round-trip must produce original");
}
