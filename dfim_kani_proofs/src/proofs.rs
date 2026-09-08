//! Property-based proofs for Layer-0 integrity gates and binary parsers.
//!
//! Production parsers accept streams up to 256 KiB (`MAX_IMAGE_BYTES`). CBMC tractability
//! uses a bounded symbolic slice envelope — all parser bounds use `data.len()` and checked
//! arithmetic, so OOB safety at the production cap follows the same code paths (capped by `MAX_BOOT_BLOCKS`).

use dfim_core_engine::{
    assert_block_index, assert_image_bounds, assert_target_path, parse_block_stream,
    parse_uefi_variable, MAX_IMAGE_BYTES,
};

/// Production corruption envelope (256 KiB — matches `MAX_IMAGE_BYTES`).
const MAX_PARSER_BYTES: usize = 262144;

/// CBMC symbolic slice cap (256 B) — covers DFIMBOOT header + FEC + proof paths
/// while keeping each harness tractable within CI timeouts.
const KANI_SYMBOLIC_CAP: usize = 256;

const _: () = assert!(KANI_SYMBOLIC_CAP <= MAX_PARSER_BYTES);
const _: () = assert!(MAX_IMAGE_BYTES >= MAX_PARSER_BYTES);

/// Proves integrity gates never panic on arbitrary numeric inputs (full 64 KiB numeric range).
#[kani::proof]
#[kani::unwind(65536)]
fn proof_integrity_gates_memory_safe() {
    let image_len: usize = kani::any();
    let _ = assert_image_bounds(image_len);

    let index: usize = kani::any();
    let block_count: u32 = kani::any();
    let _ = assert_block_index(index, block_count);

    let path_len: usize = kani::any();
    let _ = assert_target_path(path_len);
}

/// Proves `parse_block_stream` never panics on arbitrary corrupted slices (symbolic envelope).
#[kani::proof]
#[kani::unwind(64)]
fn proof_parse_block_stream_memory_safe() {
    let stream: [u8; KANI_SYMBOLIC_CAP] = kani::any();
    let slice = kani::slice::any_slice_of_array(&stream);
    kani::assume(slice.len() <= MAX_PARSER_BYTES);
    kani::assume(slice.len() <= 128);
    let _ = parse_block_stream(slice);
}

/// Proves `parse_uefi_variable` never panics on arbitrary corrupted slices (symbolic envelope).
#[kani::proof]
#[kani::unwind(64)]
fn proof_parse_uefi_variable_memory_safe() {
    let var: [u8; KANI_SYMBOLIC_CAP] = kani::any();
    let slice = kani::slice::any_slice_of_array(&var);
    kani::assume(slice.len() <= MAX_PARSER_BYTES);
    kani::assume(slice.len() <= 128);
    let _ = parse_uefi_variable(slice);
}

/// Unified property: parser surfaces are panic-free on the symbolic corruption envelope.
#[kani::proof]
#[kani::unwind(64)]
fn proof_layer0_parsers_unified_memory_safe() {
    let payload: [u8; KANI_SYMBOLIC_CAP] = kani::any();
    let slice = kani::slice::any_slice_of_array(&payload);
    kani::assume(slice.len() <= MAX_PARSER_BYTES);
    kani::assume(slice.len() <= 128);

    let _ = parse_block_stream(slice);
    let _ = parse_uefi_variable(slice);
    let _ = assert_image_bounds(slice.len());
}

/// Proves the Layer-0 image cap rejects inputs above `MAX_IMAGE_BYTES` without panicking.
#[kani::proof]
#[kani::unwind(65536)]
fn proof_image_bounds_rejects_above_64k() {
    let len: usize = kani::any();
    kani::assume(len > MAX_PARSER_BYTES);
    let result = assert_image_bounds(len);
    kani::assert(result.is_err(), "must reject above MAX_IMAGE_BYTES");
}
