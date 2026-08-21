#![no_main]

use dfim_windows_uefi::parse_rollback_baseline;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64;
const EXPECTED_KEY_ID: [u8; 16] = *b"DFIM-ROLLBACK-01";

fuzz_target!(|data: &[u8]| {
    if data.len() <= MAX_INPUT_BYTES {
        let _ = parse_rollback_baseline(data, &EXPECTED_KEY_ID);
    }
});
