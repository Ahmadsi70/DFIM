#![no_main]

use dfim_windows_uefi::parse_boot_manifest;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() <= MAX_INPUT_BYTES {
        let _ = parse_boot_manifest(data);
    }
});
