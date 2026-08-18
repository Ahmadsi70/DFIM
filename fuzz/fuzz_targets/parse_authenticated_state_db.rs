#![no_main]

use dfim_core_engine::parse_authenticated_state_db;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() <= MAX_INPUT_BYTES {
        let _ = parse_authenticated_state_db(data);
    }
});
