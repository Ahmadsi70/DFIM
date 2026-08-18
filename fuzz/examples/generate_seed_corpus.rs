use std::error::Error;
use std::fs;
use std::path::Path;

use dfim_core_engine::wrap_authenticated_state_db;
use dfim_windows_uefi::{build_boot_sidecar, build_rollback_baseline};

const KEY_ID: [u8; 16] = *b"DFIM-ROLLBACK-01";

fn write_seed(target: &str, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let directory = Path::new("corpus").join(target);
    fs::create_dir_all(&directory)?;
    fs::write(directory.join("valid"), bytes)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let image = [0xA5_u8; 4096];
    let sidecar = build_boot_sidecar(&image).map_err(|error| error.as_str().to_string())?;
    let authenticated =
        wrap_authenticated_state_db(&sidecar).map_err(|error| error.as_str().to_string())?;
    let rollback =
        build_rollback_baseline(KEY_ID, 1).map_err(|error| error.as_str().to_string())?;

    write_seed("parse_block_stream", &sidecar)?;
    write_seed("parse_authenticated_state_db", &authenticated)?;
    write_seed("parse_boot_manifest", &sidecar)?;
    write_seed("parse_rollback_baseline", &rollback)?;
    Ok(())
}
