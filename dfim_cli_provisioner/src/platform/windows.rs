//! Windows raw volume I/O stubs — production path uses `FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH`.

use std::path::Path;

const WIN32_DIRECT_IO_MSG: &str = "Windows raw block bypass requires FILE_FLAG_NO_BUFFERING \
    and FILE_FLAG_WRITE_THROUGH; build for Linux (x86_64-unknown-linux-musl) or use the QEMU harness";

/// Stub: Windows direct volume read is routed through the Linux implementation in CI/QEMU.
pub fn read_block_device_direct(path: &Path, _byte_len: usize) -> Result<Vec<u8>, String> {
    Err(format!(
        "{WIN32_DIRECT_IO_MSG} (requested device: {})",
        path.display()
    ))
}

/// Stub: Windows direct volume write is routed through the Linux implementation in CI/QEMU.
pub fn write_block_device_direct(path: &Path, _payload: &[u8]) -> Result<(), String> {
    Err(format!(
        "{WIN32_DIRECT_IO_MSG} (requested device: {})",
        path.display()
    ))
}

/// Stub: Windows bit-flip fault injection for raw volumes.
pub fn flip_bit_at_offset_direct(path: &Path, _byte_offset: u64) -> Result<(), String> {
    Err(format!(
        "{WIN32_DIRECT_IO_MSG} (requested device: {})",
        path.display()
    ))
}
