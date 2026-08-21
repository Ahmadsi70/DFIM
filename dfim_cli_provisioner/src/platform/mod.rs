//! Platform-specific raw block I/O and cache-bypass primitives (NIST SP 800-193 §4.2.3).

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// Logical sector size required for direct I/O buffer alignment on Linux block devices.
#[cfg(any(unix, test))]
pub const DIRECT_IO_ALIGN: usize = 4096;

/// Returns the byte offset for a DFIM block index using the engine block size.
pub fn block_byte_offset(block_index: u64, block_size: usize) -> u64 {
    block_index.saturating_mul(block_size as u64)
}

/// Rounds `value` up to the next multiple of `align` (align must be > 0).
#[cfg(any(unix, test))]
pub fn align_up(value: usize, align: usize) -> usize {
    debug_assert!(align > 0);
    value.div_ceil(align) * align
}

/// Reads `byte_len` bytes from a raw block device using OS-specific cache bypass.
pub fn read_block_device(path: &std::path::Path, byte_len: usize) -> Result<Vec<u8>, String> {
    #[cfg(unix)]
    {
        unix::read_block_device_direct(path, byte_len)
    }
    #[cfg(windows)]
    {
        windows::read_block_device_direct(path, byte_len)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, byte_len);
        Err("raw block device I/O is unsupported on this target".into())
    }
}

/// Writes `payload` to a raw block device using OS-specific cache bypass.
pub fn write_block_device(path: &std::path::Path, payload: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        unix::write_block_device_direct(path, payload)
    }
    #[cfg(windows)]
    {
        windows::write_block_device_direct(path, payload)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, payload);
        Err("raw block device I/O is unsupported on this target".into())
    }
}

/// Flips one bit at `byte_offset` on a raw block device (adversarial fault injection).
pub fn flip_bit_at_offset(path: &std::path::Path, byte_offset: u64) -> Result<(), String> {
    #[cfg(unix)]
    {
        unix::flip_bit_at_offset_direct(path, byte_offset)
    }
    #[cfg(windows)]
    {
        windows::flip_bit_at_offset_direct(path, byte_offset)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, byte_offset);
        Err("raw block device I/O is unsupported on this target".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_byte_offset_scales_by_block_size() {
        assert_eq!(block_byte_offset(512, 4096), 512 * 4096);
    }

    #[test]
    fn align_up_rounds_to_alignment_boundary() {
        assert_eq!(align_up(1, DIRECT_IO_ALIGN), DIRECT_IO_ALIGN);
        assert_eq!(align_up(DIRECT_IO_ALIGN, DIRECT_IO_ALIGN), DIRECT_IO_ALIGN);
        assert_eq!(
            align_up(DIRECT_IO_ALIGN + 1, DIRECT_IO_ALIGN),
            DIRECT_IO_ALIGN * 2
        );
    }

    #[test]
    fn direct_io_align_matches_dfim_block_size() {
        assert_eq!(DIRECT_IO_ALIGN, 4096);
        assert_eq!(DIRECT_IO_ALIGN, dfim_windows_uefi::DFIM_BLOCK_SIZE);
    }
}
