//! Linux raw block device access with `O_DIRECT` + `O_SYNC` (NIST SP 800-193 §4.2.3).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use super::{align_up, DIRECT_IO_ALIGN};

const O_DIRECT: i32 = 0o040000;
const O_SYNC: i32 = 0o04000000;

/// Opens a block device for direct I/O with write-through semantics.
fn open_direct(path: &Path, write: bool) -> Result<File, String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    if write {
        opts.write(true);
    }
    let flags = if write { libc::O_RDWR } else { libc::O_RDONLY } | O_DIRECT | O_SYNC;
    opts.custom_flags(flags);
    opts.open(path).map_err(|err| {
        format!(
            "failed to open block device {} with O_DIRECT|O_SYNC: {err}",
            path.display()
        )
    })
}

/// Reads `byte_len` bytes from `path` using sector-aligned direct I/O buffers.
pub fn read_block_device_direct(path: &Path, byte_len: usize) -> Result<Vec<u8>, String> {
    if byte_len == 0 {
        return Err("read length must be non-zero".into());
    }
    let io_len = align_up(byte_len, DIRECT_IO_ALIGN);
    let mut file = open_direct(path, false)?;
    let mut buf = AlignedBuffer::new(io_len, DIRECT_IO_ALIGN)?;
    let read = file
        .read(buf.as_mut_slice())
        .map_err(|err| format!("O_DIRECT read failed on {}: {err}", path.display()))?;
    if read < byte_len {
        return Err(format!(
            "short read on {}: expected {byte_len} bytes, got {read}",
            path.display()
        ));
    }
    Ok(buf.as_slice()[..byte_len].to_vec())
}

/// Writes `payload` to `path` using sector-aligned direct I/O buffers.
pub fn write_block_device_direct(path: &Path, payload: &[u8]) -> Result<(), String> {
    if payload.is_empty() {
        return Err("write payload must be non-empty".into());
    }
    let io_len = align_up(payload.len(), DIRECT_IO_ALIGN);
    let mut file = open_direct(path, true)?;
    let mut buf = AlignedBuffer::new(io_len, DIRECT_IO_ALIGN)?;
    buf.as_mut_slice()[..payload.len()].copy_from_slice(payload);
    file.write_all(buf.as_slice())
        .map_err(|err| format!("O_DIRECT write failed on {}: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("O_SYNC flush failed on {}: {err}", path.display()))?;
    Ok(())
}

/// XORs bit 0 at `byte_offset` via read-modify-write on a single aligned sector.
pub fn flip_bit_at_offset_direct(path: &Path, byte_offset: u64) -> Result<(), String> {
    let sector_start = (byte_offset as usize / DIRECT_IO_ALIGN) * DIRECT_IO_ALIGN;
    let in_sector = (byte_offset as usize) - sector_start;
    let mut file = open_direct(path, true)?;
    let mut buf = AlignedBuffer::new(DIRECT_IO_ALIGN, DIRECT_IO_ALIGN)?;
    file.seek(SeekFrom::Start(sector_start as u64))
        .map_err(|err| format!("seek failed on {}: {err}", path.display()))?;
    file.read_exact(buf.as_mut_slice())
        .map_err(|err| format!("sector read failed on {}: {err}", path.display()))?;
    buf.as_mut_slice()[in_sector] ^= 0x01;
    file.seek(SeekFrom::Start(sector_start as u64))
        .map_err(|err| format!("seek rewind failed on {}: {err}", path.display()))?;
    file.write_all(buf.as_slice())
        .map_err(|err| format!("sector write failed on {}: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("O_SYNC flush failed on {}: {err}", path.display()))?;
    Ok(())
}

/// Page-aligned buffer for `O_DIRECT` transfers.
struct AlignedBuffer {
    layout: std::alloc::Layout,
    ptr: *mut u8,
    len: usize,
}

impl AlignedBuffer {
    fn new(len: usize, align: usize) -> Result<Self, String> {
        let layout = std::alloc::Layout::from_size_align(len, align)
            .map_err(|err| format!("invalid aligned buffer layout: {err}"))?;
        // SAFETY: `alloc` returns null only on OOM; layout enforces alignment for O_DIRECT.
        let ptr = unsafe { std::alloc::alloc(layout) };
        if ptr.is_null() {
            return Err("aligned buffer allocation failed".into());
        }
        Ok(Self { layout, ptr, len })
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr is valid for `len` bytes until dealloc.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: ptr is valid for `len` bytes until dealloc.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: ptr/layout were created together in `new`.
        unsafe { std::alloc::dealloc(self.ptr, self.layout) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_regular_file() -> (std::path::PathBuf, Vec<u8>) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("dfim_direct_{nanos}.bin"));
        let payload = vec![0x4D_u8; DIRECT_IO_ALIGN * 2];
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(&payload).expect("write");
        (path, payload)
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn direct_read_rejects_regular_file_without_o_direct_support() {
        let (path, _payload) = temp_regular_file();
        let result = read_block_device_direct(&path, DIRECT_IO_ALIGN);
        let _ = std::fs::remove_file(&path);
        assert!(
            result.is_err(),
            "regular files typically reject O_DIRECT; got {result:?}"
        );
    }
}
