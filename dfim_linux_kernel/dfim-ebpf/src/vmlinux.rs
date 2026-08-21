//! CO-RE kernel field access — offsets generated from target BTF at build time.

use aya_ebpf::helpers::bpf_probe_read_kernel;
use dfim_core_engine::enforcement_policy::ScopeKey;

include!(concat!(env!("OUT_DIR"), "/vmlinux_offsets.rs"));

/// Read a kernel object field using a compile-time BTF-resolved byte offset.
macro_rules! bpf_core_read_at {
    ($base:expr, $ty:ty, $offset:expr) => {{
        let base = $base as *const u8;
        if base.is_null() {
            None
        } else {
            let src = unsafe { base.add($offset) as *const $ty };
            unsafe { bpf_probe_read_kernel(src).ok() }
        }
    }};
}

pub fn scope_key_from_bprm(bprm: *const u8) -> Option<ScopeKey> {
    let file: *const u8 = bpf_core_read_at!(bprm, *const u8, LINUX_BINPRM_FILE)?;
    scope_key_from_file(file)
}

/// Resolve a filesystem-stable device/inode identity from a `struct file` pointer.
pub fn scope_key_from_file(file: *const u8) -> Option<ScopeKey> {
    let inode: *const u8 = bpf_core_read_at!(file, *const u8, FILE_F_INODE)?;
    if inode.is_null() {
        return None;
    }
    let inode_number = bpf_core_read_at!(inode, u64, INODE_I_INO)?;
    let super_block: *const u8 = bpf_core_read_at!(inode, *const u8, INODE_I_SB)?;
    if super_block.is_null() {
        return None;
    }
    let device_id = bpf_core_read_at!(super_block, u32, SUPER_BLOCK_S_DEV)? as u64;
    Some(ScopeKey {
        device_id,
        inode: inode_number,
    })
}
