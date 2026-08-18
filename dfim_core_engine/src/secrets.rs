//! Compile-time string encryption helpers (`lc!` initialized in `lib.rs`).

/// Decrypt a compile-time encrypted literal into a leaked `'static str` (requires `alloc`).
#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn leak_lc(text: alloc::string::String) -> &'static str {
    alloc::boxed::Box::leak(text.into_boxed_str())
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
macro_rules! lc_static {
    ($s:expr) => {{
        $crate::secrets::leak_lc(lc!($s))
    }};
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub(crate) use lc_static;

/// Protocol identifier (encrypted at rest when `hardening` is enabled).
#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn protocol_id() -> &'static str {
    lc_static!("dfim_integrity_protocol_v1")
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn protocol_id() -> &'static str {
    "dfim_integrity_protocol_v1"
}

/// Default salt label bytes for PBKDF2 derivation.
pub fn default_salt_label() -> &'static [u8] {
    #[cfg(all(feature = "hardening", feature = "alloc"))]
    {
        lc_static!("DFIM-INTEGRITY-v1").as_bytes()
    }
    #[cfg(not(all(feature = "hardening", feature = "alloc")))]
    {
        b"DFIM-INTEGRITY-v1"
    }
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn anchors_label() -> &'static str {
    lc_static!("anchors")
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn anchors_label() -> &'static str {
    "anchors"
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn phase_bootmgfw_read() -> &'static str {
    lc_static!("BOOTMGFW_READ")
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn phase_manifest_read() -> &'static str {
    lc_static!("MANIFEST_READ")
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn phase_manifest_parse() -> &'static str {
    lc_static!("MANIFEST_PARSE")
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn phase_integrity_pipeline() -> &'static str {
    lc_static!("INTEGRITY_PIPELINE")
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn phase_load_image() -> &'static str {
    lc_static!("LOAD_IMAGE")
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn phase_start_image() -> &'static str {
    lc_static!("START_IMAGE")
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn log_hw_prefix() -> &'static str {
    lc_static!("[DFIM-HW-LOG] phase=")
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn log_halt_prefix() -> &'static str {
    lc_static!("[DFIM] Boot sequence halted — status=")
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn log_fec_corrected() -> &'static str {
    lc_static!("Hamming FEC corrected manifest bit-rot; blocks=")
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn log_merkle_passed() -> &'static str {
    lc_static!("Merkle O(log N) validation passed; blocks=")
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn log_handoff() -> &'static str {
    lc_static!("Handoff to verified bootmgfw.efi via LoadImage/StartImage")
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn log_gate() -> &'static str {
    lc_static!("DFIM Windows UEFI Boot Guard — Layer-0 integrity gate")
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn phase_bootmgfw_read() -> &'static str {
    "BOOTMGFW_READ"
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn phase_manifest_read() -> &'static str {
    "MANIFEST_READ"
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn phase_manifest_parse() -> &'static str {
    "MANIFEST_PARSE"
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn phase_integrity_pipeline() -> &'static str {
    "INTEGRITY_PIPELINE"
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn phase_load_image() -> &'static str {
    "LOAD_IMAGE"
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn phase_start_image() -> &'static str {
    "START_IMAGE"
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn log_hw_prefix() -> &'static str {
    "[DFIM-HW-LOG] phase="
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn log_halt_prefix() -> &'static str {
    "[DFIM] Boot sequence halted — status="
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn log_fec_corrected() -> &'static str {
    "Hamming FEC corrected manifest bit-rot; blocks="
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn log_merkle_passed() -> &'static str {
    "Merkle O(log N) validation passed; blocks="
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn log_handoff() -> &'static str {
    "Handoff to verified bootmgfw.efi via LoadImage/StartImage"
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn log_gate() -> &'static str {
    "DFIM Windows UEFI Boot Guard — Layer-0 integrity gate"
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn log_dfim_fatal_prefix() -> &'static str {
    "DFIM FATAL phase="
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn log_dfim_fatal_prefix() -> &'static str {
    lc_static!("DFIM FATAL phase=")
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn log_load_image_failed() -> &'static str {
    "LoadImage failed:"
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn log_load_image_failed() -> &'static str {
    lc_static!("LoadImage failed:")
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn log_start_image_failed() -> &'static str {
    "StartImage failed:"
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn log_start_image_failed() -> &'static str {
    lc_static!("StartImage failed:")
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn log_hw_log_line_prefix() -> &'static str {
    "\r\n[DFIM-HW-LOG] phase="
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn log_hw_log_line_prefix() -> &'static str {
    lc_static!("\r\n[DFIM-HW-LOG] phase=")
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn log_hw_log_error_suffix() -> &'static str {
    " error="
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn log_hw_log_error_suffix() -> &'static str {
    lc_static!(" error=")
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn log_halt_line_prefix() -> &'static str {
    "\r\n[DFIM] Boot sequence halted — status="
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn log_halt_line_prefix() -> &'static str {
    lc_static!("\r\n[DFIM] Boot sequence halted — status=")
}

#[cfg(not(all(feature = "hardening", feature = "alloc")))]
pub fn log_halt_line_suffix() -> &'static str {
    "\r\n"
}

#[cfg(all(feature = "hardening", feature = "alloc"))]
pub fn log_halt_line_suffix() -> &'static str {
    lc_static!("\r\n")
}
