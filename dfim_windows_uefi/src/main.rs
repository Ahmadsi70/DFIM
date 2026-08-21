//! DFIM Windows UEFI Boot Guard — Ring-1 firmware interceptor.
//!
//! The `#[entry]` attribute emits the UEFI-required `efi_main` symbol on
//! `x86_64-unknown-uefi`. Obfuscation uses compile-time string encryption only;
//! no external packers or OS-specific user-space constructs.

#![no_main]
#![no_std]

extern crate alloc;

use core::fmt::Write;

use dfim_core_engine::{secrets, DfimError, MAX_IMAGE_BYTES};
use dfim_windows_uefi::{
    effective_minimum_release, parse_rollback_baseline, validate_signed_boot_image_v2,
    TrustedManifestPolicy, ROLLBACK_BASELINE_LEN,
};
use log::{error, info, warn};
use uefi::boot::{self, LoadImageSource};
use uefi::guid;
use uefi::prelude::*;
use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode, FileType};
use uefi::runtime::{self, ResetType, VariableAttributes, VariableVendor};
use uefi::{Handle, Status};

/// Primary Windows boot manager image on the EFI system partition.
const BOOTMGFW_PATH: &uefi::CStr16 = cstr16!("\\EFI\\Microsoft\\Boot\\bootmgfw.efi");

/// DFIM integrity sidecar for the boot manager image.
const BOOTMGFW_MANIFEST_PATH: &uefi::CStr16 = cstr16!("\\EFI\\Microsoft\\Boot\\bootmgfw.efi.dfim");
/// Firmware-authenticated monotonic release floor.
const ROLLBACK_VARIABLE_NAME: &uefi::CStr16 = cstr16!("DFIMMinRelease");
/// DFIM-owned namespace for authenticated UEFI variables.
const DFIM_VARIABLE_VENDOR: VariableVendor =
    VariableVendor(guid!("3f33c545-c9a7-4b1d-89ee-76f1472dfb49"));

mod deployment_trust {
    include!(concat!(env!("OUT_DIR"), "/deployment_trust.rs"));
}

#[global_allocator]
static GLOBAL_ALLOCATOR: uefi::allocator::Allocator = uefi::allocator::Allocator;

/// UEFI application entry (`efi_main` emitted by `#[entry]`).
#[entry]
fn main() -> Status {
    match run_boot_guard() {
        Ok(()) => Status::SUCCESS,
        Err(status) => status,
    }
}

fn run_boot_guard() -> Result<(), Status> {
    if uefi::helpers::init().is_err() {
        return Err(Status::ABORTED);
    }

    let image_handle = boot::image_handle();
    info!("{}", secrets::log_gate());

    let boot_image = match read_volume_file(image_handle, BOOTMGFW_PATH) {
        Ok(bytes) => bytes,
        Err(err) => {
            fatal_halt(secrets::phase_bootmgfw_read(), err);
        }
    };

    let manifest_bytes = match read_volume_file(image_handle, BOOTMGFW_MANIFEST_PATH) {
        Ok(bytes) => bytes,
        Err(err) => {
            fatal_halt(secrets::phase_manifest_read(), err);
        }
    };

    let persisted_floor = match read_authenticated_rollback_floor() {
        Ok(floor) => floor,
        Err(error) => fatal_halt(secrets::phase_manifest_parse(), error),
    };
    let minimum_release =
        match effective_minimum_release(deployment_trust::BOOT_MIN_RELEASE, persisted_floor) {
            Ok(floor) => floor,
            Err(error) => fatal_halt(secrets::phase_manifest_parse(), error),
        };
    let trust_policy = TrustedManifestPolicy {
        public_key_sec1: deployment_trust::BOOT_PUBLIC_KEY,
        expected_key_id: deployment_trust::BOOT_KEY_ID,
        minimum_release,
    };
    let validated = match validate_signed_boot_image_v2(&boot_image, &manifest_bytes, &trust_policy)
    {
        Ok(v) => v,
        Err(err) => {
            fatal_halt(secrets::phase_integrity_pipeline(), err);
        }
    };

    if validated.boot.fec_corrected {
        warn!(
            "{}{}",
            secrets::log_fec_corrected(),
            validated.boot.blocks_verified
        );
    } else {
        info!(
            "{}{}",
            secrets::log_merkle_passed(),
            validated.boot.blocks_verified
        );
    }

    info!("{}", secrets::log_handoff());

    let loaded = match boot::load_image(
        image_handle,
        LoadImageSource::FromBuffer {
            buffer: &validated.boot.payload,
            file_path: None,
        },
    ) {
        Ok(handle) => handle,
        Err(err) => {
            emit_hardware_log(secrets::phase_load_image(), DfimError::IntegrityFailure);
            error!("{} {err:?}", secrets::log_load_image_failed());
            halt_system(Status::LOAD_ERROR);
        }
    };

    match boot::start_image(loaded) {
        Ok(()) => Ok(()),
        Err(err) => {
            emit_hardware_log(secrets::phase_start_image(), DfimError::IntegrityFailure);
            error!("{} {err:?}", secrets::log_start_image_failed());
            let _ = boot::unload_image(loaded);
            halt_system(Status::LOAD_ERROR);
        }
    }
}

/// Reads the monotonic floor only from a firmware time-authenticated variable.
fn read_authenticated_rollback_floor() -> Result<u64, DfimError> {
    let mut payload = [0u8; ROLLBACK_BASELINE_LEN];
    let (data, attributes) =
        runtime::get_variable(ROLLBACK_VARIABLE_NAME, &DFIM_VARIABLE_VENDOR, &mut payload)
            .map_err(|_| DfimError::IntegrityFailure)?;
    let required = VariableAttributes::NON_VOLATILE
        | VariableAttributes::BOOTSERVICE_ACCESS
        | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
    if !attributes.contains(required) {
        return Err(DfimError::IntegrityFailure);
    }
    parse_rollback_baseline(data, &deployment_trust::BOOT_KEY_ID)
}

/// Read an entire file from the same volume as this UEFI image into an allocated buffer.
fn read_volume_file(
    image_handle: Handle,
    path: &uefi::CStr16,
) -> Result<alloc::vec::Vec<u8>, DfimError> {
    let mut fs = boot::get_image_file_system(image_handle)
        .map_err(|_| DfimError::IntegrityFailure)?
        .open_volume()
        .map_err(|_| DfimError::IntegrityFailure)?;

    let file_handle = fs
        .open(path, FileMode::Read, FileAttribute::empty())
        .map_err(|_| DfimError::IntegrityFailure)?;

    match file_handle
        .into_type()
        .map_err(|_| DfimError::IntegrityFailure)?
    {
        FileType::Regular(mut regular) => {
            let mut info_buf = [0u8; 512];
            let info = regular
                .get_info::<FileInfo>(&mut info_buf)
                .map_err(|_| DfimError::IntegrityFailure)?;
            let size = info.file_size();
            if size == 0 {
                return Err(DfimError::EmptyInput);
            }
            let size_usize = usize::try_from(size).map_err(|_| DfimError::ParameterOverflow)?;
            if size_usize > MAX_IMAGE_BYTES {
                return Err(DfimError::BufferTooLong);
            }
            let mut buffer = alloc::vec![0u8; size_usize];
            let read = regular
                .read(&mut buffer)
                .map_err(|_| DfimError::IntegrityFailure)?;
            if read != size_usize {
                return Err(DfimError::BufferTooShort);
            }
            Ok(buffer)
        }
        _ => Err(DfimError::InvalidParameter),
    }
}

/// Emit a hardware-visible log line to the UEFI console and firmware log sink.
fn emit_hardware_log(phase: &str, err: DfimError) {
    error!(
        "{}{phase} code={}",
        secrets::log_dfim_fatal_prefix(),
        err.as_str()
    );
    let _ = uefi::system::with_stdout(|stdout| {
        write!(
            stdout,
            "{}{}{phase}{}{}\r\n",
            secrets::log_hw_log_line_prefix(),
            phase,
            secrets::log_hw_log_error_suffix(),
            err.as_str()
        )
    });
}

/// Halt boot on unrecoverable integrity failure.
fn fatal_halt(phase: &str, err: DfimError) -> ! {
    emit_hardware_log(phase, err);
    halt_system(Status::SECURITY_VIOLATION);
}

/// Cold reset — prevents unverified handoff to the Windows NT boot chain.
fn halt_system(status: Status) -> ! {
    let _ = uefi::system::with_stdout(|stdout| {
        write!(
            stdout,
            "{}{status:?}{}",
            secrets::log_halt_line_prefix(),
            secrets::log_halt_line_suffix()
        )
    });
    boot::stall(core::time::Duration::from_secs(5));
    runtime::reset(ResetType::COLD, status, None);
}
