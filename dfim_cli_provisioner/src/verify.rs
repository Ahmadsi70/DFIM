//! Strict integrity verification against a persisted sidecar state database.

use std::path::{Path, PathBuf};
use std::vec::Vec;

use dfim_core_engine::{assert_image_bounds, constant_time_hash_eq, parse_authenticated_state_db};
use dfim_windows_uefi::{
    build_boot_sidecar, parse_boot_manifest, validate_boot_image, validate_signed_boot_image_v2,
    TrustedManifestPolicy, DFIM_BLOCK_SIZE,
};

use crate::cli_output::{asset_id as cli_asset_id, CommandJsonReport, OutputFormat};
use crate::telemetry_sink::{emit_configured, EventType, Outcome, TelemetryEvent};
use crate::{default_sidecar_path, hex_encode, map_dfim_error, run_integrity_gates};

/// Arguments for the enterprise `verify` subcommand oracle.
#[derive(Debug, Clone)]
pub struct VerifyArgs {
    pub target: PathBuf,
    pub state: Option<PathBuf>,
    pub format: OutputFormat,
}

/// Arguments for signature-aware DFIMBOOT v2 verification.
#[derive(Debug, Clone)]
pub struct VerifyV2Args {
    pub target: PathBuf,
    pub state: Option<PathBuf>,
    pub policy: TrustedManifestPolicy,
    pub format: OutputFormat,
}

/// Outcome of a successful verification pass (live telemetry for auditors).
#[derive(Debug, Clone, Copy)]
pub struct VerifyReport {
    pub merkle_root: [u8; 32],
    pub block_count: usize,
}

/// Verify target image integrity against baseline sidecar state; exits process on result.
pub fn verify_or_exit(args: VerifyArgs) -> ! {
    match verify_target(&args) {
        Ok(report) => {
            if let Err(error) = emit_verify_event(
                &args.target,
                EventType::VerifyV1,
                Outcome::Success,
                Some(report.merkle_root),
            ) {
                eprintln!("[FAIL-CLOSED] verify audit sink: {error}");
                std::process::exit(1);
            }
            if let Err(error) = write_verify_json(
                "verify_v1",
                &args.target,
                args.format,
                "success",
                Some(report),
            ) {
                eprintln!("[FAIL-CLOSED] verify json output: {error}");
                std::process::exit(1);
            }
            if args.format == OutputFormat::Text {
                eprintln!(
                    "[PASS] verify target={} blocks={} merkle_root={}",
                    args.target.display(),
                    report.block_count,
                    hex_encode(&report.merkle_root)
                );
            }
            std::process::exit(0);
        }
        Err(reason) => {
            if let Err(error) =
                emit_verify_event(&args.target, EventType::VerifyV1, Outcome::Failure, None)
            {
                eprintln!("[FAIL-CLOSED] verify audit sink: {error}");
            }
            let _ = write_verify_json("verify_v1", &args.target, args.format, "failure", None);
            eprintln!("[FAIL] verify: {reason}");
            std::process::exit(1);
        }
    }
}

/// Runs the v2 trust oracle and exits with a machine-usable status.
pub fn verify_v2_or_exit(args: VerifyV2Args) -> ! {
    match verify_v2_target(&args) {
        Ok(report) => {
            if let Err(error) = emit_verify_event(
                &args.target,
                EventType::VerifyV2,
                Outcome::Success,
                Some(report.merkle_root),
            ) {
                eprintln!("[FAIL-CLOSED] verify-v2 audit sink: {error}");
                std::process::exit(1);
            }
            if let Err(error) = write_verify_json(
                "verify_v2",
                &args.target,
                args.format,
                "success",
                Some(report),
            ) {
                eprintln!("[FAIL-CLOSED] verify-v2 json output: {error}");
                std::process::exit(1);
            }
            if args.format == OutputFormat::Text {
                eprintln!(
                    "[PASS] verify-v2 target={} blocks={} merkle_root={}",
                    args.target.display(),
                    report.block_count,
                    hex_encode(&report.merkle_root)
                );
            }
            std::process::exit(0);
        }
        Err(reason) => {
            if let Err(error) =
                emit_verify_event(&args.target, EventType::VerifyV2, Outcome::Failure, None)
            {
                eprintln!("[FAIL-CLOSED] verify-v2 audit sink: {error}");
            }
            let _ = write_verify_json("verify_v2", &args.target, args.format, "failure", None);
            eprintln!("[FAIL] verify-v2: {reason}");
            std::process::exit(1);
        }
    }
}

fn write_verify_json(
    command: &'static str,
    target: &Path,
    format: OutputFormat,
    outcome: &'static str,
    report: Option<VerifyReport>,
) -> Result<(), String> {
    if format == OutputFormat::Text {
        return Ok(());
    }
    let (blocks, merkle_root) = match report {
        Some(report) => (Some(report.block_count), Some(report.merkle_root)),
        None => (None, None),
    };
    CommandJsonReport {
        command,
        outcome,
        asset_id: cli_asset_id(target),
        merkle_root,
        release_counter: None,
        blocks,
        bytes: None,
        dry_run: false,
    }
    .write_stdout()
}

fn emit_verify_event(
    target: &Path,
    event_type: EventType,
    outcome: Outcome,
    merkle_root: Option<[u8; 32]>,
) -> Result<(), String> {
    emit_configured(&TelemetryEvent::security(
        event_type,
        outcome,
        target,
        None,
        merkle_root,
    ))
}

/// Core verification pipeline — returns Err on tamper, corrupt state, or I/O faults.
pub fn verify_target(args: &VerifyArgs) -> Result<VerifyReport, String> {
    run_integrity_gates(&args.target)?;

    let target = canonical_target_file(&args.target)?;
    let state_path = args
        .state
        .clone()
        .unwrap_or_else(|| default_sidecar_path(&target));

    let image = read_non_empty_file(&target, "target")?;
    verify_image_bytes_against_state(&image, &state_path)
}

/// Verifies persisted v2 state against the configured trust anchor and release floor.
pub fn verify_v2_target(args: &VerifyV2Args) -> Result<VerifyReport, String> {
    run_integrity_gates(&args.target)?;
    let target = canonical_target_file(&args.target)?;
    let state_path = args
        .state
        .clone()
        .unwrap_or_else(|| default_sidecar_path(&target));
    let image = read_non_empty_file(&target, "target")?;
    let state_raw = read_non_empty_file(&state_path, "state database")?;
    // DFIMBOOT v2 sidecars carry their own signature, key-ID, and release floor;
    // they are consumed directly by the v2 verifier, not by the v1 state parser.
    let sidecar = validate_v2_sidecar_envelope(&state_raw, &state_path)?;
    verify_v2_image_bytes(&image, &sidecar, &args.policy)
}

/// Lightweight v2 envelope check that rejects plaintext injections without
/// imposing the v1 boot-sidecar header rules (`BOOT_SIDECAR_VERSION == 1`).
fn validate_v2_sidecar_envelope(state_raw: &[u8], state_path: &Path) -> Result<Vec<u8>, String> {
    if state_raw.is_empty() {
        return Err(format!("state database {} is empty", state_path.display()));
    }
    if state_raw.starts_with(b"STATE_") || state_raw.starts_with(b"STATE_HASH") {
        return Err(format!(
            "invalid authenticated v2 state ({}): plaintext state injection rejected",
            state_path.display()
        ));
    }
    if state_raw.len() == 16 {
        return Err(format!(
            "invalid authenticated v2 state ({}): legacy license blob rejected",
            state_path.display()
        ));
    }
    Ok(state_raw.to_vec())
}

/// Verifies in-memory DFIMBOOT v2 authenticity, rollback state, and image integrity.
pub fn verify_v2_image_bytes(
    image: &[u8],
    sidecar: &[u8],
    policy: &TrustedManifestPolicy,
) -> Result<VerifyReport, String> {
    if image.is_empty() {
        return Err("target image is empty".into());
    }
    assert_image_bounds(image.len()).map_err(map_dfim_error)?;
    let validated = validate_signed_boot_image_v2(image, sidecar, policy)
        .map_err(|error| format!("v2 trust validation failed: {}", map_dfim_error(error)))?;
    Ok(VerifyReport {
        merkle_root: validated.boot.merkle_root,
        block_count: validated.boot.blocks_verified as usize,
    })
}

/// Verifies an in-memory image against a persisted sidecar state database.
pub fn verify_image_bytes_against_state(
    image: &[u8],
    state_path: &Path,
) -> Result<VerifyReport, String> {
    if image.is_empty() {
        return Err("target image is empty".into());
    }
    assert_image_bounds(image.len()).map_err(map_dfim_error)?;

    let state_raw = read_non_empty_file(state_path, "state database")?;
    let sidecar = parse_authenticated_state_db(&state_raw).map_err(|err| {
        format!(
            "invalid or plaintext state database ({}): {} — expected DFIMBOOT sidecar or DFIMSTAT authenticated envelope",
            state_path.display(),
            map_dfim_error(err)
        )
    })?;

    let baseline = parse_boot_manifest(&sidecar).map_err(|err| {
        format!(
            "corrupt sidecar metadata ({}): {}",
            state_path.display(),
            map_dfim_error(err)
        )
    })?;

    let live_root = compute_live_merkle_root(image)?;

    let validated = validate_boot_image(image, &baseline).map_err(|err| {
        format!(
            "sidecar replay or block-level tamper detected: {}",
            map_dfim_error(err)
        )
    })?;

    if !constant_time_hash_eq(&live_root, &validated.merkle_root) {
        return Err(format!(
            "integrity violation: live Merkle root differs from baseline (possible bit-flip) live={} expected={}",
            hex_encode(&live_root),
            hex_encode(&validated.merkle_root)
        ));
    }

    Ok(VerifyReport {
        merkle_root: validated.merkle_root,
        block_count: image.len().div_ceil(DFIM_BLOCK_SIZE),
    })
}

fn canonical_target_file(path: &Path) -> Result<PathBuf, String> {
    path.canonicalize()
        .map_err(|err| format!("cannot access target {}: {err}", path.display()))
        .and_then(|p| {
            if p.is_file() {
                Ok(p)
            } else {
                Err(format!("target is not a regular file: {}", p.display()))
            }
        })
}

fn read_non_empty_file(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path)
        .map_err(|err| format!("failed to read {label} {}: {err}", path.display()))?;
    if bytes.is_empty() {
        return Err(format!("{label} file is empty: {}", path.display()));
    }
    Ok(bytes)
}

fn compute_live_merkle_root(image: &[u8]) -> Result<[u8; 32], String> {
    let sidecar = build_boot_sidecar(image).map_err(map_dfim_error)?;
    let manifest = parse_boot_manifest(&sidecar).map_err(map_dfim_error)?;
    Ok(manifest.merkle_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dfim_windows_uefi::DFIM_BLOCK_SIZE;
    use dfim_windows_uefi::{
        build_boot_sidecar, build_signed_boot_sidecar_v2, public_key_sec1_from_private,
    };
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("dfim_verify_{label}_{nanos}"));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn verify_passes_for_matching_sidecar() {
        let dir = temp_dir("ok");
        let target = dir.join("image.bin");
        let image = vec![0x4D_u8; DFIM_BLOCK_SIZE * 2 + 100];
        fs::write(&target, &image).expect("write image");
        fs::write(
            default_sidecar_path(&target),
            build_boot_sidecar(&image).expect("sidecar"),
        )
        .expect("write sidecar");

        let report = verify_target(&VerifyArgs {
            target: target.clone(),
            state: None,
            format: OutputFormat::Text,
        })
        .expect("verify");
        assert_eq!(report.block_count, 3);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_rejects_tampered_image() {
        let dir = temp_dir("bad");
        let target = dir.join("image.bin");
        let image = vec![0x4D_u8; DFIM_BLOCK_SIZE + 64];
        fs::write(&target, &image).expect("write image");
        fs::write(
            default_sidecar_path(&target),
            build_boot_sidecar(&image).expect("sidecar"),
        )
        .expect("write sidecar");

        let mut tampered = image;
        tampered[0] ^= 0x01;
        fs::write(&target, &tampered).expect("tamper");

        assert!(verify_target(&VerifyArgs {
            target,
            state: None,
            format: OutputFormat::Text,
        })
        .is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_rejects_plaintext_state_injection() {
        let dir = temp_dir("plain");
        let target = dir.join("image.bin");
        let image = vec![0x4D_u8; DFIM_BLOCK_SIZE + 64];
        fs::write(&target, &image).expect("write image");
        fs::write(
            default_sidecar_path(&target),
            build_boot_sidecar(&image).expect("sidecar"),
        )
        .expect("write sidecar");

        let bogus_state = dir.join("bogus.dat");
        fs::write(&bogus_state, b"STATE_HASH_CLOCK_VALID_A").expect("write bogus");

        assert!(verify_target(&VerifyArgs {
            target,
            state: Some(bogus_state),
            format: OutputFormat::Text,
        })
        .is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_rejects_license_blob_as_state_db() {
        let dir = temp_dir("lic");
        let target = dir.join("image.bin");
        let image = vec![0x4D_u8; DFIM_BLOCK_SIZE + 64];
        fs::write(&target, &image).expect("write image");
        fs::write(
            default_sidecar_path(&target),
            build_boot_sidecar(&image).expect("sidecar"),
        )
        .expect("write sidecar");

        let bogus_state = dir.join("license.dat");
        fs::write(&bogus_state, [0u8; 16]).expect("write legacy license blob");

        assert!(verify_target(&VerifyArgs {
            target,
            state: Some(bogus_state),
            format: OutputFormat::Text,
        })
        .is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_v2_enforces_signature_and_release_floor() {
        const PRIVATE_KEY: [u8; 32] = [0x22; 32];
        const KEY_ID: [u8; 16] = *b"DFIM-VERIFY-V2!!";
        let image = vec![0x4D_u8; DFIM_BLOCK_SIZE * 2];
        let sidecar =
            build_signed_boot_sidecar_v2(&image, &PRIVATE_KEY, KEY_ID, 9).expect("sidecar");
        let policy = TrustedManifestPolicy {
            public_key_sec1: public_key_sec1_from_private(&PRIVATE_KEY).expect("public key"),
            expected_key_id: KEY_ID,
            minimum_release: 9,
        };

        assert!(verify_v2_image_bytes(&image, &sidecar, &policy).is_ok());
        let rollback_policy = TrustedManifestPolicy {
            minimum_release: 10,
            ..policy
        };
        assert!(verify_v2_image_bytes(&image, &sidecar, &rollback_policy).is_err());
    }

    #[test]
    fn verify_v2_target_accepts_provision_v2_sidecar() {
        // Regression: verify-v2 previously routed the v2 sidecar through the v1
        // state parser (validate_boot_sidecar_header expects version 1), which
        // rejected every provision-v2 output with InvalidParameter. The CLI pair
        // must round-trip on the persisted path.
        const PRIVATE_KEY: [u8; 32] = [0x42; 32];
        const KEY_ID: [u8; 16] = *b"0123456789ABCDEF";
        let dir = temp_dir("v2cli");
        let target = dir.join("release.bin");
        let image = vec![0x5A_u8; DFIM_BLOCK_SIZE * 2];
        fs::write(&target, &image).expect("write image");
        fs::write(
            default_sidecar_path(&target),
            build_signed_boot_sidecar_v2(&image, &PRIVATE_KEY, KEY_ID, 9).expect("v2 sidecar"),
        )
        .expect("write v2 sidecar");

        let policy = TrustedManifestPolicy {
            public_key_sec1: public_key_sec1_from_private(&PRIVATE_KEY).expect("public key"),
            expected_key_id: KEY_ID,
            minimum_release: 9,
        };
        let report = verify_v2_target(&VerifyV2Args {
            target: target.clone(),
            state: None,
            policy,
            format: OutputFormat::Text,
        })
        .expect("verify-v2 must accept its own provision-v2 sidecar");
        assert_eq!(report.block_count, 2);

        // A tampered image must still be denied through the same path.
        let mut tampered = image;
        tampered[0] ^= 0x01;
        fs::write(&target, &tampered).expect("tamper");
        assert!(verify_v2_target(&VerifyV2Args {
            target,
            state: None,
            policy,
            format: OutputFormat::Text,
        })
        .is_err());
        let _ = fs::remove_dir_all(dir);
    }
}
