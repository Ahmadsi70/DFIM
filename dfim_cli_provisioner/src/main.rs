//! DFIM Ring-3 host provisioning CLI — generates `.dfim` boot integrity sidecars.

#[macro_use]
extern crate litcrypt;

use_litcrypt!();

#[cfg(all(feature = "tpm", target_os = "linux"))]
mod tpm;

mod attestation;
mod cli_output;
mod platform;
mod raw_stress;
mod recovery;
mod telemetry_sink;
mod verify;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[cfg(all(feature = "tpm", target_os = "linux"))]
use attestation::encode_attestation_evidence;
use attestation::{
    encode_attestation_challenge, encode_attestation_policy, parse_attestation_challenge,
    parse_attestation_evidence, parse_attestation_policy, verify_attestation, AttestationChallenge,
    AttestationPolicy, ATTESTED_PCR_COUNT,
};
use clap::{Parser, Subcommand};
use dfim_core_engine::{assert_image_bounds, assert_target_path, DfimError};
use dfim_windows_uefi::{
    build_boot_sidecar, build_rollback_baseline, build_signed_boot_sidecar_v2, parse_boot_manifest,
    public_key_sec1_from_private, validate_boot_image, validate_signed_boot_image_v2,
    TrustedManifestPolicy, DFIM_BLOCK_SIZE,
};
use recovery::{recover_target_atomically, RecoveryRequest};
use telemetry_sink::{emit_configured, EventType, Outcome, TelemetryEvent};

use cli_output::{asset_id as cli_asset_id, CommandJsonReport, OutputFormat};
use verify::{verify_or_exit, verify_v2_or_exit, VerifyArgs, VerifyV2Args};

use raw_stress::{run_raw_stress, RawStressArgs};

/// Host-side provisioner for DFIM Windows UEFI Boot Guard sidecar files.
#[derive(Parser, Debug)]
#[command(name = "dfim-provisioner", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Target image path (legacy implicit `provision` mode).
    #[arg(value_name = "TARGET")]
    target: Option<PathBuf>,

    /// Output sidecar path. Defaults to `<target>.dfim` in the same directory.
    #[arg(long, short, requires = "target")]
    output: Option<PathBuf>,

    /// Print Merkle root and block statistics without writing output.
    #[arg(long, requires = "target")]
    dry_run: bool,

    /// Extend verified Merkle root into TPM 2.0 PCR-14 (Linux + `tpm` feature).
    #[arg(long, requires = "target")]
    extend_tpm: bool,

    /// Machine-readable stdout for verify, provision, and recovery (`text` or `json`).
    #[arg(long, global = true, default_value = "text", value_name = "FORMAT")]
    format: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Verify live target integrity against baseline sidecar state (auditor oracle).
    Verify {
        /// Path to the protected firmware / binary image.
        target: PathBuf,

        /// Optional path to baseline sidecar state database (defaults to `<target>.dfim`).
        #[arg(long, value_name = "STATE_DB")]
        state: Option<PathBuf>,
    },
    /// Verify DFIMBOOT v2 signature, rollback floor, and live image integrity.
    VerifyV2 {
        /// Path to the protected firmware / binary image.
        target: PathBuf,
        /// Optional sidecar path; defaults to `<target>.dfim`.
        #[arg(long, value_name = "STATE_DB")]
        state: Option<PathBuf>,
        /// Compressed SEC1 P-256 public key encoded as 66 hexadecimal characters.
        #[arg(long)]
        public_key: String,
        /// Expected 16-byte key ID encoded as 32 hexadecimal characters.
        #[arg(long)]
        key_id: String,
        /// Lowest release counter accepted by this deployment.
        #[arg(long)]
        minimum_release: u64,
    },
    /// Restore a protected image only from an authenticated DFIMBOOT v2 source.
    RecoverV2 {
        /// Protected image to replace.
        target: PathBuf,
        /// Protected sidecar to replace; defaults to `<target>.dfim`.
        #[arg(long)]
        state: Option<PathBuf>,
        /// Authorized recovery image.
        #[arg(long)]
        recovery_image: PathBuf,
        /// Signed DFIMBOOT v2 sidecar for the recovery image.
        #[arg(long)]
        recovery_sidecar: PathBuf,
        /// Compressed SEC1 P-256 public key encoded as 66 hexadecimal characters.
        #[arg(long)]
        public_key: String,
        /// Expected 16-byte key ID encoded as 32 hexadecimal characters.
        #[arg(long)]
        key_id: String,
        /// Lowest release counter accepted by this deployment.
        #[arg(long)]
        minimum_release: u64,
    },
    /// Generate or refresh `.dfim` sidecar state for a target image.
    Provision {
        /// Path to the target bootloader image (e.g. bootmgfw.efi).
        target: PathBuf,

        /// Output sidecar path. Defaults to `<target>.dfim` in the same directory.
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// Print Merkle root and block statistics without writing output.
        #[arg(long)]
        dry_run: bool,

        /// Extend verified Merkle root into TPM 2.0 PCR-14 (Linux + `tpm` feature).
        #[arg(long)]
        extend_tpm: bool,
    },
    /// Generate a signed DFIMBOOT v2 sidecar with anti-rollback metadata.
    ProvisionV2 {
        /// Path to the target bootloader or protected binary.
        target: PathBuf,
        /// Output sidecar path. Defaults to `<target>.dfim`.
        #[arg(long, short)]
        output: Option<PathBuf>,
        /// File containing exactly 32 raw private-key bytes or 64 hexadecimal characters.
        #[arg(long, value_name = "KEY_FILE")]
        signing_key: PathBuf,
        /// Sixteen-byte organizational key ID encoded as 32 hexadecimal characters.
        #[arg(long)]
        key_id: String,
        /// Monotonic release counter; must be greater than zero.
        #[arg(long)]
        release_counter: u64,
        /// Validate and print metadata without writing the sidecar.
        #[arg(long)]
        dry_run: bool,
        /// Extend the verified Merkle root into TPM PCR-14.
        #[arg(long)]
        extend_tpm: bool,
    },
    /// Build the payload for a firmware time-authenticated rollback variable update.
    RollbackPayload {
        /// Expected 16-byte key ID encoded as 32 hexadecimal characters.
        #[arg(long)]
        key_id: String,
        /// New monotonic release floor; must be greater than zero.
        #[arg(long)]
        minimum_release: u64,
        /// Raw payload output; platform tooling must add EFI_VARIABLE_AUTHENTICATION_2.
        #[arg(long, short)]
        output: PathBuf,
    },
    /// Build a verifier-issued, nonce-bound attestation challenge.
    AttestationChallenge {
        /// Cryptographically random 32-byte nonce encoded as 64 hexadecimal characters.
        #[arg(long)]
        nonce: String,
        /// Expected signed release counter.
        #[arg(long)]
        release_counter: u64,
        /// Expected enforcement policy generation.
        #[arg(long)]
        policy_generation: u64,
        /// Expected DFIM Merkle root encoded as 64 hexadecimal characters.
        #[arg(long)]
        merkle_root: String,
        /// Challenge output path.
        #[arg(long, short)]
        output: PathBuf,
    },
    /// Build an enrolled verifier policy from AK and PCR baselines.
    AttestationPolicy {
        /// Compressed SEC1 P-256 AK public key encoded as 66 hexadecimal characters.
        #[arg(long)]
        ak_public_key: String,
        /// Lowest accepted release counter.
        #[arg(long)]
        minimum_release: u64,
        /// Required enforcement policy generation.
        #[arg(long)]
        policy_generation: u64,
        /// Enrolled DFIM Merkle root encoded as 64 hexadecimal characters.
        #[arg(long)]
        merkle_root: String,
        /// Raw concatenated SHA-256 PCR values for PCRs 0,2,4,7,14 (160 bytes).
        #[arg(long)]
        pcr_values: PathBuf,
        /// Policy output path.
        #[arg(long, short)]
        output: PathBuf,
    },
    /// Verify a TPM quote against a challenge and enrolled policy.
    AttestationVerify {
        /// Verifier challenge file.
        #[arg(long)]
        challenge: PathBuf,
        /// Attester evidence file.
        #[arg(long)]
        evidence: PathBuf,
        /// Enrolled verifier policy file.
        #[arg(long)]
        policy: PathBuf,
    },
    /// Create a TPM-resident ECC P-256 attestation key (Linux + `tpm` feature).
    AttestationEnroll {
        /// TPM private-object blob output.
        #[arg(long)]
        private_blob: PathBuf,
        /// TPM public-object blob output.
        #[arg(long)]
        public_blob: PathBuf,
        /// Compressed SEC1 AK public key output.
        #[arg(long)]
        ak_public_key: PathBuf,
    },
    /// Generate nonce-bound TPM quote evidence (Linux + `tpm` feature).
    AttestationQuote {
        /// Verifier challenge file.
        #[arg(long)]
        challenge: PathBuf,
        /// Enrolled TPM private-object blob.
        #[arg(long)]
        private_blob: PathBuf,
        /// Enrolled TPM public-object blob.
        #[arg(long)]
        public_blob: PathBuf,
        /// Evidence output file.
        #[arg(long, short)]
        output: PathBuf,
    },
    /// Raw block-device validation with O_DIRECT cache bypass (Linux / QEMU).
    RawStress {
        /// Raw block device path (e.g. `/dev/vda`).
        #[arg(long)]
        device: PathBuf,

        /// Golden image file written to the device before validation cycles.
        #[arg(long)]
        golden: PathBuf,

        /// Baseline sidecar path (defaults to `<golden>.dfim`).
        #[arg(long, value_name = "STATE_DB")]
        state: Option<PathBuf>,

        /// Number of O_DIRECT verify cycles (default 1000).
        #[arg(long, default_value_t = 1000)]
        cycles: usize,

        /// Inject a single-bit fault at this DFIM block index (fail-closed oracle).
        #[arg(long)]
        inject_sector: Option<u64>,

        /// JSONL compliance report path (host-visible when using virtio-fs).
        #[arg(long, default_value = "dfim_qemu_compliance.jsonl")]
        jsonl_out: PathBuf,
    },
}

fn main() -> ExitCode {
    dfim_host_init::enforce_host_gate();
    let cli = Cli::parse();
    let format = match OutputFormat::parse(&cli.format) {
        Ok(format) => format,
        Err(error) => {
            eprintln!("dfim-provisioner: {error}");
            return ExitCode::FAILURE;
        }
    };

    match cli.command {
        Some(Commands::Verify { target, state }) => {
            verify_or_exit(VerifyArgs {
                target,
                state,
                format,
            });
        }
        Some(Commands::VerifyV2 {
            target,
            state,
            public_key,
            key_id,
            minimum_release,
        }) => {
            let policy = match parse_trusted_policy(&public_key, &key_id, minimum_release) {
                Ok(policy) => policy,
                Err(error) => {
                    if let Err(audit_error) = emit_security_event(
                        &target,
                        EventType::VerifyV2,
                        Outcome::Failure,
                        None,
                        None,
                    ) {
                        eprintln!("[FAIL-CLOSED] verify-v2 audit sink: {audit_error}");
                    }
                    let _ = write_command_json(
                        "verify_v2",
                        &target,
                        format,
                        "failure",
                        None,
                        None,
                        None,
                        false,
                    );
                    eprintln!("dfim-provisioner: invalid v2 trust policy: {error}");
                    return ExitCode::FAILURE;
                }
            };
            verify_v2_or_exit(VerifyV2Args {
                target,
                state,
                policy,
                format,
            });
        }
        Some(Commands::RecoverV2 {
            target,
            state,
            recovery_image,
            recovery_sidecar,
            public_key,
            key_id,
            minimum_release,
        }) => command_recover_v2(
            &target,
            state.as_deref(),
            &recovery_image,
            &recovery_sidecar,
            &public_key,
            &key_id,
            minimum_release,
            format,
        ),
        Some(Commands::Provision {
            target,
            output,
            dry_run,
            extend_tpm,
        }) => match run_provision(&target, output.as_deref(), dry_run, extend_tpm, format) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                let _ = emit_provision_event(
                    &target,
                    EventType::ProvisionV1,
                    Outcome::Failure,
                    None,
                    None,
                    dry_run,
                );
                let _ = write_command_json(
                    "provision_v1",
                    &target,
                    format,
                    "failure",
                    None,
                    None,
                    None,
                    dry_run,
                );
                eprintln!("{}: {err}", lc!("dfim-provisioner"));
                ExitCode::FAILURE
            }
        },
        Some(Commands::RawStress {
            device,
            golden,
            state,
            cycles,
            inject_sector,
            jsonl_out,
        }) => match run_raw_stress(&RawStressArgs {
            device,
            golden,
            state,
            cycles,
            inject_sector,
            jsonl_out,
        }) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("{}: raw-stress {err}", lc!("dfim-provisioner"));
                ExitCode::FAILURE
            }
        },
        Some(Commands::ProvisionV2 {
            target,
            output,
            signing_key,
            key_id,
            release_counter,
            dry_run,
            extend_tpm,
        }) => match run_provision_v2(&ProvisionV2Args {
            target: &target,
            output: output.as_deref(),
            signing_key: &signing_key,
            key_id: &key_id,
            release_counter,
            dry_run,
            extend_tpm,
            format,
        }) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                let _ = emit_provision_event(
                    &target,
                    EventType::ProvisionV2,
                    Outcome::Failure,
                    None,
                    None,
                    dry_run,
                );
                let _ = write_command_json(
                    "provision_v2",
                    &target,
                    format,
                    "failure",
                    None,
                    None,
                    None,
                    dry_run,
                );
                eprintln!("{}: {err}", lc!("dfim-provisioner"));
                ExitCode::FAILURE
            }
        },
        Some(Commands::RollbackPayload {
            key_id,
            minimum_release,
            output,
        }) => match write_rollback_payload(&key_id, minimum_release, &output) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("dfim-provisioner: {error}");
                ExitCode::FAILURE
            }
        },
        Some(Commands::AttestationChallenge {
            nonce,
            release_counter,
            policy_generation,
            merkle_root,
            output,
        }) => command_write_attestation_challenge(
            &nonce,
            release_counter,
            policy_generation,
            &merkle_root,
            &output,
        ),
        Some(Commands::AttestationPolicy {
            ak_public_key,
            minimum_release,
            policy_generation,
            merkle_root,
            pcr_values,
            output,
        }) => command_write_attestation_policy(
            &ak_public_key,
            minimum_release,
            policy_generation,
            &merkle_root,
            &pcr_values,
            &output,
        ),
        Some(Commands::AttestationVerify {
            challenge,
            evidence,
            policy,
        }) => command_verify_attestation(&challenge, &evidence, &policy),
        Some(Commands::AttestationEnroll {
            private_blob,
            public_blob,
            ak_public_key,
        }) => report_attestation_command(run_attestation_enroll(
            &private_blob,
            &public_blob,
            &ak_public_key,
        )),
        Some(Commands::AttestationQuote {
            challenge,
            private_blob,
            public_blob,
            output,
        }) => report_attestation_command(run_attestation_quote(
            &challenge,
            &private_blob,
            &public_blob,
            &output,
        )),
        None => {
            let Some(target) = cli.target else {
                eprintln!("{}: missing subcommand or TARGET", lc!("dfim-provisioner"));
                return ExitCode::FAILURE;
            };
            match run_provision(
                &target,
                cli.output.as_deref(),
                cli.dry_run,
                cli.extend_tpm,
                format,
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    let _ = emit_provision_event(
                        &target,
                        EventType::ProvisionV1,
                        Outcome::Failure,
                        None,
                        None,
                        cli.dry_run,
                    );
                    let _ = write_command_json(
                        "provision_v1",
                        &target,
                        format,
                        "failure",
                        None,
                        None,
                        None,
                        cli.dry_run,
                    );
                    eprintln!("{}: {err}", lc!("dfim-provisioner"));
                    ExitCode::FAILURE
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn command_recover_v2(
    target: &Path,
    state: Option<&Path>,
    recovery_image: &Path,
    recovery_sidecar: &Path,
    public_key: &str,
    key_id: &str,
    minimum_release: u64,
    format: OutputFormat,
) -> ExitCode {
    let policy = match parse_trusted_policy(public_key, key_id, minimum_release) {
        Ok(policy) => policy,
        Err(error) => {
            if let Err(audit_error) =
                emit_security_event(target, EventType::RecoveryV2, Outcome::Failure, None, None)
            {
                eprintln!("[FAIL-CLOSED] recovery audit sink: {audit_error}");
            }
            let _ = write_command_json(
                "recover_v2",
                target,
                format,
                "failure",
                None,
                None,
                None,
                false,
            );
            eprintln!("dfim-provisioner: invalid recovery trust policy: {error}");
            return ExitCode::FAILURE;
        }
    };
    let target_sidecar = state
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_sidecar_path(target));
    match recover_target_atomically(&RecoveryRequest {
        target,
        target_sidecar: &target_sidecar,
        recovery_image,
        recovery_sidecar,
        policy: &policy,
    }) {
        Ok(report) => {
            if let Err(error) = emit_security_event(
                target,
                EventType::RecoveryV2,
                Outcome::Success,
                Some(report.release_counter),
                Some(report.merkle_root),
            ) {
                eprintln!("[FAIL-CLOSED] recovery audit sink: {error}");
                return ExitCode::FAILURE;
            }
            if let Err(error) = write_command_json(
                "recover_v2",
                target,
                format,
                "success",
                Some(report.merkle_root),
                Some(report.release_counter),
                Some(report.restored_bytes),
                false,
            ) {
                eprintln!("[FAIL-CLOSED] recovery json output: {error}");
                return ExitCode::FAILURE;
            }
            if format == OutputFormat::Text {
                eprintln!(
                    "DFIM-RECOVERY: PASS target={} bytes={} release={} key_id={} merkle_root={}",
                    target.display(),
                    report.restored_bytes,
                    report.release_counter,
                    hex_encode(&report.key_id),
                    hex_encode(&report.merkle_root)
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            if let Err(audit_error) =
                emit_security_event(target, EventType::RecoveryV2, Outcome::Failure, None, None)
            {
                eprintln!("[FAIL-CLOSED] recovery audit sink: {audit_error}");
            }
            let _ = write_command_json(
                "recover_v2",
                target,
                format,
                "failure",
                None,
                None,
                None,
                false,
            );
            eprintln!(
                "DFIM-RECOVERY: FAIL target={} error={error}",
                target.display()
            );
            ExitCode::FAILURE
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn write_command_json(
    command: &'static str,
    target: &Path,
    format: OutputFormat,
    outcome: &'static str,
    merkle_root: Option<[u8; 32]>,
    release_counter: Option<u64>,
    bytes: Option<usize>,
    dry_run: bool,
) -> Result<(), String> {
    if format == OutputFormat::Text {
        return Ok(());
    }
    CommandJsonReport {
        command,
        outcome,
        asset_id: cli_asset_id(target),
        merkle_root,
        release_counter,
        blocks: None,
        bytes,
        dry_run,
    }
    .write_stdout()
}

fn emit_provision_event(
    target: &Path,
    event_type: EventType,
    outcome: Outcome,
    release_counter: Option<u64>,
    merkle_root: Option<[u8; 32]>,
    dry_run: bool,
) -> Result<(), String> {
    emit_configured(&TelemetryEvent::provision(
        event_type,
        outcome,
        target,
        release_counter,
        merkle_root,
        dry_run,
    ))
}

fn emit_security_event(
    target: &Path,
    event_type: EventType,
    outcome: Outcome,
    release_counter: Option<u64>,
    merkle_root: Option<[u8; 32]>,
) -> Result<(), String> {
    emit_configured(&TelemetryEvent::security(
        event_type,
        outcome,
        target,
        release_counter,
        merkle_root,
    ))
}

struct ProvisionV2Args<'a> {
    target: &'a Path,
    output: Option<&'a Path>,
    signing_key: &'a Path,
    key_id: &'a str,
    release_counter: u64,
    dry_run: bool,
    extend_tpm: bool,
    format: OutputFormat,
}

fn run_provision_v2(args: &ProvisionV2Args<'_>) -> Result<(), String> {
    run_integrity_gates(args.target)?;
    if args.release_counter == 0 {
        return Err("release counter must be greater than zero".into());
    }

    let target = args
        .target
        .canonicalize()
        .map_err(|error| format!("cannot access target {}: {error}", args.target.display()))?;
    if !target.is_file() {
        return Err(format!(
            "target is not a regular file: {}",
            target.display()
        ));
    }
    let image = std::fs::read(&target)
        .map_err(|error| format!("failed to read {}: {error}", target.display()))?;
    assert_image_bounds(image.len()).map_err(map_dfim_error)?;

    let private_key = read_private_key(args.signing_key)?;
    let key_id = decode_hex_exact::<16>(args.key_id)?;
    let sidecar = build_signed_boot_sidecar_v2(&image, &private_key, key_id, args.release_counter)
        .map_err(map_dfim_error)?;
    let policy = TrustedManifestPolicy {
        public_key_sec1: public_key_sec1_from_private(&private_key).map_err(map_dfim_error)?,
        expected_key_id: key_id,
        minimum_release: args.release_counter,
    };
    let validated =
        validate_signed_boot_image_v2(&image, &sidecar, &policy).map_err(map_dfim_error)?;

    eprintln!(
        "DFIMBOOT v2 provision: target={} bytes={} blocks={} release={} key_id={} merkle_root={}",
        target.display(),
        image.len(),
        validated.boot.blocks_verified,
        validated.release_counter,
        hex_encode(&validated.key_id),
        hex_encode(&validated.boot.merkle_root),
    );

    if args.extend_tpm {
        extend_merkle_to_tpm(&validated.boot.merkle_root)?;
    }
    if args.dry_run {
        eprintln!("dry-run: signed sidecar not written");
        emit_provision_event(
            &target,
            EventType::ProvisionV2,
            Outcome::Success,
            Some(validated.release_counter),
            Some(validated.boot.merkle_root),
            true,
        )?;
        write_command_json(
            "provision_v2",
            &target,
            args.format,
            "success",
            Some(validated.boot.merkle_root),
            Some(validated.release_counter),
            Some(image.len()),
            true,
        )?;
        return Ok(());
    }

    let output = args
        .output
        .map(PathBuf::from)
        .unwrap_or_else(|| default_sidecar_path(&target));
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create output directory {}: {error}",
                    parent.display()
                )
            })?;
        }
    }
    std::fs::write(&output, &sidecar)
        .map_err(|error| format!("failed to write {}: {error}", output.display()))?;
    emit_provision_event(
        &target,
        EventType::ProvisionV2,
        Outcome::Success,
        Some(validated.release_counter),
        Some(validated.boot.merkle_root),
        false,
    )?;
    write_command_json(
        "provision_v2",
        &target,
        args.format,
        "success",
        Some(validated.boot.merkle_root),
        Some(validated.release_counter),
        Some(image.len()),
        false,
    )?;
    if args.format == OutputFormat::Text {
        eprintln!(
            "wrote signed DFIMBOOT v2 sidecar {} ({} bytes)",
            output.display(),
            sidecar.len()
        );
    }
    Ok(())
}

fn read_private_key(path: &Path) -> Result<[u8; 32], String> {
    let raw = std::fs::read(path)
        .map_err(|error| format!("failed to read signing key {}: {error}", path.display()))?;
    if raw.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);
        return Ok(key);
    }
    let text = core::str::from_utf8(&raw)
        .map_err(|_| "signing key must be 32 raw bytes or hexadecimal UTF-8".to_string())?;
    decode_hex_exact::<32>(text.trim())
}

fn parse_trusted_policy(
    public_key: &str,
    key_id: &str,
    minimum_release: u64,
) -> Result<TrustedManifestPolicy, String> {
    if minimum_release == 0 {
        return Err("minimum release must be greater than zero".into());
    }
    let public_key_sec1 = decode_hex_exact::<33>(public_key)?;
    if !matches!(public_key_sec1[0], 0x02 | 0x03) {
        return Err("public key must use compressed SEC1 encoding".into());
    }
    Ok(TrustedManifestPolicy {
        public_key_sec1,
        expected_key_id: decode_hex_exact::<16>(key_id)?,
        minimum_release,
    })
}

fn write_rollback_payload(key_id: &str, minimum_release: u64, output: &Path) -> Result<(), String> {
    let payload = build_rollback_baseline(decode_hex_exact::<16>(key_id)?, minimum_release)
        .map_err(map_dfim_error)?;
    std::fs::write(output, payload)
        .map_err(|error| format!("failed to write {}: {error}", output.display()))?;
    eprintln!(
        "wrote rollback payload {}; sign it as an EFI_VARIABLE_AUTHENTICATION_2 update for DFIMMinRelease",
        output.display()
    );
    Ok(())
}

fn command_write_attestation_challenge(
    nonce: &str,
    release_counter: u64,
    policy_generation: u64,
    merkle_root: &str,
    output: &Path,
) -> ExitCode {
    report_attestation_command(write_attestation_challenge(
        nonce,
        release_counter,
        policy_generation,
        merkle_root,
        output,
    ))
}

fn write_attestation_challenge(
    nonce: &str,
    release_counter: u64,
    policy_generation: u64,
    merkle_root: &str,
    output: &Path,
) -> Result<(), String> {
    if release_counter == 0 || policy_generation == 0 {
        return Err("release counter and policy generation must be positive".into());
    }
    let challenge = AttestationChallenge {
        nonce: decode_hex_exact::<32>(nonce)?,
        release_counter,
        policy_generation,
        merkle_root: decode_hex_exact::<32>(merkle_root)?,
    };
    std::fs::write(output, encode_attestation_challenge(&challenge))
        .map_err(|error| format!("failed to write {}: {error}", output.display()))?;
    eprintln!("wrote attestation challenge {}", output.display());
    Ok(())
}

fn command_write_attestation_policy(
    ak_public_key: &str,
    minimum_release: u64,
    policy_generation: u64,
    merkle_root: &str,
    pcr_values: &Path,
    output: &Path,
) -> ExitCode {
    report_attestation_command(write_attestation_policy(
        ak_public_key,
        minimum_release,
        policy_generation,
        merkle_root,
        pcr_values,
        output,
    ))
}

fn write_attestation_policy(
    ak_public_key: &str,
    minimum_release: u64,
    policy_generation: u64,
    merkle_root: &str,
    pcr_values_path: &Path,
    output: &Path,
) -> Result<(), String> {
    if minimum_release == 0 || policy_generation == 0 {
        return Err("release floor and policy generation must be positive".into());
    }
    let raw_pcrs = read_exact_file::<{ ATTESTED_PCR_COUNT * 32 }>(pcr_values_path)?;
    let mut expected_pcr_values = [[0u8; 32]; ATTESTED_PCR_COUNT];
    for (index, value) in expected_pcr_values.iter_mut().enumerate() {
        let start = index * 32;
        value.copy_from_slice(&raw_pcrs[start..start + 32]);
    }
    let policy = AttestationPolicy {
        ak_public_key_sec1: decode_hex_exact::<33>(ak_public_key)?,
        expected_pcr_values,
        minimum_release,
        expected_policy_generation: policy_generation,
        expected_merkle_root: decode_hex_exact::<32>(merkle_root)?,
    };
    let encoded = encode_attestation_policy(&policy);
    parse_attestation_policy(&encoded)?;
    std::fs::write(output, encoded)
        .map_err(|error| format!("failed to write {}: {error}", output.display()))?;
    eprintln!("wrote attestation policy {}", output.display());
    Ok(())
}

fn command_verify_attestation(challenge: &Path, evidence: &Path, policy: &Path) -> ExitCode {
    let result = (|| {
        let challenge =
            parse_attestation_challenge(&std::fs::read(challenge).map_err(|error| {
                format!("failed to read challenge {}: {error}", challenge.display())
            })?)?;
        let evidence = parse_attestation_evidence(&std::fs::read(evidence).map_err(|error| {
            format!("failed to read evidence {}: {error}", evidence.display())
        })?)?;
        let policy =
            parse_attestation_policy(&std::fs::read(policy).map_err(|error| {
                format!("failed to read policy {}: {error}", policy.display())
            })?)?;
        verify_attestation(&evidence, &challenge, &policy)
    })();
    match result {
        Ok(verified) => {
            eprintln!(
                "[PASS] attestation release={} policy_generation={} merkle_root={}",
                verified.release_counter,
                verified.policy_generation,
                hex_encode(&verified.merkle_root)
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("[FAIL] attestation: {error}");
            ExitCode::FAILURE
        }
    }
}

fn report_attestation_command(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dfim-provisioner: {error}");
            ExitCode::FAILURE
        }
    }
}

fn read_exact_file<const N: usize>(path: &Path) -> Result<[u8; N], String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    if bytes.len() != N {
        return Err(format!("{} must contain exactly {N} bytes", path.display()));
    }
    let mut output = [0u8; N];
    output.copy_from_slice(&bytes);
    Ok(output)
}

#[cfg(all(feature = "tpm", target_os = "linux"))]
fn run_attestation_enroll(
    private_blob_path: &Path,
    public_blob_path: &Path,
    ak_public_key_path: &Path,
) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let enrolled = tpm::create_attestation_key()
        .map_err(|error| format!("TPM AK enrollment failed: {error}"))?;
    let mut private_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(private_blob_path)
        .map_err(|error| {
            format!(
                "failed to create private AK blob {}: {error}",
                private_blob_path.display()
            )
        })?;
    private_file
        .write_all(&enrolled.private_blob)
        .map_err(|error| format!("failed to write private AK blob: {error}"))?;
    std::fs::write(public_blob_path, &enrolled.public_blob).map_err(|error| {
        format!(
            "failed to write public AK blob {}: {error}",
            public_blob_path.display()
        )
    })?;
    std::fs::write(
        ak_public_key_path,
        hex_encode(&enrolled.public_key_sec1).as_bytes(),
    )
    .map_err(|error| {
        format!(
            "failed to write AK enrollment key {}: {error}",
            ak_public_key_path.display()
        )
    })?;
    eprintln!(
        "[PASS] TPM AK enrolled public_key={}",
        hex_encode(&enrolled.public_key_sec1)
    );
    Ok(())
}

#[cfg(not(all(feature = "tpm", target_os = "linux")))]
fn run_attestation_enroll(
    _private_blob_path: &Path,
    _public_blob_path: &Path,
    _ak_public_key_path: &Path,
) -> Result<(), String> {
    Err("attestation-enroll requires Linux compiled with --features tpm".into())
}

#[cfg(all(feature = "tpm", target_os = "linux"))]
fn run_attestation_quote(
    challenge_path: &Path,
    private_blob_path: &Path,
    public_blob_path: &Path,
    output: &Path,
) -> Result<(), String> {
    let challenge = parse_attestation_challenge(
        &std::fs::read(challenge_path)
            .map_err(|error| format!("failed to read {}: {error}", challenge_path.display()))?,
    )?;
    let private_blob = std::fs::read(private_blob_path)
        .map_err(|error| format!("failed to read {}: {error}", private_blob_path.display()))?;
    let public_blob = std::fs::read(public_blob_path)
        .map_err(|error| format!("failed to read {}: {error}", public_blob_path.display()))?;
    let evidence = tpm::quote_attestation(&challenge, &private_blob, &public_blob)
        .map_err(|error| format!("TPM quote failed: {error}"))?;
    let encoded = encode_attestation_evidence(&evidence)?;
    std::fs::write(output, encoded)
        .map_err(|error| format!("failed to write {}: {error}", output.display()))?;
    eprintln!("[PASS] TPM quote evidence written {}", output.display());
    Ok(())
}

#[cfg(not(all(feature = "tpm", target_os = "linux")))]
fn run_attestation_quote(
    _challenge_path: &Path,
    _private_blob_path: &Path,
    _public_blob_path: &Path,
    _output: &Path,
) -> Result<(), String> {
    Err("attestation-quote requires Linux compiled with --features tpm".into())
}

fn run_provision(
    target: &Path,
    output: Option<&Path>,
    dry_run: bool,
    extend_tpm: bool,
    format: OutputFormat,
) -> Result<(), String> {
    run_integrity_gates(target)?;

    let target = target
        .canonicalize()
        .map_err(|e| format!("{} {}: {e}", lc!("cannot access target"), target.display()))?;

    if !target.is_file() {
        return Err(format!(
            "{}: {}",
            lc!("target is not a regular file"),
            target.display()
        ));
    }

    let image = std::fs::read(&target)
        .map_err(|e| format!("{} {}: {e}", lc!("failed to read"), target.display()))?;

    if image.is_empty() {
        return Err(format!(
            "{}: {}",
            lc!("target file is empty"),
            target.display()
        ));
    }

    assert_image_bounds(image.len()).map_err(map_dfim_error)?;

    let sidecar = build_boot_sidecar(&image).map_err(map_dfim_error)?;

    let manifest = parse_boot_manifest(&sidecar).map_err(map_dfim_error)?;
    let validated = validate_boot_image(&image, &manifest).map_err(map_dfim_error)?;

    let block_count = image.len().div_ceil(DFIM_BLOCK_SIZE);
    let root_hex = hex_encode(validated.merkle_root.as_slice());

    eprintln!(
        "{} target={} bytes={} blocks={} block_size={} merkle_root={}",
        lc!("DFIM provision:"),
        target.display(),
        image.len(),
        block_count,
        DFIM_BLOCK_SIZE,
        root_hex,
    );

    if extend_tpm {
        extend_merkle_to_tpm(&validated.merkle_root)?;
    }

    if dry_run {
        eprintln!("{}", lc!("dry-run: sidecar not written"));
        emit_provision_event(
            &target,
            EventType::ProvisionV1,
            Outcome::Success,
            None,
            Some(validated.merkle_root),
            true,
        )?;
        write_command_json(
            "provision_v1",
            &target,
            format,
            "success",
            Some(validated.merkle_root),
            None,
            Some(image.len()),
            true,
        )?;
        return Ok(());
    }

    let output = output
        .map(PathBuf::from)
        .unwrap_or_else(|| default_sidecar_path(&target));

    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "{} {}: {e}",
                    lc!("failed to create output directory"),
                    parent.display()
                )
            })?;
        }
    }

    std::fs::write(&output, &sidecar)
        .map_err(|e| format!("{} {}: {e}", lc!("failed to write"), output.display()))?;

    emit_provision_event(
        &target,
        EventType::ProvisionV1,
        Outcome::Success,
        None,
        Some(validated.merkle_root),
        false,
    )?;
    write_command_json(
        "provision_v1",
        &target,
        format,
        "success",
        Some(validated.merkle_root),
        None,
        Some(image.len()),
        false,
    )?;

    if format == OutputFormat::Text {
        eprintln!(
            "{} {} ({} bytes, {} proofs)",
            lc!("wrote sidecar"),
            output.display(),
            sidecar.len(),
            manifest.proofs.len(),
        );
    }

    Ok(())
}

/// Active Layer-0 integrity gates shared by provision and verify paths.
pub fn run_integrity_gates(target: &Path) -> Result<(), String> {
    assert_target_path(target.as_os_str().len()).map_err(map_dfim_error)
}

fn default_sidecar_path(target: &Path) -> PathBuf {
    let mut out = target.as_os_str().to_os_string();
    out.push(lc!(".dfim"));
    PathBuf::from(out)
}

fn map_dfim_error(err: DfimError) -> String {
    format!("{}: {}", lc!("integrity pipeline error"), err.as_str())
}

/// Routes Merkle root extension to TPM PCR-14 when compiled with the `tpm` feature on Linux.
fn extend_merkle_to_tpm(merkle_root: &[u8; 32]) -> Result<(), String> {
    #[cfg(all(feature = "tpm", target_os = "linux"))]
    {
        tpm::extend_merkle_root_to_hardware_tpm(merkle_root)
            .map_err(|err| format!("{}: {err}", lc!("TPM PCR extend failed")))
    }

    #[cfg(not(all(feature = "tpm", target_os = "linux")))]
    {
        let _ = merkle_root;
        Err(lc!(
            "--extend-tpm requires Linux build compiled with --features tpm"
        ))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_exact<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2 {
        return Err(format!("expected {} hexadecimal characters", N * 2));
    }
    let bytes = text.as_bytes();
    let mut output = [0u8; N];
    for index in 0..N {
        let high = decode_hex_nibble(bytes[index * 2])?;
        let low = decode_hex_nibble(bytes[index * 2 + 1])?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn decode_hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("invalid hexadecimal character".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dfim_windows_uefi::build_boot_sidecar;

    #[test]
    fn provision_round_trip_matches_uefi_parser() {
        let image = vec![0x4D_u8; DFIM_BLOCK_SIZE * 3 + 512];
        let sidecar = build_boot_sidecar(&image).expect("build");
        let manifest = parse_boot_manifest(&sidecar).expect("parse");
        assert_eq!(manifest.block_count as usize, 4);
        validate_boot_image(&image, &manifest).expect("validate");
    }

    #[test]
    fn default_sidecar_path_appends_extension() {
        let p = PathBuf::from(r"C:\EFI\Microsoft\Boot\bootmgfw.efi");
        assert_eq!(
            default_sidecar_path(&p),
            PathBuf::from(r"C:\EFI\Microsoft\Boot\bootmgfw.efi.dfim")
        );
    }

    #[test]
    fn decode_hex_exact_accepts_v2_key_material() {
        let decoded = decode_hex_exact::<16>("00112233445566778899aabbccddeeff").expect("decode");
        assert_eq!(decoded[0], 0x00);
        assert_eq!(decoded[15], 0xff);
    }

    #[test]
    fn decode_hex_exact_rejects_wrong_length_and_non_hex() {
        assert!(decode_hex_exact::<16>("00").is_err());
        assert!(decode_hex_exact::<16>("zz112233445566778899aabbccddeeff").is_err());
    }
}
