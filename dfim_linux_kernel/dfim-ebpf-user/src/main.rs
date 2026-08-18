//! DFIM eBPF user-space loader — attaches LSM probes and provisions `.dfim` sidecars.

mod deny_monitor;
mod ima;
mod maps;
mod siem_sink;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::maps::{Array, HashMap};
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfLoader};
use aya_log::EbpfLogger;
use clap::{Parser, Subcommand};
use dfim_core_engine::{constant_time_hash_eq, DfimError};
use dfim_windows_uefi::{
    build_boot_sidecar, parse_boot_manifest, validate_boot_image, BootManifest,
};
use log::{info, warn};
use maps::{DfimConfigV1, ScopeEntryV1, ScopeKey};
use nix::sys::stat::stat;

use deny_monitor::spawn_deny_monitor;
use siem_sink::{emit_configured, SiemDenyEvent};

#[derive(Parser, Debug)]
#[command(name = "dfim-ebpf-user", about = "DFIM Linux eBPF integrity loader")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Load and verify the eBPF object without attaching LSM hooks (no enforcement).
    Load,
    /// Validate live image + sidecar, populate BPF maps, attach fail-closed LSM probes.
    Provision {
        /// Target ELF binary or kernel module path.
        #[arg(long)]
        target: PathBuf,
        /// Optional explicit `.dfim` sidecar (defaults to `<target>.dfim`).
        #[arg(long)]
        sidecar: Option<PathBuf>,
        /// Monotonic policy generation shared by config and protected-scope entries.
        #[arg(long, default_value_t = 1)]
        policy_generation: u64,
    },
}

fn main() -> Result<()> {
    dfim_host_init::enforce_host_gate();
    env_logger::init();
    match Cli::parse().command {
        Commands::Load => load_program(),
        Commands::Provision {
            target,
            sidecar,
            policy_generation,
        } => provision_target(&target, sidecar.as_deref(), policy_generation),
    }
}

fn load_program() -> Result<()> {
    let mut ebpf = load_ebpf()?;
    init_logger(&mut ebpf)?;
    info!("eBPF object loaded; LSM hooks are not attached until `provision` succeeds");
    wait_for_shutdown();
    Ok(())
}

fn provision_target(target: &Path, sidecar: Option<&Path>, policy_generation: u64) -> Result<()> {
    if policy_generation == 0 {
        anyhow::bail!("policy generation must be non-zero");
    }
    let target = target
        .canonicalize()
        .with_context(|| format!("cannot resolve target {}", target.display()))?;
    let sidecar = sidecar.map(Path::to_path_buf).unwrap_or_else(|| {
        let mut p = target.as_os_str().to_os_string();
        p.push(".dfim");
        PathBuf::from(p)
    });

    let (live_manifest, disk_manifest) = verify_live_image_against_sidecar(&target, &sidecar)?;
    let ima_evidence = ima::require_ima_appraisal()?;
    ima::preflight_target_read(&target)?;

    let st = stat(&target).context("stat target for inode key")?;
    let scope_key = ScopeKey {
        device_id: st.st_dev,
        inode: st.st_ino,
    };

    let mut ebpf = load_ebpf()?;
    init_logger(&mut ebpf)?;
    prepare_scope_entry(
        &mut ebpf,
        scope_key,
        policy_generation,
        live_manifest.merkle_root,
    )?;
    publish_production_config(&mut ebpf, policy_generation)?;
    commit_scope_entry(
        &mut ebpf,
        scope_key,
        policy_generation,
        live_manifest.merkle_root,
    )?;
    attach_lsm_programs(&mut ebpf)?;

    let running = Arc::new(AtomicBool::new(true));
    spawn_deny_monitor(&mut ebpf, running.clone())?;

    info!(
        "provisioned dev={} inode={} generation={} target={} blocks={} sidecar={} disk_root={} live_root={} ima_enforce={}",
        scope_key.device_id,
        scope_key.inode,
        policy_generation,
        target.display(),
        live_manifest.block_count,
        sidecar.display(),
        hex::encode(&disk_manifest.merkle_root),
        hex::encode(&live_manifest.merkle_root),
        ima_evidence.enforce_mode,
    );
    run_until_shutdown(running);
    Ok(())
}

/// Reads target bytes, validates sidecar, and proves live image matches on-disk baseline.
fn verify_live_image_against_sidecar(
    target: &Path,
    sidecar: &Path,
) -> Result<(BootManifest, BootManifest)> {
    let image =
        std::fs::read(target).with_context(|| format!("read target {}", target.display()))?;
    let sidecar_bytes =
        std::fs::read(sidecar).with_context(|| format!("read sidecar {}", sidecar.display()))?;

    let live_sidecar = build_boot_sidecar(&image).map_err(|error| siem_dfim_error(target, error))?;
    let live_manifest = parse_boot_manifest(&live_sidecar).map_err(|error| siem_dfim_error(target, error))?;
    let disk_manifest = parse_boot_manifest(&sidecar_bytes).map_err(|error| siem_dfim_error(target, error))?;

    validate_boot_image(&image, &disk_manifest).map_err(|error| siem_dfim_error(target, error))?;

    if !constant_time_hash_eq(&live_manifest.merkle_root, &disk_manifest.merkle_root) {
        let event = SiemDenyEvent::integrity_mismatch(
            target,
            disk_manifest.merkle_root,
            live_manifest.merkle_root,
        );
        let _ = emit_configured(&event);
        anyhow::bail!(
            "live Merkle root differs from on-disk sidecar — possible post-provision tamper"
        );
    }

    if live_sidecar != sidecar_bytes {
        warn!("sidecar canonical encoding differs from disk file; enforcing live-built manifest");
    }

    let image = std::fs::read(target)
        .with_context(|| format!("re-read target {} before map load", target.display()))?;
    validate_boot_image(&image, &live_manifest).map_err(|error| siem_dfim_error(target, error))?;

    Ok((live_manifest, disk_manifest))
}

fn siem_dfim_error(target: &Path, error: DfimError) -> anyhow::Error {
    let _ = emit_configured(&SiemDenyEvent::from_dfim_error(target, error));
    map_dfim(error)
}

fn publish_production_config(ebpf: &mut Ebpf, policy_generation: u64) -> Result<()> {
    let mut config = Array::<_, DfimConfigV1>::try_from(
        ebpf.map_mut("DFIM_CONFIG")
            .context("DFIM_CONFIG map missing")?,
    )?;
    config.set(0, DfimConfigV1::production(policy_generation), 0)?;
    Ok(())
}

fn attach_lsm_programs(ebpf: &mut Ebpf) -> Result<()> {
    let btf = Btf::from_sys_fs().context("BTF required — enable CONFIG_DEBUG_INFO_BTF=y")?;

    let program: &mut Lsm = ebpf
        .program_mut("bprm_check_security")
        .context("bprm_check_security program missing")?
        .try_into()?;
    program.load("bprm_check_security", &btf)?;
    program.attach()?;

    let program: &mut Lsm = ebpf
        .program_mut("kernel_module_from_file")
        .context("kernel_module_from_file program missing")?
        .try_into()?;
    program.load("kernel_module_from_file", &btf)?;
    program.attach()?;

    info!("DFIM LSM hooks active (fail-closed): bprm_check_security, kernel_module_from_file");
    Ok(())
}

fn prepare_scope_entry(
    ebpf: &mut Ebpf,
    key: ScopeKey,
    policy_generation: u64,
    expected_merkle_root: [u8; 32],
) -> Result<()> {
    let mut scope = HashMap::try_from(
        ebpf.map_mut("DFIM_SCOPE")
            .context("DFIM_SCOPE map missing")?,
    )?;
    scope.insert(
        key,
        ScopeEntryV1::pending(policy_generation, expected_merkle_root),
        0,
    )?;
    Ok(())
}

fn commit_scope_entry(
    ebpf: &mut Ebpf,
    key: ScopeKey,
    policy_generation: u64,
    expected_merkle_root: [u8; 32],
) -> Result<()> {
    let mut scope = HashMap::try_from(
        ebpf.map_mut("DFIM_SCOPE")
            .context("DFIM_SCOPE map missing")?,
    )?;
    scope.insert(
        key,
        ScopeEntryV1::active(policy_generation, expected_merkle_root),
        0,
    )?;
    Ok(())
}

fn load_ebpf() -> Result<Ebpf> {
    EbpfLoader::new()
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/dfim-ebpf"
        )))
        .context("load eBPF object")
}

fn init_logger(ebpf: &mut Ebpf) -> Result<()> {
    if let Err(e) = EbpfLogger::init(ebpf) {
        warn!("eBPF logger init failed: {e}");
    }
    Ok(())
}

fn wait_for_shutdown() {
    run_until_shutdown(Arc::new(AtomicBool::new(true)));
}

fn run_until_shutdown(running: Arc<AtomicBool>) {
    let flag = running.clone();
    let _ = ctrlc::set_handler(move || flag.store(false, Ordering::SeqCst));
    info!("Press Ctrl-C to detach");
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn map_dfim(err: DfimError) -> anyhow::Error {
    anyhow::anyhow!("{}", err.as_str())
}

mod hex {
    pub fn encode(bytes: &[u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
