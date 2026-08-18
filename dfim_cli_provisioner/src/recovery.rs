//! Authenticated, fail-closed recovery for DFIMBOOT v2 protected files.

#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use dfim_windows_uefi::{validate_signed_boot_image_v2, TrustedManifestPolicy, V2_KEY_ID_LEN};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Paths and trust policy required for an authorized recovery operation.
pub struct RecoveryRequest<'a> {
    pub target: &'a Path,
    pub target_sidecar: &'a Path,
    pub recovery_image: &'a Path,
    pub recovery_sidecar: &'a Path,
    pub policy: &'a TrustedManifestPolicy,
}

/// Audit fields emitted only after the restored pair passes verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryReport {
    pub release_counter: u64,
    pub key_id: [u8; V2_KEY_ID_LEN],
    pub restored_bytes: usize,
    pub merkle_root: [u8; 32],
}

/// Restores a pre-authenticated image/sidecar pair with durable per-file replacement.
pub fn recover_target_atomically(request: &RecoveryRequest<'_>) -> Result<RecoveryReport, String> {
    let recovery_image = read_non_empty(request.recovery_image, "recovery image")?;
    let recovery_sidecar = read_non_empty(request.recovery_sidecar, "recovery sidecar")?;
    let prevalidated =
        validate_signed_boot_image_v2(&recovery_image, &recovery_sidecar, request.policy)
            .map_err(|error| format!("recovery authorization failed: {}", error.as_str()))?;

    atomic_replace(request.target_sidecar, &recovery_sidecar)?;
    atomic_replace(request.target, &recovery_image)?;

    let restored_image = read_non_empty(request.target, "restored image")?;
    let restored_sidecar = read_non_empty(request.target_sidecar, "restored sidecar")?;
    let postvalidated =
        validate_signed_boot_image_v2(&restored_image, &restored_sidecar, request.policy)
            .map_err(|error| format!("post-recovery verification failed: {}", error.as_str()))?;
    if prevalidated.release_counter != postvalidated.release_counter
        || prevalidated.key_id != postvalidated.key_id
        || prevalidated.boot.merkle_root != postvalidated.boot.merkle_root
    {
        return Err("post-recovery identity differs from authorized source".into());
    }

    Ok(RecoveryReport {
        release_counter: postvalidated.release_counter,
        key_id: postvalidated.key_id,
        restored_bytes: restored_image.len(),
        merkle_root: postvalidated.boot.merkle_root,
    })
}

fn read_non_empty(path: &Path, label: &str) -> Result<Vec<u8>, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("failed to read {label} {}: {error}", path.display()))?;
    if bytes.is_empty() {
        return Err(format!("{label} is empty: {}", path.display()));
    }
    Ok(bytes)
}

fn atomic_replace(target: &Path, payload: &[u8]) -> Result<(), String> {
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| format!("target has no parent directory: {}", target.display()))?;
    let name = target
        .file_name()
        .ok_or_else(|| format!("target has no file name: {}", target.display()))?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{}.dfim-recovery-{}-{sequence}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let result = write_and_replace(&temporary, target, payload);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_and_replace(temporary: &Path, target: &Path, payload: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temporary)
        .map_err(|error| format!("failed to create {}: {error}", temporary.display()))?;
    file.write_all(payload)
        .map_err(|error| format!("failed to write {}: {error}", temporary.display()))?;
    if let Ok(metadata) = fs::metadata(target) {
        file.set_permissions(metadata.permissions())
            .map_err(|error| format!("failed to preserve target permissions: {error}"))?;
    }
    file.sync_all()
        .map_err(|error| format!("failed to sync {}: {error}", temporary.display()))?;
    drop(file);

    fs::rename(temporary, target).map_err(|error| {
        format!(
            "failed to atomically replace {} with {}: {error}",
            target.display(),
            temporary.display()
        )
    })?;
    OpenOptions::new()
        .write(true)
        .open(target)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            format!(
                "failed to sync restored target {}: {error}",
                target.display()
            )
        })?;
    sync_parent_directory(target)
}

#[cfg(unix)]
fn sync_parent_directory(target: &Path) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| format!("target has no parent directory: {}", target.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("failed to sync directory {}: {error}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent_directory(_target: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dfim_windows_uefi::{
        build_signed_boot_sidecar_v2, public_key_sec1_from_private, TrustedManifestPolicy,
        DFIM_BLOCK_SIZE,
    };
    use std::fmt::Debug;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    const PRIVATE_KEY: [u8; 32] = [0x66; 32];
    const KEY_ID: [u8; 16] = *b"DFIM-RECOVERY-01";

    fn must<T, E: Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("recovery fixture failed: {error:?}"),
        }
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let nanos = must(SystemTime::now().duration_since(UNIX_EPOCH)).as_nanos();
        let path = std::env::temp_dir().join(format!("dfim_recovery_{label}_{nanos}"));
        must(fs::create_dir_all(&path));
        path
    }

    fn policy(minimum_release: u64) -> TrustedManifestPolicy {
        TrustedManifestPolicy {
            public_key_sec1: must(public_key_sec1_from_private(&PRIVATE_KEY)),
            expected_key_id: KEY_ID,
            minimum_release,
        }
    }

    #[test]
    fn recovery_replaces_image_and_sidecar_then_reverifies() {
        let dir = temp_dir("success");
        let target = dir.join("protected.bin");
        let target_sidecar = dir.join("protected.bin.dfim");
        let source = dir.join("authorized.bin");
        let source_sidecar = dir.join("authorized.bin.dfim");
        let authorized = vec![0xA5; DFIM_BLOCK_SIZE * 2];
        let sidecar = must(build_signed_boot_sidecar_v2(
            &authorized,
            &PRIVATE_KEY,
            KEY_ID,
            11,
        ));
        must(fs::write(&target, vec![0xCC; authorized.len()]));
        must(fs::write(&target_sidecar, b"corrupt"));
        must(fs::write(&source, &authorized));
        must(fs::write(&source_sidecar, &sidecar));

        let report = must(recover_target_atomically(&RecoveryRequest {
            target: &target,
            target_sidecar: &target_sidecar,
            recovery_image: &source,
            recovery_sidecar: &source_sidecar,
            policy: &policy(10),
        }));

        assert_eq!(report.release_counter, 11);
        assert_eq!(must(fs::read(&target)), authorized);
        assert_eq!(must(fs::read(&target_sidecar)), sidecar);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn recovery_rejects_rollback_without_touching_target() {
        let dir = temp_dir("rollback");
        let target = dir.join("protected.bin");
        let target_sidecar = dir.join("protected.bin.dfim");
        let source = dir.join("old.bin");
        let source_sidecar = dir.join("old.bin.dfim");
        let original = vec![0x77; DFIM_BLOCK_SIZE];
        let old = vec![0x11; DFIM_BLOCK_SIZE];
        must(fs::write(&target, &original));
        must(fs::write(&target_sidecar, b"existing-state"));
        must(fs::write(&source, &old));
        must(fs::write(
            &source_sidecar,
            must(build_signed_boot_sidecar_v2(&old, &PRIVATE_KEY, KEY_ID, 4)),
        ));

        assert!(recover_target_atomically(&RecoveryRequest {
            target: &target,
            target_sidecar: &target_sidecar,
            recovery_image: &source,
            recovery_sidecar: &source_sidecar,
            policy: &policy(5),
        })
        .is_err());
        assert_eq!(must(fs::read(&target)), original);
        assert_eq!(must(fs::read(&target_sidecar)), b"existing-state");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    #[ignore = "explicit Phase-5 scalability/soak gate"]
    fn scalability_soak_recovers_many_assets() {
        let assets = std::env::var("DFIM_SOAK_ASSETS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(16);
        let cycles = std::env::var("DFIM_SOAK_CYCLES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(10);
        let dir = temp_dir("soak");
        let authorized = vec![0x5A; DFIM_BLOCK_SIZE];
        let sidecar = must(build_signed_boot_sidecar_v2(
            &authorized,
            &PRIVATE_KEY,
            KEY_ID,
            20,
        ));

        for asset in 0..assets {
            let target = dir.join(format!("protected-{asset}.bin"));
            let target_sidecar = dir.join(format!("protected-{asset}.bin.dfim"));
            let source = dir.join(format!("recovery-{asset}.bin"));
            let source_sidecar = dir.join(format!("recovery-{asset}.bin.dfim"));
            must(fs::write(&source, &authorized));
            must(fs::write(&source_sidecar, &sidecar));
            for cycle in 0..cycles {
                must(fs::write(&target, vec![cycle as u8; authorized.len()]));
                must(fs::write(&target_sidecar, b"invalid"));
                let report = must(recover_target_atomically(&RecoveryRequest {
                    target: &target,
                    target_sidecar: &target_sidecar,
                    recovery_image: &source,
                    recovery_sidecar: &source_sidecar,
                    policy: &policy(20),
                }));
                assert_eq!(report.restored_bytes, authorized.len());
            }
        }
        let _ = fs::remove_dir_all(dir);
    }
}
