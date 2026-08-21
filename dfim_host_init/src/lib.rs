//! Host-side initialization gates shared by Ring-3 DFIM binaries.
//!
//! Anchors a 30-day evaluation window to the first execution timestamp stored
//! in an authenticated binary state file (`.dfim_sys.dat`), with clock-rollback
//! detection via a monotonic last-execution watermark.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// Environment variable override for license state directory (deployment isolation).
pub const STATE_DIR_ENV: &str = "DFIM_STATE_DIR";

/// Hidden state file written beside the configured execution directory on first run.
pub const STATE_FILE_NAME: &str = ".dfim_sys.dat";

/// Evaluation period: 30 calendar days in seconds.
pub const EVAL_PERIOD_SECS: u64 = 30 * 24 * 60 * 60;

const STATE_MAGIC: [u8; 8] = *b"DFIMLIC\0";
const STATE_VERSION: u16 = 1;
const STATE_HEADER_LEN: usize = 28;
const STATE_INTEGRITY_LEN: usize = 32;
const STATE_FILE_LEN: usize = STATE_HEADER_LEN + STATE_INTEGRITY_LEN;

const INTEGRITY_DOMAIN: &[u8] = b"dfim-host-init-license-v1\0";

/// Exact vendor message emitted when the dynamic evaluation window has elapsed.
pub const EXPIRED_MESSAGE: &str = "CRITICAL: [DFIM-ERR-09] 30-Day Evaluation Period Expired. Please contact the vendor for a production license.";

/// Exact vendor message emitted when the system clock is rolled back or backdated.
pub const CLOCK_TAMPER_MESSAGE: &str =
    "SECURITY ALERT: [DFIM-ERR-10] System clock tampering detected. Execution terminated.";

/// Pair of Unix-epoch second counts persisted in `.dfim_sys.dat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LicenseState {
    /// Anchor set on first binary execution.
    pub activation_timestamp: u64,
    /// Highest observed execution time (monotonic watermark).
    pub last_execution_timestamp: u64,
}

/// Resolves the directory where `.dfim_sys.dat` is stored.
pub fn execution_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(STATE_DIR_ENV) {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(_) => PathBuf::from("."),
    }
}

/// Full path to the localized activation anchor file.
pub fn state_file_path() -> PathBuf {
    execution_dir().join(STATE_FILE_NAME)
}

/// Serializes license state into the authenticated on-disk header (pre-integrity tag).
pub fn encode_state_header(state: LicenseState) -> [u8; STATE_HEADER_LEN] {
    let mut header = [0u8; STATE_HEADER_LEN];
    header[0..8].copy_from_slice(&STATE_MAGIC);
    header[8..10].copy_from_slice(&STATE_VERSION.to_le_bytes());
    header[12..20].copy_from_slice(&state.activation_timestamp.to_le_bytes());
    header[20..28].copy_from_slice(&state.last_execution_timestamp.to_le_bytes());
    header
}

/// Deserializes license state from authenticated header bytes.
pub fn decode_state_header(
    header: &[u8; STATE_HEADER_LEN],
) -> Result<LicenseState, EvalLicenseError> {
    if header[0..8] != STATE_MAGIC {
        return Err(EvalLicenseError::StateUnreadable);
    }
    let version = u16::from_le_bytes([header[8], header[9]]);
    if version != STATE_VERSION {
        return Err(EvalLicenseError::StateUnreadable);
    }

    let mut activation_bytes = [0u8; 8];
    let mut last_exec_bytes = [0u8; 8];
    activation_bytes.copy_from_slice(&header[12..20]);
    last_exec_bytes.copy_from_slice(&header[20..28]);
    Ok(LicenseState {
        activation_timestamp: u64::from_le_bytes(activation_bytes),
        last_execution_timestamp: u64::from_le_bytes(last_exec_bytes),
    })
}

/// Computes SHA-256 integrity tag over the license header using a domain-separated prefix.
pub fn compute_state_integrity(header: &[u8; STATE_HEADER_LEN]) -> [u8; STATE_INTEGRITY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(INTEGRITY_DOMAIN);
    hasher.update(header);
    let digest = hasher.finalize();
    let mut out = [0u8; STATE_INTEGRITY_LEN];
    out.copy_from_slice(&digest);
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

/// Writes authenticated license state to disk.
pub fn write_state(path: &Path, state: LicenseState) -> std::io::Result<()> {
    let header = encode_state_header(state);
    let integrity = compute_state_integrity(&header);
    let mut file = [0u8; STATE_FILE_LEN];
    file[..STATE_HEADER_LEN].copy_from_slice(&header);
    file[STATE_HEADER_LEN..].copy_from_slice(&integrity);
    std::fs::write(path, file)
}

/// Reads and cryptographically validates persisted license state.
pub fn read_state(path: &Path) -> Result<LicenseState, EvalLicenseError> {
    let bytes = std::fs::read(path).map_err(|_| EvalLicenseError::StateUnreadable)?;
    if bytes.len() != STATE_FILE_LEN {
        return Err(EvalLicenseError::StateUnreadable);
    }
    if bytes.starts_with(b"STATE_") {
        return Err(EvalLicenseError::StateUnreadable);
    }

    let header: [u8; STATE_HEADER_LEN] = bytes[..STATE_HEADER_LEN]
        .try_into()
        .map_err(|_| EvalLicenseError::StateUnreadable)?;
    let stored: [u8; STATE_INTEGRITY_LEN] = bytes[STATE_HEADER_LEN..]
        .try_into()
        .map_err(|_| EvalLicenseError::StateUnreadable)?;

    let expected = compute_state_integrity(&header);
    if !constant_time_eq(&expected, &stored) {
        return Err(EvalLicenseError::StateUnreadable);
    }

    decode_state_header(&header)
}

/// Reads current system time as whole Unix seconds.
pub fn current_unix_secs() -> Result<u64, EvalLicenseError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| EvalLicenseError::ClockTampering)
}

/// Core license gate — first-run anchor, clock-tamper detection, 30-day expiry.
pub fn check_eval_license(now_secs: u64, path: &Path) -> Result<(), EvalLicenseError> {
    if path.exists() {
        let state = read_state(path)?;

        if now_secs < state.last_execution_timestamp {
            return Err(EvalLicenseError::ClockTampering);
        }
        if now_secs < state.activation_timestamp {
            return Err(EvalLicenseError::ClockTampering);
        }
        if now_secs.saturating_sub(state.activation_timestamp) > EVAL_PERIOD_SECS {
            return Err(EvalLicenseError::Expired);
        }

        write_state(
            path,
            LicenseState {
                activation_timestamp: state.activation_timestamp,
                last_execution_timestamp: now_secs,
            },
        )
        .map_err(|_| EvalLicenseError::StateUnreadable)?;

        Ok(())
    } else {
        let state = LicenseState {
            activation_timestamp: now_secs,
            last_execution_timestamp: now_secs,
        };
        write_state(path, state).map_err(|_| EvalLicenseError::StateUnreadable)?;
        Ok(())
    }
}

/// Host entry gate: evaluation window in dev builds; optional bypass for production packaging.
pub fn enforce_host_gate() {
    if !host_gate_required() {
        return;
    }
    enforce_eval_license();
}

/// Returns true when the dynamic evaluation license must still be enforced.
pub fn host_gate_required() -> bool {
    if production_build() {
        return false;
    }
    !matches!(
        std::env::var("DFIM_PRODUCTION").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    )
}

const fn production_build() -> bool {
    cfg!(feature = "production")
}

/// Blocks clock rollback and expired evaluation windows (development builds).
pub fn enforce_eval_license() {
    let path = state_file_path();
    let now = match current_unix_secs() {
        Ok(secs) => secs,
        Err(EvalLicenseError::ClockTampering) | Err(EvalLicenseError::StateUnreadable) => {
            eprintln!("{CLOCK_TAMPER_MESSAGE}");
            std::process::exit(1);
        }
        Err(EvalLicenseError::Expired) => {
            eprintln!("{EXPIRED_MESSAGE}");
            std::process::exit(1);
        }
    };

    match check_eval_license(now, &path) {
        Ok(()) => {}
        Err(EvalLicenseError::ClockTampering) | Err(EvalLicenseError::StateUnreadable) => {
            eprintln!("{CLOCK_TAMPER_MESSAGE}");
            std::process::exit(1);
        }
        Err(EvalLicenseError::Expired) => {
            eprintln!("{EXPIRED_MESSAGE}");
            std::process::exit(1);
        }
    }
}

/// Errors surfaced by [`check_eval_license`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalLicenseError {
    ClockTampering,
    Expired,
    StateUnreadable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_state_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("dfim_{label}_{}", std::process::id()))
    }

    #[test]
    fn production_env_disables_host_gate_requirement() {
        std::env::set_var("DFIM_PRODUCTION", "1");
        assert!(!host_gate_required());
        std::env::remove_var("DFIM_PRODUCTION");
    }

    #[test]
    fn integrity_tag_detects_header_tamper() {
        let state = LicenseState {
            activation_timestamp: 1_700_000_000,
            last_execution_timestamp: 1_700_000_100,
        };
        let mut header = encode_state_header(state);
        header[12] ^= 0x01;
        let mut file = [0u8; STATE_FILE_LEN];
        file[..STATE_HEADER_LEN].copy_from_slice(&header);
        file[STATE_HEADER_LEN..]
            .copy_from_slice(&compute_state_integrity(&encode_state_header(state)));
        let dir = temp_state_path("tamper");
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(STATE_FILE_NAME);
        fs::write(&path, file).expect("write");
        assert_eq!(read_state(&path), Err(EvalLicenseError::StateUnreadable));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn first_run_creates_authenticated_file() {
        let dir = temp_state_path("first");
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(STATE_FILE_NAME);
        let now = 3_000_000_u64;
        check_eval_license(now, &path).expect("first run");
        let bytes = fs::read(&path).expect("read");
        assert_eq!(bytes.len(), STATE_FILE_LEN);
        assert_eq!(&bytes[0..8], &STATE_MAGIC);
        let state = read_state(&path).expect("decode");
        assert_eq!(state.activation_timestamp, now);
        assert_eq!(state.last_execution_timestamp, now);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn success_updates_last_execution_watermark() {
        let dir = temp_state_path("watermark");
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(STATE_FILE_NAME);
        let activation = 3_000_000_u64;
        check_eval_license(activation, &path).expect("first");
        check_eval_license(activation + 3600, &path).expect("second");
        let state = read_state(&path).expect("read");
        assert_eq!(state.activation_timestamp, activation);
        assert_eq!(state.last_execution_timestamp, activation + 3600);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn clock_rollback_triggers_err10() {
        let dir = temp_state_path("rollback");
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(STATE_FILE_NAME);
        let t0 = 4_000_000_u64;
        check_eval_license(t0, &path).expect("seed");
        assert_eq!(
            check_eval_license(t0 - 1, &path),
            Err(EvalLicenseError::ClockTampering)
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn backdate_before_activation_triggers_err10() {
        let dir = temp_state_path("backdate");
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(STATE_FILE_NAME);
        write_state(
            &path,
            LicenseState {
                activation_timestamp: 5_000_000,
                last_execution_timestamp: 5_000_000,
            },
        )
        .expect("write");
        assert_eq!(
            check_eval_license(4_999_999, &path),
            Err(EvalLicenseError::ClockTampering)
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn expired_when_delta_exceeds_thirty_days() {
        let dir = temp_state_path("expired");
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(STATE_FILE_NAME);
        let activation = 1_000_000_u64;
        write_state(
            &path,
            LicenseState {
                activation_timestamp: activation,
                last_execution_timestamp: activation,
            },
        )
        .expect("write");
        assert_eq!(
            check_eval_license(activation + EVAL_PERIOD_SECS + 1, &path),
            Err(EvalLicenseError::Expired)
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn valid_on_day_thirty_boundary() {
        let dir = temp_state_path("boundary");
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(STATE_FILE_NAME);
        let activation = 2_000_000_u64;
        write_state(
            &path,
            LicenseState {
                activation_timestamp: activation,
                last_execution_timestamp: activation,
            },
        )
        .expect("write");
        assert!(check_eval_license(activation + EVAL_PERIOD_SECS, &path).is_ok());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_truncated_state_file() {
        let dir = temp_state_path("trunc");
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(STATE_FILE_NAME);
        fs::write(&path, [0u8; 8]).expect("write");
        assert_eq!(read_state(&path), Err(EvalLicenseError::StateUnreadable));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_plaintext_state_injection() {
        let dir = temp_state_path("plain");
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(STATE_FILE_NAME);
        fs::write(&path, b"STATE_HASH_CLOCK_VALID_A").expect("write");
        assert_eq!(read_state(&path), Err(EvalLicenseError::StateUnreadable));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_legacy_xor_state_blob() {
        let dir = temp_state_path("legacy");
        fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(STATE_FILE_NAME);
        fs::write(&path, [0x5A; 16]).expect("write");
        assert_eq!(read_state(&path), Err(EvalLicenseError::StateUnreadable));
        let _ = fs::remove_dir_all(dir);
    }
}
