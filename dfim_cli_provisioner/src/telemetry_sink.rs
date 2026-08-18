//! Durable, dependency-free security audit boundary for host CLI operations.

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use dfim_core_engine::sha256_digest_chunked;

const SCHEMA_VERSION: u8 = 1;
const ASSET_HASH_DOMAIN: &[u8] = b"dfim-asset-id-v1\0";

/// Security operation represented by the stable JSONL audit contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EventType {
    VerifyV1,
    VerifyV2,
    ProvisionV1,
    ProvisionV2,
    RecoveryV2,
}

impl EventType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::VerifyV1 => "verify_v1",
            Self::VerifyV2 => "verify_v2",
            Self::ProvisionV1 => "provision_v1",
            Self::ProvisionV2 => "provision_v2",
            Self::RecoveryV2 => "recovery_v2",
        }
    }
}

/// Command result used to derive severity without accepting arbitrary log text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Success,
    Failure,
}

impl Outcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }

    const fn severity(self) -> &'static str {
        match self {
            Self::Success => "info",
            Self::Failure => "error",
        }
    }
}

/// Typed fields prevent paths, errors, keys, and other unreviewed data entering audit records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TelemetryEvent {
    event_type: EventType,
    outcome: Outcome,
    timestamp_unix_ms: u128,
    asset_id: String,
    release_counter: Option<u64>,
    merkle_root: Option<[u8; 32]>,
    dry_run: bool,
}

impl TelemetryEvent {
    /// Builds a redacted security event so callers cannot accidentally serialize a raw asset path.
    pub(crate) fn security(
        event_type: EventType,
        outcome: Outcome,
        asset_path: &Path,
        release_counter: Option<u64>,
        merkle_root: Option<[u8; 32]>,
    ) -> Self {
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        Self {
            event_type,
            outcome,
            timestamp_unix_ms,
            asset_id: asset_id(asset_path.as_os_str()),
            release_counter,
            merkle_root,
            dry_run: false,
        }
    }

    /// Provision audit record; dry-run is explicit so SIEM can suppress write alerts.
    pub(crate) fn provision(
        event_type: EventType,
        outcome: Outcome,
        asset_path: &Path,
        release_counter: Option<u64>,
        merkle_root: Option<[u8; 32]>,
        dry_run: bool,
    ) -> Self {
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        Self {
            event_type,
            outcome,
            timestamp_unix_ms,
            asset_id: asset_id(asset_path.as_os_str()),
            release_counter,
            merkle_root,
            dry_run,
        }
    }

    fn to_json_line(&self) -> String {
        let mut output = String::with_capacity(320);
        output.push_str(r#"{"schema_version":"#);
        output.push_str(&SCHEMA_VERSION.to_string());
        output.push_str(r#","event_type":""#);
        output.push_str(self.event_type.as_str());
        output.push_str(r#"","severity":""#);
        output.push_str(self.outcome.severity());
        output.push_str(r#"","outcome":""#);
        output.push_str(self.outcome.as_str());
        output.push_str(r#"","timestamp_unix_ms":"#);
        output.push_str(&self.timestamp_unix_ms.to_string());
        output.push_str(r#","asset_id":""#);
        output.push_str(&json_escape(&self.asset_id));
        output.push('"');
        if let Some(release_counter) = self.release_counter {
            output.push_str(r#","release_counter":"#);
            output.push_str(&release_counter.to_string());
        }
        if let Some(merkle_root) = self.merkle_root {
            output.push_str(r#","merkle_root":""#);
            output.push_str(&hex_encode(&merkle_root));
            output.push('"');
        }
        if self.dry_run {
            output.push_str(r#","dry_run":true"#);
        }
        output.push_str("}\n");
        output
    }
}

/// Appends and synchronizes one complete record because acknowledged audit events must be durable.
pub(crate) fn append_event(path: &Path, event: &TelemetryEvent) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("cannot open telemetry sink: {error}"))?;
    file.write_all(event.to_json_line().as_bytes())
        .map_err(|error| format!("cannot append telemetry event: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("cannot synchronize telemetry sink: {error}"))
}

/// Emits only when explicitly configured; a configured sink is a fail-closed security boundary.
pub(crate) fn emit_configured(event: &TelemetryEvent) -> Result<(), String> {
    let Some(path) = std::env::var_os("DFIM_TELEMETRY_OUT") else {
        return Ok(());
    };
    append_event(Path::new(&path), event)
}

fn asset_id(path: &OsStr) -> String {
    let bytes = os_string_bytes(path);
    let digest = sha256_digest_chunked(&[ASSET_HASH_DOMAIN, &bytes]);
    format!("sha256:{}", hex_encode(&digest))
}

#[cfg(unix)]
fn os_string_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

#[cfg(windows)]
fn os_string_bytes(value: &OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>()
}

#[cfg(not(any(unix, windows)))]
fn os_string_bytes(value: &OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

fn json_escape(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control <= '\u{1f}' => {
                let value = control as usize;
                output.push_str("\\u00");
                output.push(HEX[value >> 4] as char);
                output.push(HEX[value & 0x0f] as char);
            }
            other => output.push(other),
        }
    }
    output
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn must<T, E: Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("telemetry fixture failed: {error:?}"),
        }
    }

    fn temp_path(label: &str) -> PathBuf {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "dfim-telemetry-{label}-{}-{sequence}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn audit_event_serializes_stable_schema_and_redacts_path() {
        let path = temp_path("schema");
        let asset = PathBuf::from(r#"C:\Users\Alice\secret "firmware".efi"#);
        let event = TelemetryEvent::security(
            EventType::VerifyV2,
            Outcome::Success,
            &asset,
            Some(42),
            Some([0xab; 32]),
        );

        must(append_event(&path, &event));
        let jsonl = must(fs::read_to_string(&path));

        assert!(jsonl.starts_with(
            r#"{"schema_version":1,"event_type":"verify_v2","severity":"info","outcome":"success","timestamp_unix_ms":"#
        ));
        assert!(jsonl.contains(r#","asset_id":"sha256:"#));
        assert!(jsonl.contains(r#","release_counter":42"#));
        assert!(jsonl.contains(&format!(r#","merkle_root":"{}""#, "ab".repeat(32))));
        assert!(!jsonl.contains("Alice"));
        assert!(!jsonl.contains("firmware"));
        assert!(jsonl.ends_with('\n'));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn provision_event_serializes_dry_run_flag() {
        let path = temp_path("provision");
        let asset = PathBuf::from("/boot/image.efi");
        let event = TelemetryEvent::provision(
            EventType::ProvisionV2,
            Outcome::Success,
            &asset,
            Some(7),
            Some([0xcd; 32]),
            true,
        );

        must(append_event(&path, &event));
        let jsonl = must(fs::read_to_string(&path));

        assert!(jsonl.contains(r#""event_type":"provision_v2""#));
        assert!(jsonl.contains(r#""release_counter":7"#));
        assert!(jsonl.contains(r#","dry_run":true"#));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn json_escape_handles_all_control_and_special_characters() {
        assert_eq!(
            json_escape("quote\" slash\\ line\n tab\t nul\u{0} unit\u{1f}"),
            r#"quote\" slash\\ line\n tab\t nul\u0000 unit\u001f"#
        );
    }

    #[test]
    fn append_preserves_existing_jsonl_records() {
        let path = temp_path("append");
        let asset = PathBuf::from("/boot/first");
        let first =
            TelemetryEvent::security(EventType::VerifyV1, Outcome::Failure, &asset, None, None);
        let second = TelemetryEvent::security(
            EventType::RecoveryV2,
            Outcome::Success,
            &asset,
            Some(7),
            None,
        );

        must(append_event(&path, &first));
        must(append_event(&path, &second));
        let jsonl = must(fs::read_to_string(&path));

        assert_eq!(jsonl.lines().count(), 2);
        assert!(jsonl
            .lines()
            .next()
            .is_some_and(|line| line.contains("verify_v1")));
        assert!(jsonl
            .lines()
            .nth(1)
            .is_some_and(|line| line.contains("recovery_v2")));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn configured_sink_is_fail_closed_when_append_fails() {
        let directory = std::env::temp_dir();
        let asset = PathBuf::from("/boot/asset");
        let event =
            TelemetryEvent::security(EventType::VerifyV1, Outcome::Success, &asset, None, None);

        assert!(append_event(&directory, &event).is_err());
    }
}
