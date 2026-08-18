//! Durable JSONL deny events for Linux eBPF/IMA enforcement (Phase 9 SIEM bridge).

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use dfim_core_engine::enforcement_policy::EnforcementDecision;
use dfim_core_engine::sha256_digest_chunked;
use dfim_core_engine::DfimError;

const ASSET_HASH_DOMAIN: &[u8] = b"dfim-asset-id-v1\0";
const SCHEMA_VERSION: &str = "1.0";

/// Stable SIEM event names consumed by ENTERPRISE_INTEGRATION.md mappers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiemEventType {
    IntegrityFailure,
    MetadataCorrupt,
    PolicyDeny,
}

impl SiemEventType {
    const fn as_str(self) -> &'static str {
        match self {
            Self::IntegrityFailure => "dfim.integrity.failure",
            Self::MetadataCorrupt => "dfim.metadata.corrupt",
            Self::PolicyDeny => "dfim.policy.deny",
        }
    }

    const fn severity(self) -> &'static str {
        match self {
            Self::IntegrityFailure | Self::PolicyDeny => "critical",
            Self::MetadataCorrupt => "high",
        }
    }
}

/// Typed deny record — paths are hashed before persistence to match telemetry redaction.
pub struct SiemDenyEvent {
    pub event_type: SiemEventType,
    pub asset_id: String,
    pub enforcement_layer: &'static str,
    pub action_taken: &'static str,
    pub reason_code: Option<&'static str>,
    pub policy_generation: Option<u64>,
    pub device_id: Option<u64>,
    pub inode: Option<u64>,
    pub expected_merkle_root: Option<[u8; 32]>,
    pub calculated_merkle_root: Option<[u8; 32]>,
}

impl SiemDenyEvent {
    /// Live-vs-baseline Merkle mismatch detected during provision-time validation.
    pub fn integrity_mismatch(
        asset_path: &Path,
        expected_merkle_root: [u8; 32],
        calculated_merkle_root: [u8; 32],
    ) -> Self {
        Self {
            event_type: SiemEventType::IntegrityFailure,
            asset_id: asset_id(asset_path),
            enforcement_layer: "ebpf_lsm",
            action_taken: "deny",
            reason_code: Some("live_merkle_root_mismatch"),
            policy_generation: None,
            device_id: None,
            inode: None,
            expected_merkle_root: Some(expected_merkle_root),
            calculated_merkle_root: Some(calculated_merkle_root),
        }
    }

    /// Maps core parser errors to the enterprise SIEM taxonomy.
    pub fn from_dfim_error(asset_path: &Path, error: DfimError) -> Self {
        let event_type = match error {
            DfimError::CorruptMetadata | DfimError::UncorrectableError => {
                SiemEventType::MetadataCorrupt
            }
            DfimError::IntegrityFailure => SiemEventType::IntegrityFailure,
            _ => SiemEventType::IntegrityFailure,
        };
        Self {
            event_type,
            asset_id: asset_id(asset_path),
            enforcement_layer: "ebpf_lsm",
            action_taken: "deny",
            reason_code: Some(error.as_str()),
            policy_generation: None,
            device_id: None,
            inode: None,
            expected_merkle_root: None,
            calculated_merkle_root: None,
        }
    }

    /// Maps kernel policy denials surfaced through the deny ring buffer.
    pub fn from_enforcement_decision(
        device_id: u64,
        inode: u64,
        decision: EnforcementDecision,
        policy_generation: u64,
    ) -> Self {
        Self {
            event_type: SiemEventType::PolicyDeny,
            asset_id: asset_id_from_inode(device_id, inode),
            enforcement_layer: "ebpf_lsm",
            action_taken: "deny",
            reason_code: Some(decision_reason(decision)),
            policy_generation: Some(policy_generation),
            device_id: Some(device_id),
            inode: Some(inode),
            expected_merkle_root: None,
            calculated_merkle_root: None,
        }
    }

    fn to_json_line(&self) -> String {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        let correlation_id = format!("dfim-{timestamp_ms:x}");

        let mut line = String::with_capacity(384);
        line.push_str(r#"{"schema_version":""#);
        line.push_str(SCHEMA_VERSION);
        line.push_str(r#"","event_type":""#);
        line.push_str(self.event_type.as_str());
        line.push_str(r#"","severity":""#);
        line.push_str(self.event_type.severity());
        line.push_str(r#"","timestamp_unix_ms":"#);
        line.push_str(&timestamp_ms.to_string());
        line.push_str(r#","asset_id":""#);
        line.push_str(&json_escape(&self.asset_id));
        line.push_str(r#"","enforcement_layer":""#);
        line.push_str(self.enforcement_layer);
        line.push_str(r#"","action_taken":""#);
        line.push_str(self.action_taken);
        line.push('"');
        if let Some(reason) = self.reason_code {
            line.push_str(r#","reason_code":""#);
            line.push_str(&json_escape(reason));
            line.push('"');
        }
        if let Some(generation) = self.policy_generation {
            line.push_str(r#","policy_generation":"#);
            line.push_str(&generation.to_string());
        }
        if let Some(device_id) = self.device_id {
            line.push_str(r#","device_id":"#);
            line.push_str(&device_id.to_string());
        }
        if let Some(inode) = self.inode {
            line.push_str(r#","inode":"#);
            line.push_str(&inode.to_string());
        }
        if let Some(root) = self.expected_merkle_root {
            line.push_str(r#","expected_merkle_root":""#);
            line.push_str(&hex_encode(&root));
            line.push('"');
        }
        if let Some(root) = self.calculated_merkle_root {
            line.push_str(r#","calculated_merkle_root":""#);
            line.push_str(&hex_encode(&root));
            line.push('"');
        }
        line.push_str(r#","correlation_id":""#);
        line.push_str(&json_escape(&correlation_id));
        line.push_str("\"}\n");
        line
    }
}

/// Appends one deny record when `DFIM_TELEMETRY_OUT` is configured (fail-closed for callers).
pub fn emit_configured(event: &SiemDenyEvent) -> Result<(), String> {
    let Some(path) = std::env::var_os("DFIM_TELEMETRY_OUT") else {
        return Ok(());
    };
    append_event(Path::new(&path), event)
}

fn append_event(path: &Path, event: &SiemDenyEvent) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("cannot open SIEM sink: {error}"))?;
    file.write_all(event.to_json_line().as_bytes())
        .map_err(|error| format!("cannot append SIEM event: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("cannot synchronize SIEM sink: {error}"))
}

fn asset_id(path: &Path) -> String {
    let bytes = os_string_bytes(path.as_os_str());
    let digest = sha256_digest_chunked(&[ASSET_HASH_DOMAIN, &bytes]);
    format!("sha256:{}", hex_encode(&digest))
}

fn asset_id_from_inode(device_id: u64, inode: u64) -> String {
    let mut material = Vec::with_capacity(16);
    material.extend_from_slice(&device_id.to_le_bytes());
    material.extend_from_slice(&inode.to_le_bytes());
    let digest = sha256_digest_chunked(&[ASSET_HASH_DOMAIN, &material]);
    format!("sha256:{}", hex_encode(&digest))
}

const fn decision_reason(decision: EnforcementDecision) -> &'static str {
    match decision {
        EnforcementDecision::DenyInvalidScope => "DenyInvalidScope",
        EnforcementDecision::DenyInvalidConfig => "DenyInvalidConfig",
        EnforcementDecision::DenyStaleGeneration => "DenyStaleGeneration",
        _ => "DenyUnknown",
    }
}

#[cfg(unix)]
fn os_string_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

#[cfg(windows)]
fn os_string_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    value
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(not(any(unix, windows)))]
fn os_string_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    value.to_string_lossy().as_bytes().to_vec()
}

fn json_escape(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control <= '\u{1f}' => {
                let value = character as usize;
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
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn temp_path(label: &str) -> std::path::PathBuf {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "dfim-siem-{label}-{}-{sequence}.jsonl",
            std::process::id()
        ))
    }

    #[test]
    fn integrity_failure_serializes_redacted_asset_id() {
        let path = temp_path("integrity");
        let event = SiemDenyEvent::from_dfim_error(
            std::path::Path::new("/opt/guarded/app"),
            DfimError::IntegrityFailure,
        );
        append_event(&path, &event).expect("append");
        let jsonl = fs::read_to_string(&path).expect("read");
        assert!(jsonl.contains(r#""event_type":"dfim.integrity.failure""#));
        assert!(jsonl.contains(r#""severity":"critical""#));
        assert!(jsonl.contains(r#""asset_id":"sha256:"#));
        assert!(!jsonl.contains("/opt/guarded"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn policy_deny_maps_enforcement_decision_reason() {
        let event = SiemDenyEvent::from_enforcement_decision(
            9,
            42,
            EnforcementDecision::DenyInvalidConfig,
            7,
        );
        let line = event.to_json_line();
        assert!(line.contains(r#""event_type":"dfim.policy.deny""#));
        assert!(line.contains(r#""reason_code":"DenyInvalidConfig""#));
        assert!(line.contains(r#""policy_generation":7"#));
    }

    #[test]
    fn metadata_corrupt_uses_high_severity() {
        let event = SiemDenyEvent::from_dfim_error(
            std::path::Path::new("/boot/module.ko"),
            DfimError::CorruptMetadata,
        );
        let line = event.to_json_line();
        assert!(line.contains(r#""event_type":"dfim.metadata.corrupt""#));
        assert!(line.contains(r#""severity":"high""#));
    }
}
