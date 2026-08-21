//! Machine-readable command results on stdout; human text stays on stderr.

use std::path::Path;

use dfim_core_engine::sha256_digest_chunked;

const ASSET_HASH_DOMAIN: &[u8] = b"dfim-asset-id-v1\0";

/// Selects stdout encoding while stderr retains operator-oriented text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) enum OutputFormat {
    #[default]
    Text,
    Json,
}

impl OutputFormat {
    /// Parses `--output` values without panicking on unknown tokens.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        match text {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(format!("unsupported output format: {other}")),
        }
    }
}

/// Fields shared by verify, provision, and recovery JSON responses.
pub(crate) struct CommandJsonReport {
    pub command: &'static str,
    pub outcome: &'static str,
    pub asset_id: String,
    pub merkle_root: Option<[u8; 32]>,
    pub release_counter: Option<u64>,
    pub blocks: Option<usize>,
    pub bytes: Option<usize>,
    pub dry_run: bool,
}

impl CommandJsonReport {
    /// Writes one JSON object to stdout for automation pipelines.
    pub(crate) fn write_stdout(&self) -> Result<(), String> {
        let mut line = String::with_capacity(256);
        line.push_str(r#"{"schema_version":1,"command":""#);
        line.push_str(self.command);
        line.push_str(r#"","outcome":""#);
        line.push_str(self.outcome);
        line.push_str(r#"","asset_id":""#);
        line.push_str(&json_escape(&self.asset_id));
        line.push('"');
        if let Some(blocks) = self.blocks {
            line.push_str(r#","blocks":"#);
            line.push_str(&blocks.to_string());
        }
        if let Some(bytes) = self.bytes {
            line.push_str(r#","bytes":"#);
            line.push_str(&bytes.to_string());
        }
        if let Some(release_counter) = self.release_counter {
            line.push_str(r#","release_counter":"#);
            line.push_str(&release_counter.to_string());
        }
        if let Some(merkle_root) = self.merkle_root {
            line.push_str(r#","merkle_root":""#);
            line.push_str(&hex_encode(&merkle_root));
            line.push('"');
        }
        if self.dry_run {
            line.push_str(r#","dry_run":true"#);
        }
        line.push_str("}\n");
        use std::io::Write;
        std::io::stdout()
            .write_all(line.as_bytes())
            .map_err(|error| format!("failed to write json output: {error}"))
    }
}

pub(crate) fn asset_id(path: &Path) -> String {
    let bytes = os_string_bytes(path.as_os_str());
    let digest = sha256_digest_chunked(&[ASSET_HASH_DOMAIN, &bytes]);
    format!("sha256:{}", hex_encode(&digest))
}

#[cfg(unix)]
fn os_string_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes().to_vec()
}

#[cfg(windows)]
fn os_string_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().flat_map(u16::to_le_bytes).collect()
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
    use std::path::PathBuf;

    #[test]
    fn json_report_serializes_verify_success_fields() {
        let report = CommandJsonReport {
            command: "verify_v1",
            outcome: "success",
            asset_id: asset_id(&PathBuf::from(r"C:\boot\image.efi")),
            merkle_root: Some([0xab; 32]),
            release_counter: None,
            blocks: Some(4),
            bytes: None,
            dry_run: false,
        };
        report.write_stdout().expect("stdout");
    }

    #[test]
    fn output_format_rejects_unknown_values() {
        assert!(OutputFormat::parse("yaml").is_err());
    }
}
