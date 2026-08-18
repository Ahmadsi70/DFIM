//! SIEM Connector Module — Phase 3 P3-M4
//!
//! Formats and delivers DFIM integrity events to enterprise SIEM platforms:
//!   - Splunk HTTP Event Collector (HEC)
//!   - Elastic Common Schema (ECS) v8.11
//!   - Microsoft Sentinel CEF (Common Event Format)
//!   - RFC 5424 Syslog with structured data (SD-ID: dfim@48577)
//!
//! Each connector implements a common trait for pluggable delivery.

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;

/// Supported SIEM output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SiemFormat {
    SplunkHec,
    ElasticEcs,
    SentinelCef,
    Rfc5424Syslog,
    Ndjson,
}

/// Core DFIM event that all SIEM formats derive from.
#[derive(Debug, Clone, Serialize)]
pub struct DfimSiemEvent {
    pub event_id: String,
    pub event_type: String,
    pub severity: String,  // critical, high, medium, low, info
    pub asset_id: String,
    pub message: String,
    pub host_name: String,
    pub timestamp: DateTime<Utc>,
    pub outcome: String,
    pub merkle_root: Option<String>,
    pub tampered_blocks: Option<u32>,
    pub fec_corrected: Option<u32>,
    pub rollback_counter: Option<u64>,
    pub attestation_verified: Option<bool>,
    pub enforcement_action: Option<String>,
}

/// Trait for SIEM format serializers.
pub trait SiemSerializer {
    fn format(&self) -> SiemFormat;
    fn serialize(&self, event: &DfimSiemEvent) -> String;
    fn content_type(&self) -> &'static str;
}

// ═══════════════════════════════════════════════════════════════════
// Splunk HEC
// ═══════════════════════════════════════════════════════════════════

pub struct SplunkHecSerializer;

impl SiemSerializer for SplunkHecSerializer {
    fn format(&self) -> SiemFormat { SiemFormat::SplunkHec }
    fn content_type(&self) -> &'static str { "application/json" }

    fn serialize(&self, event: &DfimSiemEvent) -> String {
        let ts = event.timestamp.timestamp_millis() as f64 / 1000.0;
        let body = serde_json::json!({
            "time": ts,
            "host": event.host_name,
            "source": "dfim://integrity",
            "sourcetype": format!("dfim:{}", event.event_type.replace('.', ":")),
            "index": "dfim_security",
            "event": {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "severity": event.severity,
                "asset_id": event.asset_id,
                "message": event.message,
                "outcome": event.outcome,
                "merkle_root": event.merkle_root,
                "tampered_blocks": event.tampered_blocks,
                "fec_corrected": event.fec_corrected,
                "rollback_counter": event.rollback_counter,
                "attestation_verified": event.attestation_verified,
                "enforcement_action": event.enforcement_action,
            }
        });
        serde_json::to_string(&body).unwrap_or_default()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Elastic ECS v8.11
// ═══════════════════════════════════════════════════════════════════

pub struct ElasticEcsSerializer;

impl SiemSerializer for ElasticEcsSerializer {
    fn format(&self) -> SiemFormat { SiemFormat::ElasticEcs }
    fn content_type(&self) -> &'static str { "application/json" }

    fn serialize(&self, event: &DfimSiemEvent) -> String {
        let severity_num = match event.severity.as_str() {
            "critical" => 9, "high" => 7, "medium" => 5, "low" => 3, _ => 1,
        };
        let body = serde_json::json!({
            "@timestamp": event.timestamp.to_rfc3339(),
            "ecs": {"version": "8.11.0"},
            "event": {
                "kind": "alert",
                "category": "intrusion_detection",
                "type": "change",
                "severity": severity_num,
                "action": event.event_type.replace("dfim.", "").replace('.', "_"),
                "outcome": event.outcome,
            },
            "host": {"name": event.host_name},
            "file": {
                "hash": {"sha256": event.asset_id.strip_prefix("sha256:").unwrap_or(&event.asset_id)},
                "integrity": {
                    "status": if event.outcome == "success" { "verified" } else { "tampered" },
                    "policy": "dfim-protected-scope",
                },
            },
            "dfim": {
                "event_id": event.event_id,
                "merkle_root": event.merkle_root,
                "tampered_blocks": event.tampered_blocks,
                "fec_corrected": event.fec_corrected,
                "rollback_counter": event.rollback_counter,
                "attestation_verified": event.attestation_verified,
                "enforcement_action": event.enforcement_action,
            },
            "message": event.message,
        });
        serde_json::to_string(&body).unwrap_or_default()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Microsoft Sentinel CEF
// ═══════════════════════════════════════════════════════════════════

pub struct SentinelCefSerializer;

impl SiemSerializer for SentinelCefSerializer {
    fn format(&self) -> SiemFormat { SiemFormat::SentinelCef }
    fn content_type(&self) -> &'static str { "text/plain" }

    fn serialize(&self, event: &DfimSiemEvent) -> String {
        let severity = match event.severity.as_str() {
            "critical" => 10, "high" => 8, "medium" => 5, "low" => 3, _ => 1,
        };
        let hash = event.asset_id.strip_prefix("sha256:").unwrap_or(&event.asset_id);
        let ts_ms = event.timestamp.timestamp_millis();

        let cef_template = format!(
            "CEF:0|DFIM|Firmware Integrity Matrix|0.1.0|{}|{}|{}|src=0.0.0.0 shost={} fileHash={} cs1={}.cs1Label=EnforcementAction cs2=NIST-800-193.cs2Label=ComplianceStandard cn1={}.cn1Label=TamperedBlockCount cn2={}.cn2Label=FecCorrectedCount start={} externalId={} msg={}",
            event.event_type.replace('.', "_").to_uppercase(),
            event.message,
            severity,
            event.host_name,
            hash,
            event.enforcement_action.as_deref().unwrap_or("block"),
            event.tampered_blocks.unwrap_or(0),
            event.fec_corrected.unwrap_or(0),
            ts_ms,
            event.event_id,
            event.message.replace('\\', "\\\\").replace('=', "\\="),
        );
        cef_template
    }
}

// ═══════════════════════════════════════════════════════════════════
// RFC 5424 Syslog
// ═══════════════════════════════════════════════════════════════════

pub struct Rfc5424SyslogSerializer;

impl SiemSerializer for Rfc5424SyslogSerializer {
    fn format(&self) -> SiemFormat { SiemFormat::Rfc5424Syslog }
    fn content_type(&self) -> &'static str { "text/plain" }

    fn serialize(&self, event: &DfimSiemEvent) -> String {
        let severity = match event.severity.as_str() {
            "critical" => 2, "high" => 4, "medium" => 5, "low" => 6, _ => 7,
        };
        let pri = 134 + severity; // facility 16 (local0) + severity
        let ts = event.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ");
        let sd = format!(
            "dfim@48577 event_type=\"{}\" severity=\"{}\" asset_id=\"{}\" \
             merkle_root=\"{}\" tampered_blocks=\"{}\" fec_corrected=\"{}\" \
             rollback_counter=\"{}\" attestation_verified=\"{}\"",
            event.event_type,
            event.severity,
            event.asset_id,
            event.merkle_root.as_deref().unwrap_or("-"),
            event.tampered_blocks.unwrap_or(0),
            event.fec_corrected.unwrap_or(0),
            event.rollback_counter.unwrap_or(0),
            event.attestation_verified.unwrap_or(false),
        );
        format!(
            "<{}>1 {} {} dfim-integrity {} ALERT [{}] {}",
            pri, ts, event.host_name, "12345",
            sd, event.message
        )
    }
}

// ═══════════════════════════════════════════════════════════════════
// NDJSON (newline-delimited JSON — default telemetry format)
// ═══════════════════════════════════════════════════════════════════

pub struct NdjsonSerializer;

impl SiemSerializer for NdjsonSerializer {
    fn format(&self) -> SiemFormat { SiemFormat::Ndjson }
    fn content_type(&self) -> &'static str { "application/x-ndjson" }

    fn serialize(&self, event: &DfimSiemEvent) -> String {
        serde_json::to_string(event).unwrap_or_default()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Factory
// ═══════════════════════════════════════════════════════════════════

pub fn get_serializer(format: SiemFormat) -> Box<dyn SiemSerializer> {
    match format {
        SiemFormat::SplunkHec => Box::new(SplunkHecSerializer),
        SiemFormat::ElasticEcs => Box::new(ElasticEcsSerializer),
        SiemFormat::SentinelCef => Box::new(SentinelCefSerializer),
        SiemFormat::Rfc5424Syslog => Box::new(Rfc5424SyslogSerializer),
        SiemFormat::Ndjson => Box::new(NdjsonSerializer),
    }
}

// ═══════════════════════════════════════════════════════════════════
// Batch delivery
// ═══════════════════════════════════════════════════════════════════

pub fn format_batch(serializer: &dyn SiemSerializer, events: &[DfimSiemEvent]) -> String {
    match serializer.format() {
        SiemFormat::Ndjson => {
            events.iter()
                .map(|e| serializer.serialize(e))
                .collect::<Vec<_>>()
                .join("\n")
        }
        _ => {
            let items: Vec<String> = events.iter()
                .map(|e| serializer.serialize(e))
                .collect();
            serde_json::to_string(&items).unwrap_or_default()
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event() -> DfimSiemEvent {
        DfimSiemEvent {
            event_id: "evt-001".into(), event_type: "dfim.integrity.failure".into(),
            severity: "critical".into(), asset_id: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".into(),
            message: "Boot image tampered".into(), host_name: "dfim-edge-01".into(),
            timestamp: Utc::now(), outcome: "failure".into(),
            merkle_root: Some("aabbccdd".into()), tampered_blocks: Some(3),
            fec_corrected: Some(1), rollback_counter: Some(42),
            attestation_verified: Some(true), enforcement_action: Some("block".into()),
        }
    }

    #[test]
    fn splunk_hec_output_contains_required_fields() {
        let s = SplunkHecSerializer;
        let out = s.serialize(&make_event());
        assert!(out.contains("\"host\""));
        assert!(out.contains("\"sourcetype\""));
        assert!(out.contains("\"tampered_blocks\""));
        assert!(out.contains("\"fec_corrected\""));
    }

    #[test]
    fn elastic_ecs_output_follows_ecs_schema() {
        let s = ElasticEcsSerializer;
        let out = s.serialize(&make_event());
        assert!(out.contains("\"ecs\""));
        assert!(out.contains("\"8.11.0\""));
        assert!(out.contains("\"dfim\""));
        assert!(out.contains("\"intrusion_detection\""));
    }

    #[test]
    fn sentinel_cef_output_has_cef_header() {
        let s = SentinelCefSerializer;
        let out = s.serialize(&make_event());
        assert!(out.starts_with("CEF:0|DFIM|"));
        assert!(out.contains("cs1Label=EnforcementAction"));
        assert!(out.contains("ComplianceStandard"));
    }

    #[test]
    fn rfc5424_output_has_structured_data() {
        let s = Rfc5424SyslogSerializer;
        let out = s.serialize(&make_event());
        assert!(out.contains("<"));
        assert!(out.contains("dfim@48577"));
        assert!(out.contains("merkle_root"));
        assert!(out.contains("rollback_counter"));
    }

    #[test]
    fn ndjson_output_is_valid_json() {
        let s = NdjsonSerializer;
        let out = s.serialize(&make_event());
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["event_type"], "dfim.integrity.failure");
    }

    #[test]
    fn format_batch_creates_5_events() {
        let s = NdjsonSerializer;
        let events: Vec<_> = (0..5).map(|i| {
            let mut e = make_event();
            e.event_id = format!("evt-{:03}", i);
            e
        }).collect();
        let batch = format_batch(&s, &events);
        let lines: Vec<_> = batch.lines().collect();
        assert_eq!(lines.len(), 5);
    }

    #[test]
    fn all_formats_serialize_without_error() {
        let event = make_event();
        for fmt in [SiemFormat::SplunkHec, SiemFormat::ElasticEcs, SiemFormat::SentinelCef, SiemFormat::Rfc5424Syslog, SiemFormat::Ndjson] {
            let s = get_serializer(fmt);
            let out = s.serialize(&event);
            assert!(!out.is_empty(), "Format {:?} produced empty output", fmt);
        }
    }
}
