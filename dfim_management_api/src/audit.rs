//! Audit Logging — Phase 5 C10: Structured security audit trail
//!
//! Logs all mutating operations (POST, PUT, DELETE) to a durable JSONL file.
//! Format: {timestamp, user, tenant, action, resource, status, ip}
// Mutation handlers are not yet wired to call into this module.
#![allow(dead_code, clippy::too_many_arguments)]

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub user: String,
    pub tenant: String,
    pub action: String,   // POST, PUT, DELETE
    pub resource: String, // /v1/assets/xxx
    pub status: u16,
    pub ip: String,
    pub user_agent: String,
    pub duration_ms: f64,
}

pub struct AuditLogger {
    writer: Mutex<Box<dyn Write + Send>>,
}

impl AuditLogger {
    pub fn new(path: &Path) -> Result<Self, std::io::Error> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            writer: Mutex::new(Box::new(file)),
        })
    }

    pub fn to_stdout() -> Self {
        Self {
            writer: Mutex::new(Box::new(std::io::stdout())),
        }
    }

    pub fn log(&self, entry: &AuditEntry) {
        let mut w = self.writer.lock();
        if let Ok(json) = serde_json::to_string(entry) {
            let _ = writeln!(w, "{}", json);
            let _ = w.flush();
        }
    }
}

pub fn audit_mutation(
    logger: Arc<AuditLogger>,
    user: &str,
    tenant: &str,
    action: &str,
    resource: &str,
    status: u16,
    ip: IpAddr,
    user_agent: &str,
    duration_ms: f64,
) {
    let entry = AuditEntry {
        timestamp: Utc::now(),
        user: user.to_string(),
        tenant: tenant.to_string(),
        action: action.to_string(),
        resource: resource.to_string(),
        status,
        ip: ip.to_string(),
        user_agent: user_agent.to_string(),
        duration_ms,
    };
    logger.log(&entry);
}
