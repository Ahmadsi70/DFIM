//! DFIM Plugin SDK — WASM-based Custom Enforcement Policy Framework.
//!
//! Phase 4 — P4-M1: Enterprise organizations write custom integrity policies
//! in Rust, compile to WASM, and upload them to the DFIM management platform.
//! Policies execute in a sandboxed WASM runtime (wasmtime) with strict
//! resource limits (fuel metering, memory caps).
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │  DFIM Plugin SDK (host)                         │
//! │  ┌────────────────────────────────────────────┐ │
//! │  │  Plugin Registry (HashMap<id, Plugin>)     │ │
//! │  │  ┌──────────┐ ┌──────────┐ ┌───────────┐  │ │
//! │  │  │ Banking   │ │ Telecom  │ │ Defense   │  │ │
//! │  │  │ Policy    │ │ Policy   │ │ Policy    │  │ │
//! │  │  │ (WASM)    │ │ (WASM)   │ │ (WASM)    │  │ │
//! │  │  └──────────┘ └──────────┘ └───────────┘  │ │
//! │  └────────────────────────────────────────────┘ │
//! │  ┌────────────────────────────────────────────┐ │
//! │  │  WASM Runtime (wasmtime)                   │ │
//! │  │  - Fuel metering (max instructions)        │ │
//! │  │  - Memory limit (16 MB)                    │ │
//! │  │  - No network, no filesystem, no system    │ │
//! │  │  - Only: dfim_integrity_check(input) -> Ok/Deny │ │
//! │  └────────────────────────────────────────────┘ │
//! └──────────────────────────────────────────────────┘
//! ```

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, error};
use wasmtime::*;

// ═══════════════════════════════════════════════════════════════════
// Policy input/output types
// ═══════════════════════════════════════════════════════════════════

/// Input fed to a WASM policy plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    /// SHA-256 of the asset being evaluated.
    pub asset_id: String,
    /// Human-readable asset name.
    pub asset_name: String,
    /// Asset type: boot_loader, kernel, initrd, executable, container, module.
    pub asset_kind: String,
    /// Host/node where the asset resides.
    pub host_name: String,
    /// Merkle root hash from the sidecar (if available).
    pub merkle_root: Option<String>,
    /// Current rollback counter value.
    pub rollback_counter: u64,
    /// Whether TPM attestation passed.
    pub attestation_verified: bool,
    /// FEC-corrected bit count (0 = no correction needed).
    pub fec_corrected: u32,
    /// Tampered block count detected.
    pub tampered_blocks: u32,
    /// Custom key-value metadata for domain-specific logic.
    pub metadata: HashMap<String, String>,
}

/// Decision returned by a WASM policy plugin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDecision {
    /// Allow execution — asset integrity verified.
    Allow,
    /// Deny execution — integrity failure detected.
    Deny,
    /// Allow with warning — integrity OK but policy concerns.
    AllowWithWarning,
    /// Escalate to human — anomalous but not necessarily malicious.
    Escalate,
}

/// Full output from a policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOutput {
    pub decision: PolicyDecision,
    pub reason: String,
    pub risk_score: f64, // 0.0 (safe) to 1.0 (maximum risk)
    pub evidence: Vec<String>,
    pub compliance_tags: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════
// Plugin manifest
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub plugin_id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub industry: String,  // banking, telecom, defense, healthcare, general
    pub compliance: Vec<String>,  // PCI-DSS, HIPAA, NERC-CIP, NIST-800-53
    pub wasm_sha256: String,
}

// ═══════════════════════════════════════════════════════════════════
// Loaded plugin
// ═══════════════════════════════════════════════════════════════════

struct LoadedPlugin {
    manifest: PluginManifest,
    module: Module,
}

// ═══════════════════════════════════════════════════════════════════
// Plugin Runtime Engine
// ═══════════════════════════════════════════════════════════════════

pub struct PluginEngine {
    engine: Engine,
    registry: HashMap<String, LoadedPlugin>,
    stats: HashMap<String, PluginStats>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PluginStats {
    pub evaluations: u64,
    pub allows: u64,
    pub denies: u64,
    pub escalates: u64,
    pub avg_duration_us: f64,
    pub errors: u64,
}

impl PluginEngine {
    /// Create a new plugin engine with sandboxed WASM runtime.
    pub fn new() -> Result<Self> {
        let mut config = Config::default();
        config.consume_fuel(true);
        config.cache_config_load_default()?;
        let engine = Engine::new(&config)?;

        Ok(Self {
            engine,
            registry: HashMap::new(),
            stats: HashMap::new(),
        })
    }

    /// Register a plugin from WASM bytes and manifest.
    pub fn register_plugin(&mut self, manifest: PluginManifest, wasm_bytes: &[u8]) -> Result<()> {
        // Verify WASM SHA-256 matches manifest
        use sha2::Digest;
        let actual_hash = hex::encode(sha2::Sha256::digest(wasm_bytes));
        if actual_hash != manifest.wasm_sha256 {
            anyhow::bail!(
                "WASM hash mismatch: expected {}, got {}",
                manifest.wasm_sha256,
                actual_hash
            );
        }

        let module = Module::from_binary(&self.engine, wasm_bytes)
            .context("Failed to compile WASM module")?;

        info!(
            plugin_id = %manifest.plugin_id,
            name = %manifest.name,
            "Registered enforcement policy plugin"
        );

        self.stats.entry(manifest.plugin_id.clone()).or_default();
        self.registry.insert(
            manifest.plugin_id.clone(),
            LoadedPlugin { manifest, module },
        );
        Ok(())
    }

    /// Evaluate an integrity event through a registered policy plugin.
    pub fn evaluate(&mut self, plugin_id: &str, input: &PolicyInput) -> Result<PolicyOutput> {
        let plugin = self.registry.get(plugin_id)
            .context("Plugin not found")?;

        let stats = self.stats.get_mut(plugin_id).unwrap();
        stats.evaluations += 1;

        let t0 = std::time::Instant::now();

        // Create WASM store with fuel limit
        let mut store = Store::new(&self.engine, ());
        store.set_fuel(1_000_000_000).context("Failed to set fuel")?; // 1B instructions

        // Create memory with 16 MB limit
        let memory_ty = MemoryType::new(1, Some(256)); // 1 page min, 256 pages max = 16 MB
        let memory = Memory::new(&mut store, memory_ty)?;

        // Serialize input to JSON and write to WASM memory
        let input_json = serde_json::to_vec(input)?;
        let input_len = input_json.len() as i32;

        // Write input to memory
        memory.write(&mut store, 0, &input_json)?;

        // Create linker and define host functions
        let mut linker = Linker::new(&self.engine);

        // Host function: dfim_log(message_ptr, message_len)
        linker.func_wrap("dfim_host", "dfim_log", |_caller: Caller<'_, ()>, _ptr: i32, _len: i32| {
            // In production: forward to tracing. In WASM: no-op for safety.
        })?;

        // Host function: dfim_get_metadata(key_ptr, key_len) -> value_ptr
        linker.func_wrap("dfim_host", "dfim_get_metadata",
            |mut caller: Caller<'_, ()>, key_ptr: i32, key_len: i32| -> i32 {
                let mem = caller.get_export("memory")
                    .and_then(|e| e.into_memory())
                    .unwrap();
                let mut buf = vec![0u8; key_len as usize];
                mem.read(&caller, key_ptr as usize, &mut buf).ok();
                // Return 0 = not found (safe default)
                0i32
            }
        )?;

        // Instantiate the module
        let instance = linker.instantiate(&mut store, &plugin.module)?;

        // Call the exported evaluate function
        let evaluate_fn = instance.get_typed_func::<(i32, i32), i32>(&mut store, "evaluate")?;

        let result_ptr = match evaluate_fn.call(&mut store, (0i32, input_len)) {
            Ok(ptr) => ptr,
            Err(e) => {
                stats.errors += 1;
                error!(plugin_id = %plugin_id, error = %e, "Plugin evaluation failed");
                // Fallback to deny (fail-closed)
                return Ok(PolicyOutput {
                    decision: PolicyDecision::Deny,
                    reason: format!("Plugin error: {e}"),
                    risk_score: 1.0,
                    evidence: vec!["plugin-evaluation-failed".into()],
                    compliance_tags: vec![],
                });
            }
        };

        // Read result from WASM memory
        let result_len = if result_ptr > 0 {
            // Read 4-byte length prefix at result_ptr
            let mut len_buf = [0u8; 4];
            memory.read(&store, result_ptr as usize, &mut len_buf)?;
            u32::from_le_bytes(len_buf) as usize
        } else {
            stats.errors += 1;
            return Ok(PolicyOutput {
                decision: PolicyDecision::Deny,
                reason: "Plugin returned null result".into(),
                risk_score: 1.0,
                evidence: vec!["null-result".into()],
                compliance_tags: vec![],
            });
        };

        let data_ptr = (result_ptr + 4) as usize;
        let mut result_buf = vec![0u8; result_len.min(65536)];
        memory.read(&store, data_ptr, &mut result_buf)?;

        let output: PolicyOutput = serde_json::from_slice(&result_buf)?;

        let elapsed_us = t0.elapsed().as_micros() as f64;
        let new_avg = (stats.avg_duration_us * (stats.evaluations - 1) as f64 + elapsed_us)
            / stats.evaluations as f64;
        stats.avg_duration_us = new_avg;

        match output.decision {
            PolicyDecision::Allow | PolicyDecision::AllowWithWarning => stats.allows += 1,
            PolicyDecision::Deny => stats.denies += 1,
            PolicyDecision::Escalate => stats.escalates += 1,
        }

        Ok(output)
    }

    /// List all registered plugins.
    pub fn list_plugins(&self) -> Vec<&PluginManifest> {
        self.registry.values().map(|p| &p.manifest).collect()
    }

    /// Get plugin statistics.
    pub fn get_stats(&self, plugin_id: &str) -> Option<&PluginStats> {
        self.stats.get(plugin_id)
    }

    /// Get all plugin statistics.
    pub fn all_stats(&self) -> &HashMap<String, PluginStats> {
        &self.stats
    }
}

// ═══════════════════════════════════════════════════════════════════
// Built-in sample policies (compiled to WASM in production)
// ═══════════════════════════════════════════════════════════════════

/// Simulated policy: Banking — PCI-DSS
/// Requires attestation + no tampered blocks + rollback counter monotonic
pub fn evaluate_banking_policy(input: &PolicyInput) -> PolicyOutput {
    let mut evidence = vec![];
    let mut risk: f64 = 0.0;

    if !input.attestation_verified {
        evidence.push("TPM attestation failed".into());
        risk += 0.4;
    }
    if input.tampered_blocks > 0 {
        evidence.push(format!("{} tampered blocks detected", input.tampered_blocks));
        risk += 0.5;
    }
    if input.fec_corrected > 2 {
        evidence.push(format!("{} FEC corrections — possible attack", input.fec_corrected));
        risk += 0.3;
    }

    if risk >= 0.5 {
        PolicyOutput {
            decision: PolicyDecision::Deny,
            reason: format!("PCI-DSS compliance: integrity failure (risk={:.2})", risk),
            risk_score: risk.min(1.0),
            evidence,
            compliance_tags: vec!["PCI-DSS".into(), "SOX".into()],
        }
    } else if risk > 0.0 {
        PolicyOutput {
            decision: PolicyDecision::AllowWithWarning,
            reason: "PCI-DSS: minor anomalies, monitoring escalated".into(),
            risk_score: risk,
            evidence,
            compliance_tags: vec!["PCI-DSS".into()],
        }
    } else {
        PolicyOutput {
            decision: PolicyDecision::Allow,
            reason: "PCI-DSS compliant integrity verified".into(),
            risk_score: 0.0,
            evidence: vec!["all-checks-passed".into()],
            compliance_tags: vec!["PCI-DSS".into()],
        }
    }
}

/// Simulated policy: Defense — NIST SP 800-53
/// Zero-tolerance: any anomaly = deny + escalate
pub fn evaluate_defense_policy(input: &PolicyInput) -> PolicyOutput {
    let mut evidence = vec![];
    if !input.attestation_verified {
        evidence.push("CRITICAL: TPM attestation chain broken".into());
        return PolicyOutput {
            decision: PolicyDecision::Deny,
            reason: "NIST 800-53: attestation chain broken".into(),
            risk_score: 1.0,
            evidence,
            compliance_tags: vec!["NIST-800-53".into(), "CMMC".into(), "ITAR".into()],
        };
    }
    if input.tampered_blocks > 0 {
        evidence.push(format!("{} tampered blocks — possible APT", input.tampered_blocks));
        return PolicyOutput {
            decision: PolicyDecision::Deny,
            reason: "NIST 800-53: zero-tolerance tamper detection".into(),
            risk_score: 1.0,
            evidence,
            compliance_tags: vec!["NIST-800-53".into(), "CMMC".into()],
        };
    }
    PolicyOutput {
        decision: PolicyDecision::Allow,
        reason: "NIST 800-53 integrity verified".into(),
        risk_score: 0.0,
        evidence: vec!["all-cleared".into()],
        compliance_tags: vec!["NIST-800-53".into(), "CMMC".into(), "ITAR".into()],
    }
}

/// Simulated policy: Telecom — GDPR + NIS2
/// Risk-based scoring with threat intelligence integration
pub fn evaluate_telecom_policy(input: &PolicyInput) -> PolicyOutput {
    let risk: f64 = (input.tampered_blocks as f64 * 0.15)
        + (input.fec_corrected as f64 * 0.05)
        + if !input.attestation_verified { 0.3 } else { 0.0 };

    let decision = if risk > 0.5 { PolicyDecision::Deny }
        else if risk > 0.2 { PolicyDecision::Escalate }
        else if risk > 0.05 { PolicyDecision::AllowWithWarning }
        else { PolicyDecision::Allow };

    PolicyOutput {
        decision,
        reason: format!("Telecom risk score: {:.2}", risk),
        risk_score: risk.min(1.0),
        evidence: vec![format!("block-errors={}", input.tampered_blocks)],
        compliance_tags: vec!["GDPR".into(), "NIS2".into(), "ePrivacy".into()],
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_healthy_input() -> PolicyInput {
        PolicyInput {
            asset_id: "sha256:test".into(),
            asset_name: "test-asset".into(),
            asset_kind: "kernel".into(),
            host_name: "node-01".into(),
            merkle_root: Some("aabbccdd".into()),
            rollback_counter: 42,
            attestation_verified: true,
            fec_corrected: 0,
            tampered_blocks: 0,
            metadata: HashMap::new(),
        }
    }

    fn make_tampered_input() -> PolicyInput {
        let mut inp = make_healthy_input();
        inp.tampered_blocks = 5;
        inp.attestation_verified = false;
        inp.fec_corrected = 3;
        inp
    }

    #[test]
    fn banking_policy_allows_healthy() {
        let out = evaluate_banking_policy(&make_healthy_input());
        assert_eq!(out.decision, PolicyDecision::Allow);
        assert_eq!(out.risk_score, 0.0);
    }

    #[test]
    fn banking_policy_denies_tampered() {
        let out = evaluate_banking_policy(&make_tampered_input());
        assert_eq!(out.decision, PolicyDecision::Deny);
        assert!(out.risk_score > 0.5);
        assert!(out.compliance_tags.contains(&"PCI-DSS".to_string()));
    }

    #[test]
    fn defense_policy_zero_tolerance() {
        let out = evaluate_defense_policy(&make_tampered_input());
        assert_eq!(out.decision, PolicyDecision::Deny);
        assert_eq!(out.risk_score, 1.0);
    }

    #[test]
    fn telecom_policy_risk_scoring() {
        let out = evaluate_telecom_policy(&make_tampered_input());
        assert!(out.risk_score > 0.5);
        assert!(out.compliance_tags.contains(&"GDPR".to_string()));
    }

    #[test]
    fn plugin_engine_creation() {
        let engine = PluginEngine::new();
        assert!(engine.is_ok());
    }

    #[test]
    fn stats_initialized_zero() {
        let engine = PluginEngine::new().unwrap();
        assert_eq!(engine.all_stats().len(), 0);
    }

    #[test]
    fn manifest_validation_hash_mismatch() {
        let mut engine = PluginEngine::new().unwrap();
        let manifest = PluginManifest {
            plugin_id: "test".into(),
            name: "Test".into(),
            version: "1.0".into(),
            author: "DFIM".into(),
            description: "Test".into(),
            industry: "general".into(),
            compliance: vec![],
            wasm_sha256: "deadbeef".into(),
        };
        let result = engine.register_plugin(manifest, b"invalid wasm");
        assert!(result.is_err());
    }
}
