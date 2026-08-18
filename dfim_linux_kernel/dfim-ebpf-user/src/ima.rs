//! Runtime gate proving Linux IMA signed appraisal is active before LSM attachment.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use dfim_core_engine::ima_policy::{inspect_ima_policy, ImaPolicyEvidence};

const PROC_CMDLINE: &str = "/proc/cmdline";
const IMA_POLICY: &str = "/sys/kernel/security/ima/policy";

/// Reads immutable kernel evidence and rejects production attachment without signed appraisal.
pub fn require_ima_appraisal() -> Result<ImaPolicyEvidence> {
    let cmdline = fs::read_to_string(PROC_CMDLINE).context("read /proc/cmdline for IMA mode")?;
    let policy = fs::read_to_string(IMA_POLICY).with_context(|| {
        format!(
            "read {IMA_POLICY}; mount securityfs and load signed IMA appraisal policy before DFIM"
        )
    })?;
    let evidence = inspect_ima_policy(&cmdline, &policy);
    if !evidence.is_production_ready() {
        anyhow::bail!(
            "IMA production appraisal is not ready: enforce_mode={} signed_exec={} signed_module={}",
            evidence.enforce_mode,
            evidence.signed_exec_appraisal,
            evidence.signed_module_appraisal
        );
    }
    Ok(evidence)
}

/// Re-reads a target after IMA readiness so applicable FILE_CHECK rules can reject bad signatures.
pub fn preflight_target_read(target: &Path) -> Result<()> {
    let _ = fs::read(target)
        .with_context(|| format!("IMA preflight read rejected target {}", target.display()))?;
    Ok(())
}
