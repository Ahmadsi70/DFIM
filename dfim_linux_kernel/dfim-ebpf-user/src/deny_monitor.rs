//! Reads kernel deny ring-buffer records and persists SIEM JSONL events.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::RingBuf;
use aya::Ebpf;
use dfim_core_engine::enforcement_policy::{DenyEventV1, EnforcementDecision};
use log::warn;

use crate::siem_sink::{emit_configured, SiemDenyEvent};

/// Starts a background thread that drains `DFIM_DENY_EVENTS` until `stop` is set.
pub fn spawn_deny_monitor(ebpf: &mut Ebpf, stop: Arc<AtomicBool>) -> Result<()> {
    let map = ebpf
        .take_map("DFIM_DENY_EVENTS")
        .context("DFIM_DENY_EVENTS ring buffer missing")?;
    let mut ring = RingBuf::try_from(map).context("open deny ring buffer")?;

    thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            while let Some(bytes) = ring.next() {
                if let Some(event) = parse_deny_event(&bytes) {
                    if let Err(error) = emit_configured(&event) {
                        warn!("SIEM deny sink fail-closed: {error}");
                    }
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
    Ok(())
}

fn parse_deny_event(bytes: &[u8]) -> Option<SiemDenyEvent> {
    if bytes.len() < core::mem::size_of::<DenyEventV1>() {
        return None;
    }
    let mut raw = [0u8; core::mem::size_of::<DenyEventV1>()];
    raw.copy_from_slice(&bytes[..core::mem::size_of::<DenyEventV1>()]);
    let record = bytemuck_must_read(&raw);
    let decision = match record.reason {
        3 => EnforcementDecision::DenyInvalidScope,
        4 => EnforcementDecision::DenyInvalidConfig,
        5 => EnforcementDecision::DenyStaleGeneration,
        _ => return None,
    };
    Some(SiemDenyEvent::from_enforcement_decision(
        record.device_id,
        record.inode,
        decision,
        record.policy_generation,
    ))
}

fn bytemuck_must_read(bytes: &[u8; core::mem::size_of::<DenyEventV1>()]) -> DenyEventV1 {
    let mut value = DenyEventV1 {
        device_id: 0,
        inode: 0,
        reason: 0,
        policy_generation: 0,
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            &mut value as *mut DenyEventV1 as *mut u8,
            core::mem::size_of::<DenyEventV1>(),
        );
    }
    value
}
