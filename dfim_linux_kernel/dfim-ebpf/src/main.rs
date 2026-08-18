//! DFIM eBPF LSM probe — protected-scope policy gate layered with Linux IMA appraisal.

#![no_std]
#![no_main]

mod vmlinux;

use aya_ebpf::{
    macros::{lsm, map},
    maps::{Array, HashMap, RingBuf},
    programs::LsmContext,
};
use dfim_core_engine::enforcement_policy::{
    evaluate_enforcement, DenyEventV1, DfimConfigV1, EnforcementDecision, ScopeEntryV1, ScopeKey,
};
use vmlinux::{scope_key_from_bprm, scope_key_from_file};

/// Linux `-EPERM` — deny execution at Ring-0.
const DFIM_DENY: i32 = -1;

#[map]
static DFIM_SCOPE: HashMap<ScopeKey, ScopeEntryV1> = HashMap::with_max_entries(512, 0);

/// Versioned runtime policy; invalid state denies committed protected assets only.
#[map]
static DFIM_CONFIG: Array<DfimConfigV1> = Array::with_max_entries(1, 0);

/// Bounded deny telemetry consumed by userspace SIEM bridge.
#[map]
static DFIM_DENY_EVENTS: RingBuf = RingBuf::with_byte_size(8192, 0);

#[lsm(hook = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match try_bprm_check_security(ctx) {
        Ok(code) => code,
        Err(code) => code,
    }
}

#[lsm(hook = "kernel_module_from_file")]
pub fn kernel_module_from_file(ctx: LsmContext) -> i32 {
    match try_kernel_module_from_file(ctx) {
        Ok(code) => code,
        Err(code) => code,
    }
}

fn try_bprm_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let bprm = unsafe { ctx.arg::<usize>(0) as *const u8 };
    let key = match scope_key_from_bprm(bprm) {
        Some(value) => value,
        None => return Ok(0),
    };
    enforce_dfim_policy(key)
}

fn try_kernel_module_from_file(ctx: LsmContext) -> Result<i32, i32> {
    let file = unsafe { ctx.arg::<usize>(0) as *const u8 };
    let key = match scope_key_from_file(file) {
        Some(value) => value,
        None => return Ok(0),
    };
    enforce_dfim_policy(key)
}

#[inline(always)]
fn enforce_dfim_policy(key: ScopeKey) -> Result<i32, i32> {
    let scope = unsafe { DFIM_SCOPE.get(&key) };
    let config = DFIM_CONFIG.get(0);
    match evaluate_enforcement(scope, config) {
        EnforcementDecision::AllowUnprotected
        | EnforcementDecision::AllowPendingEnrollment
        | EnforcementDecision::AllowProtectedToIma => Ok(0),
        decision => {
            record_deny_event(&key, scope, config, decision);
            Err(DFIM_DENY)
        }
    }
}

#[inline(always)]
fn record_deny_event(
    key: &ScopeKey,
    scope: Option<&ScopeEntryV1>,
    config: Option<&DfimConfigV1>,
    decision: EnforcementDecision,
) {
    let generation = scope
        .map(|entry| entry.policy_generation)
        .or_else(|| config.map(|entry| entry.policy_generation))
        .unwrap_or(0);
    let event = DenyEventV1::from_decision(key.device_id, key.inode, decision, generation);
    if let Some(mut record) = DFIM_DENY_EVENTS.reserve::<DenyEventV1>(0) {
        unsafe {
            core::ptr::write(record.as_mut_ptr(), event);
        }
        record.submit(0);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // BPF verifier requires all CFG paths to terminate with exit/jmp — not unreachable_unchecked().
    loop {}
}
