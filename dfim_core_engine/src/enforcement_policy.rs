//! Shared, verifier-friendly policy ABI for DFIM protected-scope enforcement.

/// Stable marker identifying a DFIM enforcement configuration map value.
pub const DFIM_CONFIG_MAGIC: u32 = u32::from_le_bytes(*b"DFIM");
/// First supported enforcement configuration schema.
pub const DFIM_CONFIG_SCHEMA_V1: u32 = 1;
/// Production profile that limits DFIM enforcement to explicitly enrolled assets.
pub const DFIM_PROFILE_PROTECTED_SCOPE: u32 = 1;
/// Configuration flag proving userspace completed policy initialization.
pub const DFIM_CONFIG_FLAG_ENFORCEMENT_READY: u32 = 1;
/// Scope entry is prepared but not yet visible as protected.
pub const DFIM_SCOPE_PENDING: u32 = 0;
/// Scope entry is committed and must fail closed on policy errors.
pub const DFIM_SCOPE_ACTIVE: u32 = 1;

/// Versioned userspace-to-eBPF configuration ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DfimConfigV1 {
    pub magic: u32,
    pub schema_version: u32,
    pub struct_size: u32,
    pub deployment_profile: u32,
    pub policy_generation: u64,
    pub flags: u32,
    pub reserved: u32,
}

impl DfimConfigV1 {
    /// Creates the only production configuration accepted by schema v1.
    pub const fn production(policy_generation: u64) -> Self {
        Self {
            magic: DFIM_CONFIG_MAGIC,
            schema_version: DFIM_CONFIG_SCHEMA_V1,
            struct_size: core::mem::size_of::<Self>() as u32,
            deployment_profile: DFIM_PROFILE_PROTECTED_SCOPE,
            policy_generation,
            flags: DFIM_CONFIG_FLAG_ENFORCEMENT_READY,
            reserved: 0,
        }
    }

    /// Rejects unknown layouts and any configuration that is not enforcement-ready.
    pub const fn is_production_ready(&self) -> bool {
        self.magic == DFIM_CONFIG_MAGIC
            && self.schema_version == DFIM_CONFIG_SCHEMA_V1
            && self.struct_size == core::mem::size_of::<Self>() as u32
            && self.deployment_profile == DFIM_PROFILE_PROTECTED_SCOPE
            && self.policy_generation != 0
            && self.flags & DFIM_CONFIG_FLAG_ENFORCEMENT_READY != 0
            && self.reserved == 0
    }
}

/// Filesystem-stable protected asset identity; inode alone can collide across devices.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeKey {
    pub device_id: u64,
    pub inode: u64,
}

/// Versioned protected-scope registry value published after metadata preparation.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeEntryV1 {
    pub policy_generation: u64,
    pub state: u32,
    pub reserved: u32,
    pub expected_merkle_root: [u8; 32],
}

impl ScopeEntryV1 {
    /// Creates an enrollment entry that is not yet enforced.
    pub const fn pending(policy_generation: u64, expected_merkle_root: [u8; 32]) -> Self {
        Self {
            policy_generation,
            state: DFIM_SCOPE_PENDING,
            reserved: 0,
            expected_merkle_root,
        }
    }

    /// Creates a committed protected-scope entry.
    pub const fn active(policy_generation: u64, expected_merkle_root: [u8; 32]) -> Self {
        Self {
            policy_generation,
            state: DFIM_SCOPE_ACTIVE,
            reserved: 0,
            expected_merkle_root,
        }
    }
}

/// Bounded decision result shared by unit tests and the eBPF probe.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnforcementDecision {
    AllowUnprotected = 0,
    AllowPendingEnrollment = 1,
    AllowProtectedToIma = 2,
    DenyInvalidScope = 3,
    DenyInvalidConfig = 4,
    DenyStaleGeneration = 5,
}

/// Ring-buffer record emitted when the LSM probe denies a protected asset.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DenyEventV1 {
    pub device_id: u64,
    pub inode: u64,
    pub reason: u32,
    pub policy_generation: u64,
}

impl DenyEventV1 {
    /// Builds a deny record from the shared enforcement decision enum.
    pub const fn from_decision(
        device_id: u64,
        inode: u64,
        decision: EnforcementDecision,
        policy_generation: u64,
    ) -> Self {
        Self {
            device_id,
            inode,
            reason: decision as u32,
            policy_generation,
        }
    }
}

/// Applies protected-scope semantics without attempting content validation in eBPF.
pub const fn evaluate_enforcement(
    scope: Option<&ScopeEntryV1>,
    config: Option<&DfimConfigV1>,
) -> EnforcementDecision {
    let Some(scope) = scope else {
        return EnforcementDecision::AllowUnprotected;
    };

    if scope.reserved != 0 || scope.policy_generation == 0 {
        return EnforcementDecision::DenyInvalidScope;
    }
    if scope.state == DFIM_SCOPE_PENDING {
        return EnforcementDecision::AllowPendingEnrollment;
    }
    if scope.state != DFIM_SCOPE_ACTIVE {
        return EnforcementDecision::DenyInvalidScope;
    }

    let Some(config) = config else {
        return EnforcementDecision::DenyInvalidConfig;
    };
    if !config.is_production_ready() {
        return EnforcementDecision::DenyInvalidConfig;
    }
    if config.policy_generation != scope.policy_generation {
        return EnforcementDecision::DenyStaleGeneration;
    }
    EnforcementDecision::AllowProtectedToIma
}

#[cfg(feature = "linux-loader")]
mod aya_pod {
    #![allow(unsafe_code)]

    use super::{DenyEventV1, DfimConfigV1, ScopeEntryV1, ScopeKey};
    use aya::Pod;

    // Justification:
    // - Why required: Aya requires Pod for exact map key/value byte transfer.
    // - Safety invariants: all types are Copy, repr(C), fixed-size, and contain no references.
    // - How invariants are enforced: ABI-size tests and explicit reserved fields freeze layout.
    // - Failure modes + mitigations: layout drift fails unit tests before loader/map deployment.
    // - Test coverage: enforcement_policy::tests::abi_sizes_are_stable.
    unsafe impl Pod for DfimConfigV1 {}
    unsafe impl Pod for ScopeKey {}
    unsafe impl Pod for ScopeEntryV1 {}
    unsafe impl Pod for DenyEventV1 {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_config(generation: u64) -> DfimConfigV1 {
        DfimConfigV1::production(generation)
    }

    fn active_scope(generation: u64) -> ScopeEntryV1 {
        ScopeEntryV1::active(generation, [0xAB; 32])
    }

    #[test]
    fn unprotected_asset_is_allowed_without_config() {
        assert_eq!(
            evaluate_enforcement(None, None),
            EnforcementDecision::AllowUnprotected
        );
    }

    #[test]
    fn protected_asset_denies_missing_config() {
        assert_eq!(
            evaluate_enforcement(Some(&active_scope(7)), None),
            EnforcementDecision::DenyInvalidConfig
        );
    }

    #[test]
    fn protected_asset_denies_unsupported_schema() {
        let mut config = ready_config(7);
        config.schema_version = DFIM_CONFIG_SCHEMA_V1 + 1;
        assert_eq!(
            evaluate_enforcement(Some(&active_scope(7)), Some(&config)),
            EnforcementDecision::DenyInvalidConfig
        );
    }

    #[test]
    fn protected_asset_denies_stale_policy_generation() {
        assert_eq!(
            evaluate_enforcement(Some(&active_scope(8)), Some(&ready_config(7))),
            EnforcementDecision::DenyStaleGeneration
        );
    }

    #[test]
    fn protected_asset_with_ready_config_delegates_content_to_ima() {
        assert_eq!(
            evaluate_enforcement(Some(&active_scope(7)), Some(&ready_config(7))),
            EnforcementDecision::AllowProtectedToIma
        );
    }

    #[test]
    fn pending_scope_is_not_committed_protection() {
        let scope = ScopeEntryV1::pending(7, [0xCD; 32]);
        assert_eq!(
            evaluate_enforcement(Some(&scope), Some(&ready_config(7))),
            EnforcementDecision::AllowPendingEnrollment
        );
    }

    #[test]
    fn malformed_scope_state_denies() {
        let mut scope = active_scope(7);
        scope.state = 99;
        assert_eq!(
            evaluate_enforcement(Some(&scope), Some(&ready_config(7))),
            EnforcementDecision::DenyInvalidScope
        );
    }

    #[test]
    fn abi_sizes_are_stable() {
        assert_eq!(core::mem::size_of::<DfimConfigV1>(), 32);
        assert_eq!(core::mem::size_of::<ScopeKey>(), 16);
        assert_eq!(core::mem::size_of::<ScopeEntryV1>(), 48);
        assert_eq!(core::mem::size_of::<DenyEventV1>(), 32);
    }
}
