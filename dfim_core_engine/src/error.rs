/// Domain errors for the DFIM core engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DfimError {
    InvalidParameter,
    ParameterOverflow,
    BufferTooShort,
    BufferTooLong,
    UncorrectableError,
    CorruptMetadata,
    IntegrityFailure,
    WorkCapExceeded,
    EmptyInput,
}

impl DfimError {
    pub fn as_str(self) -> &'static str {
        match self {
            #[cfg(all(feature = "hardening", feature = "alloc"))]
            Self::InvalidParameter => crate::secrets::leak_lc(lc!("invalid parameter")),
            #[cfg(all(feature = "hardening", feature = "alloc"))]
            Self::ParameterOverflow => crate::secrets::leak_lc(lc!("parameter overflow")),
            #[cfg(all(feature = "hardening", feature = "alloc"))]
            Self::BufferTooShort => crate::secrets::leak_lc(lc!("buffer too short")),
            #[cfg(all(feature = "hardening", feature = "alloc"))]
            Self::BufferTooLong => crate::secrets::leak_lc(lc!("buffer too long")),
            #[cfg(all(feature = "hardening", feature = "alloc"))]
            Self::UncorrectableError => {
                crate::secrets::leak_lc(lc!("uncorrectable error detected"))
            }
            #[cfg(all(feature = "hardening", feature = "alloc"))]
            Self::CorruptMetadata => crate::secrets::leak_lc(lc!("corrupt metadata detected")),
            #[cfg(all(feature = "hardening", feature = "alloc"))]
            Self::IntegrityFailure => crate::secrets::leak_lc(lc!("integrity verification failed")),
            #[cfg(all(feature = "hardening", feature = "alloc"))]
            Self::WorkCapExceeded => crate::secrets::leak_lc(lc!("computation work cap exceeded")),
            #[cfg(all(feature = "hardening", feature = "alloc"))]
            Self::EmptyInput => crate::secrets::leak_lc(lc!("empty input")),
            #[cfg(not(all(feature = "hardening", feature = "alloc")))]
            Self::InvalidParameter => "invalid parameter",
            #[cfg(not(all(feature = "hardening", feature = "alloc")))]
            Self::ParameterOverflow => "parameter overflow",
            #[cfg(not(all(feature = "hardening", feature = "alloc")))]
            Self::BufferTooShort => "buffer too short",
            #[cfg(not(all(feature = "hardening", feature = "alloc")))]
            Self::BufferTooLong => "buffer too long",
            #[cfg(not(all(feature = "hardening", feature = "alloc")))]
            Self::UncorrectableError => "uncorrectable error detected",
            #[cfg(not(all(feature = "hardening", feature = "alloc")))]
            Self::CorruptMetadata => "corrupt metadata detected",
            #[cfg(not(all(feature = "hardening", feature = "alloc")))]
            Self::IntegrityFailure => "integrity verification failed",
            #[cfg(not(all(feature = "hardening", feature = "alloc")))]
            Self::WorkCapExceeded => "computation work cap exceeded",
            #[cfg(not(all(feature = "hardening", feature = "alloc")))]
            Self::EmptyInput => "empty input",
        }
    }
}

pub type DfimResult<T> = core::result::Result<T, DfimError>;
