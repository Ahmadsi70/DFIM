//! Active pipeline preconditions — replaces deprecated no-op opaque predicates.
//!
//! Every gate maps to a real invariant enforced by the DFIM Layer-0 engine.

use crate::{validate_block_count, validate_image_byte_len, DfimError, DfimResult};

/// Validates guarded image byte length against Layer-0 caps before Merkle work begins.
pub fn assert_image_bounds(image_len: usize) -> DfimResult<()> {
    validate_image_byte_len(image_len)
}

/// Validates block enumeration index stays within the manifest-declared block count.
pub fn assert_block_index(index: usize, block_count: u32) -> DfimResult<()> {
    validate_block_count(block_count)?;
    if index >= block_count as usize {
        return Err(DfimError::IntegrityFailure);
    }
    Ok(())
}

/// Validates host target path is non-empty and within representable bounds.
pub fn assert_target_path(path_component_len: usize) -> DfimResult<()> {
    if path_component_len == 0 {
        return Err(DfimError::InvalidParameter);
    }
    if path_component_len > u32::MAX as usize {
        return Err(DfimError::ParameterOverflow);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_IMAGE_BYTES;

    #[test]
    fn rejects_empty_path_gate() {
        assert_eq!(assert_target_path(0), Err(DfimError::InvalidParameter));
    }

    #[test]
    fn rejects_block_index_out_of_range() {
        assert_eq!(assert_block_index(4, 4), Err(DfimError::IntegrityFailure));
    }

    #[test]
    fn accepts_image_at_cap() {
        assert!(assert_image_bounds(MAX_IMAGE_BYTES).is_ok());
    }
}
