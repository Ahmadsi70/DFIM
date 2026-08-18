//! Work-capping observer for loops exceeding 1000 iterations.

use crate::error::{DfimError, DfimResult};

/// Monitors iteration count and enforces a deterministic work cap.
///
/// /// [DFIM_AUDIT_LMT] Proof: [L=O(1) per tick, M=O(1), T=O(1)]
pub struct PatternObserver {
    max_iterations: usize,
    count: usize,
}

impl PatternObserver {
    /// Create an observer capped at `max_iterations`.
    pub fn new(max_iterations: usize) -> DfimResult<Self> {
        if max_iterations == 0 {
            return Err(DfimError::InvalidParameter);
        }
        Ok(Self {
            max_iterations,
            count: 0,
        })
    }

    /// Increment the counter; returns [`DfimError::WorkCapExceeded`] when over cap.
    pub fn tick(&mut self) -> DfimResult<()> {
        self.count = self.count.saturating_add(1);
        if self.count > self.max_iterations {
            return Err(DfimError::WorkCapExceeded);
        }
        Ok(())
    }

    pub const fn count(&self) -> usize {
        self.count
    }

    pub const fn max_iterations(&self) -> usize {
        self.max_iterations
    }

    pub fn reset(&mut self) {
        self.count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observer_exceeds_on_overflow() {
        let mut obs = PatternObserver::new(2).expect("create");
        assert!(obs.tick().is_ok());
        assert!(obs.tick().is_ok());
        assert_eq!(obs.tick(), Err(DfimError::WorkCapExceeded));
    }
}
