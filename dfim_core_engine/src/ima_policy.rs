//! Pure parsing contract for Linux IMA appraisal readiness evidence.

/// Evidence required before DFIM may attach production protected-scope enforcement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImaPolicyEvidence {
    pub enforce_mode: bool,
    pub signed_exec_appraisal: bool,
    pub signed_module_appraisal: bool,
}

impl ImaPolicyEvidence {
    /// Requires signed appraisal for both executable and kernel-module load paths.
    pub const fn is_production_ready(&self) -> bool {
        self.enforce_mode && self.signed_exec_appraisal && self.signed_module_appraisal
    }
}

/// Parses immutable kernel command-line and loaded IMA policy text without allocation.
pub fn inspect_ima_policy(cmdline: &str, policy: &str) -> ImaPolicyEvidence {
    let enforce_mode = cmdline
        .split_ascii_whitespace()
        .any(|token| token == "ima_appraise=enforce");
    let signed_exec_appraisal = policy
        .lines()
        .any(|line| is_signed_appraisal_rule(line, "BPRM_CHECK"));
    let signed_module_appraisal = policy
        .lines()
        .any(|line| is_signed_appraisal_rule(line, "MODULE_CHECK"));

    ImaPolicyEvidence {
        enforce_mode,
        signed_exec_appraisal,
        signed_module_appraisal,
    }
}

fn is_signed_appraisal_rule(line: &str, function: &str) -> bool {
    let mut is_appraise = false;
    let mut has_function = false;
    let mut has_signature_type = false;

    for token in line.split_ascii_whitespace() {
        if token.starts_with('#') {
            break;
        }
        if token == "appraise" {
            is_appraise = true;
        } else if token
            .strip_prefix("func=")
            .is_some_and(|value| value == function)
        {
            has_function = true;
        } else if token == "appraise_type=imasig" {
            has_signature_type = true;
        }
    }

    is_appraise && has_function && has_signature_type
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "\
appraise func=BPRM_CHECK appraise_type=imasig\n\
appraise func=MODULE_CHECK appraise_type=imasig\n";

    #[test]
    fn accepts_enforce_mode_with_exec_and_module_rules() {
        let evidence = inspect_ima_policy("quiet ima_appraise=enforce", POLICY);
        assert!(evidence.is_production_ready());
    }

    #[test]
    fn rejects_fix_mode() {
        let evidence = inspect_ima_policy("ima_appraise=fix", POLICY);
        assert!(!evidence.is_production_ready());
    }

    #[test]
    fn rejects_missing_exec_rule() {
        let evidence = inspect_ima_policy(
            "ima_appraise=enforce",
            "appraise func=MODULE_CHECK appraise_type=imasig",
        );
        assert!(!evidence.is_production_ready());
    }

    #[test]
    fn rejects_measure_only_rules() {
        let evidence = inspect_ima_policy(
            "ima_appraise=enforce",
            "measure func=BPRM_CHECK\nmeasure func=MODULE_CHECK",
        );
        assert!(!evidence.is_production_ready());
    }
}
