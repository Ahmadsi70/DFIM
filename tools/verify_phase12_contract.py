"""Enforces Phase-12 enterprise market readiness: RFP, compliance, pen-test, and SLA artifacts."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "docs/enterprise/RFP_RESPONSE_BUNDLE.md": {
        "### Q1.",
        "### Q20.",
        "Twenty procurement",
        "build_enterprise_sales_bundle.sh",
    },
    "docs/security/COMPLIANCE_MAPPING.md": {
        "ISO/IEC 27001",
        "telecommunications",
        "P0-C1",
        "Annex A",
    },
    "docs/security/PEN_TEST_SCOPE.md": {
        "Critical",
        "High",
        "attestation.rs",
        "recovery.rs",
    },
    "docs/enterprise/ENTERPRISE_SLA.md": {
        "P1",
        "100 ms",
        "24×7",
    },
    "docs/enterprise/PILOT_CASE_STUDY_TEMPLATE.md": {
        "90 days",
        "AT-01",
        "RTO",
    },
    "docs/enterprise/OPS_TRAINING_CURRICULUM.md": {
        "2 Days",
        "recover-v2",
        "DFIM_TELEMETRY_OUT",
    },
    "tools/build_enterprise_sales_bundle.sh": {
        "enterprise-bundle",
        "BUNDLE_MANIFEST.json",
        "RFP_RESPONSE_BUNDLE.md",
        "COMPLIANCE_MAPPING.md",
    },
    "docs/security/RELEASE_MATURITY.md": {
        "Phase 12",
        "pen-test",
        "enterprise",
    },
    "SECURITY.md": {
        "COMPLIANCE_MAPPING.md",
        "PEN_TEST_SCOPE.md",
        "RFP_RESPONSE_BUNDLE.md",
    },
    ".github/workflows/ci.yml": {
        "verify_phase12_contract.py",
        "build_enterprise_sales_bundle.sh",
    },
}


def validate_required_controls() -> None:
    """Requires sales and compliance docs to remain coupled to CI gates."""
    for relative_path, tokens in REQUIRED.items():
        path = ROOT / relative_path
        if not path.is_file():
            raise ValueError(f"missing Phase-12 control: {relative_path}")
        text = path.read_text(encoding="utf-8")
        folded = text.casefold()
        missing = sorted(token for token in tokens if token.casefold() not in folded)
        if missing:
            raise ValueError(f"{relative_path} missing tokens: {missing}")


def validate_rfp_question_count() -> None:
    """RFP bundle must contain exactly twenty numbered questions."""
    path = ROOT / "docs" / "enterprise" / "RFP_RESPONSE_BUNDLE.md"
    text = path.read_text(encoding="utf-8")
    questions = [line for line in text.splitlines() if line.startswith("### Q") and ". " in line]
    if len(questions) != 20:
        raise ValueError(f"RFP bundle must have 20 questions, found {len(questions)}")


def validate_bundle_script_manifest() -> None:
    """Bundle builder must list core enterprise documents."""
    script = (ROOT / "tools" / "build_enterprise_sales_bundle.sh").read_text(encoding="utf-8")
    for doc in (
        "docs/enterprise/RFP_RESPONSE_BUNDLE.md",
        "docs/enterprise/OFFLINE_REPORT.md",
        "docs/security/COMPLIANCE_MAPPING.md",
        "docs/security/PEN_TEST_SCOPE.md",
    ):
        if doc not in script:
            raise ValueError(f"build_enterprise_sales_bundle.sh missing {doc}")


def main() -> int:
    """Runs the Phase-12 contract as a dependency-free local and CI gate."""
    try:
        validate_required_controls()
        validate_rfp_question_count()
        validate_bundle_script_manifest()
    except (OSError, ValueError) as error:
        print(f"PHASE12-CONTRACT: FAIL: {error}", file=sys.stderr)
        return 1
    print("PHASE12-CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
