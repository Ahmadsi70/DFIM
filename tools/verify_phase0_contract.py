"""Validates the machine-readable DFIM Phase-0 security contract and its audit documents."""

from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "security" / "phase0-policy.json"
DOCUMENTS = {
    ROOT / "docs" / "security" / "THREAT_MODEL.md": {
        "TM-01",
        "TM-02",
        "TM-03",
        "TM-04",
        "TM-05",
        "TM-06",
        "TM-07",
        "TM-08",
    },
    ROOT / "docs" / "security" / "ENFORCEMENT_POLICY.md": {
        "protected-scope",
        "IMA appraisal",
        "DFIM_CONFIG",
        "fail-closed",
    },
    ROOT / "docs" / "security" / "ADVERSARIAL_ACCEPTANCE.md": {
        "AT-01",
        "AT-02",
        "AT-03",
        "AT-04",
        "AT-05",
        "AT-06",
        "AT-07",
        "AT-08",
        "AT-09",
        "AT-10",
    },
}

REQUIRED_CONTROL_IDS = {
    "P0-C1",
    "P0-C2",
    "P0-C3",
    "P0-C4",
    "P0-C5",
    "P0-C6",
    "P0-C7",
    "P0-C8",
}


def fail(message: str) -> None:
    """Terminates validation with a concise, CI-friendly failure."""
    raise ValueError(message)


def validate_policy() -> None:
    """Ensures the policy freezes the approved Phase-0 security decisions."""
    if not POLICY.is_file():
        fail(f"missing policy: {POLICY.relative_to(ROOT)}")

    policy = json.loads(POLICY.read_text(encoding="utf-8"))
    expected = {
        "schema_version": 1,
        "deployment_profile": "protected-scope",
        "linux_content_enforcement": "ima-appraisal",
        "unprotected_asset_action": "allow",
        "protected_integrity_failure_action": "deny",
        "unknown_policy_state_action": "deny-protected-only",
    }
    for key, value in expected.items():
        if policy.get(key) != value:
            fail(f"policy field {key!r}: expected {value!r}, got {policy.get(key)!r}")

    controls = policy.get("controls")
    if not isinstance(controls, list):
        fail("policy controls must be a list")
    control_ids = {control.get("id") for control in controls if isinstance(control, dict)}
    missing = REQUIRED_CONTROL_IDS - control_ids
    if missing:
        fail(f"policy missing controls: {sorted(missing)}")


def validate_documents() -> None:
    """Checks that every auditable Phase-0 decision is represented in documentation."""
    for path, required_tokens in DOCUMENTS.items():
        if not path.is_file():
            fail(f"missing document: {path.relative_to(ROOT)}")
        text = path.read_text(encoding="utf-8")
        missing = {token for token in required_tokens if token not in text}
        if missing:
            fail(f"{path.relative_to(ROOT)} missing tokens: {sorted(missing)}")


def main() -> int:
    """Runs all Phase-0 contract checks for local and CI execution."""
    try:
        validate_policy()
        validate_documents()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"PHASE0-CONTRACT: FAIL: {error}", file=sys.stderr)
        return 1
    print("PHASE0-CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
