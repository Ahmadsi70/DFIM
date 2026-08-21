"""Enforces Phase-9 Linux qualify, SIEM deny emit, and ops dashboard controls."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "dfim_core_engine/src/enforcement_policy.rs": {
        "DenyEventV1",
        "evaluate_enforcement",
        "DenyInvalidConfig",
        "AllowUnprotected",
    },
    "dfim_linux_kernel/dfim-ebpf/src/main.rs": {
        "DFIM_DENY_EVENTS",
        "record_deny_event",
        "DFIM_SCOPE",
        "DFIM_CONFIG",
        "bprm_check_security",
    },
    "dfim_linux_kernel/dfim-ebpf-user/src/siem_sink.rs": {
        "dfim.integrity.failure",
        "dfim.metadata.corrupt",
        "dfim.policy.deny",
        "DFIM_TELEMETRY_OUT",
        "sync_all",
        "emit_configured",
    },
    "dfim_linux_kernel/dfim-ebpf-user/src/deny_monitor.rs": {
        "DFIM_DENY_EVENTS",
        "spawn_deny_monitor",
        "parse_deny_event",
    },
    "dfim_linux_kernel/dfim-ebpf-user/src/main.rs": {
        "mod siem_sink",
        "mod deny_monitor",
        "spawn_deny_monitor",
        "siem_dfim_error",
    },
    "tools/qualify_at_linux.sh": {
        "AT-01",
        "AT-02",
        "AT-03",
        "AT-04",
        "DFIM_TELEMETRY_OUT",
        "qualify-at-summary.jsonl",
    },
    "docs/security/LINUX_QUALIFY.md": {
        "AT-01",
        "AT-04",
        "BTF",
        "IMA",
        "BPF LSM",
    },
    "test_environment/ops-stack/docker-compose.yml": {
        "grafana",
        "loki",
        "DFIM_TELEMETRY_OUT",
    },
    "test_environment/ops-stack/grafana/dashboards/dfim-ops.json": {
        "verify_v1",
        "dfim.policy.deny",
        "recovery_v2",
        "provision_v1",
    },
    "docs/security/TELEMETRY.md": {
        "dfim.integrity.failure",
        "dfim.metadata.corrupt",
        "dfim.policy.deny",
    },
    "test_environment/docs/ENTERPRISE_INTEGRATION.md": {
        "dfim.integrity.failure",
        "enforcement_layer",
        "action_taken",
    },
    ".github/workflows/ci.yml": {"verify_phase9_contract.py"},
}


def validate_required_controls() -> None:
    """Keeps Linux qualify artifacts coupled to SIEM deny implementation."""
    for relative_path, tokens in REQUIRED.items():
        path = ROOT / relative_path
        if not path.is_file():
            raise ValueError(f"missing Phase-9 control: {relative_path}")
        text = path.read_text(encoding="utf-8")
        folded = text.casefold()
        missing = sorted(token for token in tokens if token.casefold() not in folded)
        if missing:
            raise ValueError(f"{relative_path} missing tokens: {missing}")


def validate_no_legacy_manifest_map() -> None:
    """Protected-scope enforcement must not depend on legacy DFIM_MANIFESTS."""
    path = ROOT / "dfim_linux_kernel" / "dfim-ebpf" / "src" / "main.rs"
    text = path.read_text(encoding="utf-8")
    if "DFIM_MANIFESTS" in text:
        raise ValueError("eBPF probe must not reference legacy DFIM_MANIFESTS map")


def main() -> int:
    """Runs the Phase-9 contract as a dependency-free local and CI gate."""
    try:
        validate_required_controls()
        validate_no_legacy_manifest_map()
    except (OSError, ValueError) as error:
        print(f"PHASE9-CONTRACT: FAIL: {error}", file=sys.stderr)
        return 1
    print("PHASE9-CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
