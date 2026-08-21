"""Validates DFIM Phase-6 durable telemetry and Collector controls."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "dfim_cli_provisioner/src/telemetry_sink.rs": {
        "schema_version",
        "event_type",
        "timestamp_unix_ms",
        "asset_id",
        "sha256_digest_chunked",
        ".create(true)",
        ".append(true)",
        "sync_all",
        "json_escape",
        "DFIM_TELEMETRY_OUT",
    },
    "dfim_cli_provisioner/src/verify.rs": {
        "EventType::VerifyV1",
        "EventType::VerifyV2",
        "Outcome::Success",
        "Outcome::Failure",
        "FAIL-CLOSED",
    },
    "dfim_cli_provisioner/src/main.rs": {
        "EventType::RecoveryV2",
        "release_counter",
        "merkle_root",
        "FAIL-CLOSED",
    },
    "test_environment/otel-collector/config.yaml": {
        "filelog/dfim_audit",
        "json_parser",
        "memory_limiter",
        "batch",
        "file_storage",
        "sending_queue",
        "retry_on_failure",
        "${env:DFIM_OTLP_ENDPOINT}",
        "${env:DFIM_TELEMETRY_OUT}",
        "${env:DFIM_OTEL_STORAGE_DIR}",
    },
    "docs/security/TELEMETRY.md": {
        "schema version 1",
        "Redaction",
        "Availability",
        "retention",
        "fail-closed",
        "beta",
    },
    "SECURITY.md": {"TELEMETRY.md", "JSONL", "OpenTelemetry"},
    ".github/workflows/ci.yml": {"verify_phase6_contract.py"},
}


def validate_required_controls() -> None:
    """Requires code, operations guidance, and CI to evolve as one security contract."""
    for relative_path, tokens in REQUIRED.items():
        path = ROOT / relative_path
        if not path.is_file():
            raise ValueError(f"missing Phase-6 control: {relative_path}")
        text = path.read_text(encoding="utf-8")
        folded_text = text.casefold()
        missing = sorted(token for token in tokens if token.casefold() not in folded_text)
        if missing:
            raise ValueError(f"{relative_path} missing tokens: {missing}")


def validate_no_rust_otel_dependency() -> None:
    """Keeps pre-stable Rust OTLP APIs outside the host audit trust boundary."""
    cargo_files = (ROOT / "Cargo.toml", ROOT / "dfim_cli_provisioner" / "Cargo.toml")
    for path in cargo_files:
        text = path.read_text(encoding="utf-8").lower()
        if "opentelemetry" in text:
            raise ValueError(f"Rust OpenTelemetry dependency forbidden in {path.relative_to(ROOT)}")


def validate_collector_secret_boundary() -> None:
    """Prevents example configuration from becoming a plaintext credential source."""
    path = ROOT / "test_environment" / "otel-collector" / "config.yaml"
    text = path.read_text(encoding="utf-8").lower()
    forbidden = ("password:", "api_key:", "authorization:", "insecure: true")
    present = sorted(token for token in forbidden if token in text)
    if present:
        raise ValueError(f"collector config contains forbidden settings: {present}")


def main() -> int:
    """Runs the Phase-6 contract as a dependency-free local and CI gate."""
    try:
        validate_required_controls()
        validate_no_rust_otel_dependency()
        validate_collector_secret_boundary()
    except (OSError, ValueError) as error:
        print(f"PHASE6-CONTRACT: FAIL: {error}", file=sys.stderr)
        return 1
    print("PHASE6-CONTRACT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
