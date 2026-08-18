#!/usr/bin/env bash
# Generate CycloneDX SBOM for the DFIM workspace (Telecom supply-chain assurance).
set -euo pipefail

# Self-heal CRLF when invoked from a Windows-mounted workspace (/mnt/c/...).
if grep -q $'\r' "$0" 2>/dev/null; then
    sed -i 's/\r$//' "$0"
    exec bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT="${SCRIPT_DIR}/bom.json"
PROVISIONER_BOM="${ROOT_DIR}/dfim_cli_provisioner/bom.json"

log_info() { printf '[INFO] %s\n' "$*"; }
log_pass() { printf '[PASS] %s\n' "$*"; }
log_fail() { printf '[FAIL] %s\n' "$*" >&2; }

on_error() {
    log_fail "SBOM generation aborted (exit $?)"
    exit 1
}
trap on_error ERR

log_info "DFIM CycloneDX SBOM pipeline"
log_info "Workspace root: ${ROOT_DIR}"

if ! command -v cargo >/dev/null 2>&1; then
    log_fail "cargo not found in PATH"
    exit 1
fi

if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
    log_info "cargo-cyclonedx not found — installing via cargo install"
    cargo install cargo-cyclonedx --locked
fi

cd "${ROOT_DIR}"

log_info "Generating workspace CycloneDX JSON SBOMs (cargo-cyclonedx 0.5.x API)"
cargo cyclonedx --format json --spec-version 1.5 --override-filename bom

if [[ ! -f "${PROVISIONER_BOM}" ]]; then
    log_fail "Expected provisioner SBOM missing: ${PROVISIONER_BOM}"
    exit 1
fi

cp "${PROVISIONER_BOM}" "${OUTPUT}"

if [[ ! -s "${OUTPUT}" ]]; then
    log_fail "Generated SBOM is empty: ${OUTPUT}"
    exit 1
fi

log_pass "CycloneDX SBOM validated at ${OUTPUT} ($(wc -c < "${OUTPUT}") bytes)"
