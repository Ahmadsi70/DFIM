#!/usr/bin/env bash
# Reproducible DFIM production release — IEC 62443 supply-chain attestation pipeline.
set -euo pipefail

# Self-heal CRLF when invoked from a Windows-mounted workspace (/mnt/c/...).
if grep -q $'\r' "$0" 2>/dev/null; then
    sed -i 's/\r$//' "$0"
    exec bash "$0" "$@"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="${ROOT_DIR}/production_bundle"
BIN_DIR="${BUNDLE_DIR}/bin"
SBOM_DIR="${BUNDLE_DIR}/sbom"
CHECKSUM_FILE="${BUNDLE_DIR}/RELEASE_SHA256SUMS"

log_info() { printf '[INFO] %s\n' "$*"; }
log_pass() { printf '[PASS] %s\n' "$*"; }
log_fail() { printf '[FAIL] %s\n' "$*" >&2; }

on_error() {
    log_fail "Release build aborted (exit $?)"
    exit 1
}
trap on_error ERR

log_info "DFIM reproducible production release"
log_info "Workspace: ${ROOT_DIR}"

if [[ -z "${DFIM_CRYPTO_KEY:-}" ]]; then
    log_fail "DFIM_CRYPTO_KEY must be set (IEC 62443 CR 1.8). Example: export DFIM_CRYPTO_KEY=\"\$(openssl rand -hex 32)\""
    exit 1
fi

if [[ ${#DFIM_CRYPTO_KEY} -lt 16 ]]; then
    log_fail "DFIM_CRYPTO_KEY must be at least 16 bytes"
    exit 1
fi

if ! command -v cargo >/dev/null 2>&1; then
    log_fail "cargo not found in PATH"
    exit 1
fi

# Reproducibility constraints (deterministic timestamps, no incremental cache).
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-946684800}"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="${RUSTFLAGS:--C debuginfo=0 -C strip=symbols}"

cd "${ROOT_DIR}"

if ! command -v cargo-deny >/dev/null 2>&1; then
    log_info "Installing pinned cargo-deny 0.19.9"
    cargo install cargo-deny --version 0.19.9 --locked
fi

log_info "Enforcing dependency advisories, licenses, bans, and sources"
cargo deny check

log_info "Cleaning build cache"
cargo clean

log_info "Compiling production targets (release profile: LTO, strip, panic=abort)"
cargo build --locked --release -p dfim_cli_provisioner -p dfim-ebpf-user

PROVISIONER_SRC="${ROOT_DIR}/target/release/dfim-provisioner"
EBPF_USER_SRC="${ROOT_DIR}/target/release/dfim-ebpf-user"

if [[ ! -x "${PROVISIONER_SRC}" ]]; then
    log_fail "Missing release binary: ${PROVISIONER_SRC}"
    exit 1
fi
if [[ ! -x "${EBPF_USER_SRC}" ]]; then
    log_fail "Missing release binary: ${EBPF_USER_SRC}"
    exit 1
fi

log_info "Staging stripped binaries to ${BIN_DIR}"
rm -rf "${BUNDLE_DIR}"
mkdir -p "${BIN_DIR}" "${SBOM_DIR}"

cp "${PROVISIONER_SRC}" "${BIN_DIR}/dfim-provisioner"
cp "${EBPF_USER_SRC}" "${BIN_DIR}/dfim-ebpf-user"

if command -v strip >/dev/null 2>&1; then
    strip --strip-unneeded "${BIN_DIR}/dfim-provisioner" "${BIN_DIR}/dfim-ebpf-user"
fi

chmod 755 "${BIN_DIR}/dfim-provisioner" "${BIN_DIR}/dfim-ebpf-user"

if ! command -v cargo-cyclonedx >/dev/null 2>&1; then
    log_info "Installing pinned cargo-cyclonedx 0.5.9"
    cargo install cargo-cyclonedx --version 0.5.9 --locked
fi

log_info "Generating CycloneDX SBOM (spec 1.5)"
cargo cyclonedx --format json --spec-version 1.5 --override-filename bom

PROVISIONER_BOM="${ROOT_DIR}/dfim_cli_provisioner/bom.json"
EBPF_BOM="${ROOT_DIR}/dfim_linux_kernel/dfim-ebpf-user/bom.json"
CORE_BOM="${ROOT_DIR}/dfim_core_engine/bom.json"

for src in "${PROVISIONER_BOM}" "${EBPF_BOM}" "${CORE_BOM}"; do
    if [[ ! -s "${src}" ]]; then
        log_fail "Expected SBOM missing or empty: ${src}"
        exit 1
    fi
    cp "${src}" "${SBOM_DIR}/"
done

cp "${PROVISIONER_BOM}" "${BUNDLE_DIR}/SBOM.json"

log_info "Writing canonical SHA-256 integrity manifest"
(
    cd "${BUNDLE_DIR}"
    find . -type f ! -name 'RELEASE_SHA256SUMS' -print0 \
        | sort -z \
        | xargs -0 sha256sum
) > "${CHECKSUM_FILE}"

if [[ ! -s "${CHECKSUM_FILE}" ]]; then
    log_fail "RELEASE_SHA256SUMS is empty"
    exit 1
fi

log_pass "Release bundle: ${BUNDLE_DIR}"
log_pass "Binaries: dfim-provisioner ($(wc -c < "${BIN_DIR}/dfim-provisioner") bytes), dfim-ebpf-user ($(wc -c < "${BIN_DIR}/dfim-ebpf-user") bytes)"
log_pass "SBOM: ${BUNDLE_DIR}/SBOM.json"
log_pass "Integrity manifest: ${CHECKSUM_FILE} ($(wc -l < "${CHECKSUM_FILE}") entries)"

cat "${CHECKSUM_FILE}"
