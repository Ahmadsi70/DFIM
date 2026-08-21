#!/usr/bin/env bash
# Package attested UEFI release artifact (cross-platform build host).
set -euo pipefail

if grep -q $'\r' "$0" 2>/dev/null; then
  sed -i 's/\r$//' "$0"
  exec bash "$0" "$@"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="${DFIM_UEFI_DIST_DIR:-${ROOT_DIR}/dist-uefi}"
ARCHIVE="${DFIM_UEFI_ARCHIVE:-${ROOT_DIR}/dfim-uefi-x86_64.tar.gz}"
UEFI_TARGET="x86_64-unknown-uefi"

log() { printf '[UEFI-RELEASE] %s\n' "$*"; }
fail() { printf '[UEFI-RELEASE] FAIL: %s\n' "$*" >&2; exit 1; }

[[ -n "${DFIM_CRYPTO_KEY:-}" ]] || fail "DFIM_CRYPTO_KEY must be set"
[[ "${#DFIM_CRYPTO_KEY}" -ge 16 ]] || fail "DFIM_CRYPTO_KEY must be at least 16 bytes"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-946684800}"
export CARGO_INCREMENTAL=0

cd "${ROOT_DIR}"
rustup target add "${UEFI_TARGET}" >/dev/null 2>&1 || true

log "Building dfim_windows_uefi.efi (release)"
cargo build --locked --release \
  -p dfim_windows_uefi \
  --features uefi-app \
  --target "${UEFI_TARGET}"

EFI_SRC="${ROOT_DIR}/target/${UEFI_TARGET}/release/dfim_windows_uefi.efi"
[[ -f "${EFI_SRC}" ]] || fail "missing ${EFI_SRC}"

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"
install -m 0644 "${EFI_SRC}" "${DIST_DIR}/dfim_windows_uefi.efi"
install -m 0644 "${ROOT_DIR}/LICENSE" "${DIST_DIR}/LICENSE"
(
  cd "${DIST_DIR}"
  sha256sum dfim_windows_uefi.efi LICENSE > RELEASE_SHA256SUMS
)

tar \
  --sort=name \
  --mtime="@${SOURCE_DATE_EPOCH}" \
  --owner=0 --group=0 --numeric-owner \
  -czf "${ARCHIVE}" \
  -C "${DIST_DIR}" \
  LICENSE RELEASE_SHA256SUMS dfim_windows_uefi.efi

log "Packaged ${ARCHIVE}"
