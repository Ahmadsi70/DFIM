#!/usr/bin/env bash
# AT-07 CI gate: swtpm-backed enroll → quote → verify with replay rejection evidence.
set -euo pipefail

if grep -q $'\r' "$0" 2>/dev/null; then
  sed -i 's/\r$//' "$0"
  exec bash "$0" "$@"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${DFIM_AT07_ARTIFACTS:-${ROOT_DIR}/artifacts/at07-swtpm}"
TPMSTATE="${ARTIFACT_DIR}/tpmstate"
PROVISIONER="${ROOT_DIR}/target/release/dfim-provisioner"
SWTPM_PID=""

log() { printf '[AT07-SWTPM] %s\n' "$*"; }
fail() { printf '[AT07-SWTPM] FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [[ -n "${SWTPM_PID}" ]] && kill -0 "${SWTPM_PID}" 2>/dev/null; then
    kill "${SWTPM_PID}" 2>/dev/null || true
    wait "${SWTPM_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

require_env() {
  [[ -n "${DFIM_CRYPTO_KEY:-}" ]] || fail "DFIM_CRYPTO_KEY must be set"
  [[ "${#DFIM_CRYPTO_KEY}" -ge 16 ]] || fail "DFIM_CRYPTO_KEY must be at least 16 bytes"
}

install_runtime_deps() {
  if command -v swtpm >/dev/null && command -v tpm2_getcap >/dev/null; then
    return
  fi
  if [[ "$(id -u)" -ne 0 ]]; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq swtpm swtpm-tools tpm2-tools libtss2-tcti-swtpm0 libtss2-dev pkg-config
  else
    apt-get update -qq
    apt-get install -y -qq swtpm swtpm-tools tpm2-tools libtss2-tcti-swtpm0 libtss2-dev pkg-config
  fi
}

start_swtpm() {
  mkdir -p "${ARTIFACT_DIR}" "${TPMSTATE}"
  swtpm_setup --tpmstate "${TPMSTATE}" --tpm2 --create --overwrite
  swtpm socket \
    --tpmstate "dir=${TPMSTATE}" \
    --ctrl "type=unixio,path=${TPMSTATE}/swtpm.sock" \
    --tpm2 --daemon \
    --log "file=${ARTIFACT_DIR}/swtpm.log,level=20"
  export DFIM_TPM_TCTI="swtpm:host=127.0.0.1,port=2321"
  for _ in $(seq 1 30); do
    if tpm2_getcap properties-fixed -T "${DFIM_TPM_TCTI}" >/dev/null 2>&1; then
      log "swtpm ready via ${DFIM_TPM_TCTI}"
      return
    fi
    sleep 1
  done
  fail "swtpm did not become ready"
}

build_provisioner() {
  cd "${ROOT_DIR}"
  cargo build --locked --release -p dfim_cli_provisioner --features tpm
  [[ -x "${PROVISIONER}" ]] || fail "missing ${PROVISIONER}"
}

run_attestation_flow() {
  local nonce merkle ak_hex
  nonce="$(printf '11%.0s' {1..32})"
  merkle="$(printf 'a5%.0s' {1..32})"
  ak_hex="036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"

  "${PROVISIONER}" attestation-enroll \
    --private-blob "${ARTIFACT_DIR}/ak.private" \
    --public-blob "${ARTIFACT_DIR}/ak.public" \
    --ak-public-key "${ARTIFACT_DIR}/ak.pub"

  ak_hex="$(tr -d '\r\n' <"${ARTIFACT_DIR}/ak.pub")"

  "${PROVISIONER}" attestation-challenge \
    --nonce "${nonce}" \
    --release-counter 9 \
    --policy-generation 12 \
    --merkle-root "${merkle}" \
    --output "${ARTIFACT_DIR}/challenge.bin"

  dd if=/dev/zero of="${ARTIFACT_DIR}/pcrs.bin" bs=160 count=1 status=none

  "${PROVISIONER}" attestation-policy \
    --ak-public-key "${ak_hex}" \
    --minimum-release 8 \
    --policy-generation 12 \
    --merkle-root "${merkle}" \
    --pcr-values "${ARTIFACT_DIR}/pcrs.bin" \
    --output "${ARTIFACT_DIR}/policy.bin"

  "${PROVISIONER}" attestation-quote \
    --challenge "${ARTIFACT_DIR}/challenge.bin" \
    --private-blob "${ARTIFACT_DIR}/ak.private" \
    --public-blob "${ARTIFACT_DIR}/ak.public" \
    --output "${ARTIFACT_DIR}/evidence.bin"

  "${PROVISIONER}" attestation-verify \
    --challenge "${ARTIFACT_DIR}/challenge.bin" \
    --evidence "${ARTIFACT_DIR}/evidence.bin" \
    --policy "${ARTIFACT_DIR}/policy.bin"

  cp "${ARTIFACT_DIR}/evidence.bin" "${ARTIFACT_DIR}/evidence.replay.bin"

  "${PROVISIONER}" attestation-challenge \
    --nonce "$(printf '22%.0s' {1..32})" \
    --release-counter 9 \
    --policy-generation 12 \
    --merkle-root "${merkle}" \
    --output "${ARTIFACT_DIR}/challenge.replay.bin"

  if "${PROVISIONER}" attestation-verify \
    --challenge "${ARTIFACT_DIR}/challenge.replay.bin" \
    --evidence "${ARTIFACT_DIR}/evidence.replay.bin" \
    --policy "${ARTIFACT_DIR}/policy.bin"; then
    fail "replay evidence unexpectedly accepted"
  fi

  printf '{"qualify_case":"AT-07","outcome":"pass","tcti":"%s"}\n' "${DFIM_TPM_TCTI}" \
    >"${ARTIFACT_DIR}/at07-evidence.jsonl"
  log "wrote ${ARTIFACT_DIR}/at07-evidence.jsonl"
}

main() {
  require_env
  install_runtime_deps
  start_swtpm
  build_provisioner
  run_attestation_flow
  log "AT-07 swtpm gate PASS"
}

main "$@"
