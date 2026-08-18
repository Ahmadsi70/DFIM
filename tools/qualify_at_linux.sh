#!/usr/bin/env bash
# Qualifies Linux runtime gates AT-01 through AT-04 on a disposable lab host.
set -euo pipefail

if grep -q $'\r' "$0" 2>/dev/null; then
  sed -i 's/\r$//' "$0"
  exec bash "$0" "$@"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${DFIM_QUALIFY_ARTIFACTS:-${ROOT_DIR}/artifacts/qualify-at}"
TELEMETRY_OUT="${DFIM_TELEMETRY_OUT:-${ARTIFACT_DIR}/dfim_audit.jsonl}"
COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)"

log() { printf '[QUALIFY-AT] %s\n' "$*"; }
fail() { printf '[QUALIFY-AT] FAIL: %s\n' "$*" >&2; exit 1; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    fail "AT qualification requires root (IMA/eBPF LSM attach)"
  fi
}

require_linux_lab() {
  [[ -r /sys/kernel/security/lsm ]] || fail "missing /sys/kernel/security/lsm"
  grep -q bpf /sys/kernel/security/lsm || fail "BPF LSM not enabled"
  [[ -r /sys/kernel/security/ima/policy ]] || fail "IMA not available"
  command -v dfim-ebpf-user >/dev/null 2>&1 || fail "dfim-ebpf-user not in PATH"
}

write_header() {
  mkdir -p "${ARTIFACT_DIR}"
  : >"${TELEMETRY_OUT}"
  export DFIM_TELEMETRY_OUT="${TELEMETRY_OUT}"
  log "artifact_dir=${ARTIFACT_DIR}"
  log "telemetry_out=${TELEMETRY_OUT}"
  log "commit=${COMMIT}"
}

record_case() {
  local case_id="$1"
  local outcome="$2"
  local note="$3"
  printf '{"schema_version":"1.0","qualify_case":"%s","outcome":"%s","commit":"%s","note":"%s"}\n' \
    "${case_id}" "${outcome}" "${COMMIT}" "${note}" >>"${ARTIFACT_DIR}/qualify-at-summary.jsonl"
}

run_at_01_post_enrollment_tamper() {
  log "AT-01: post-enrollment single-byte tamper (manual assist required)"
  record_case "AT-01" "manual" \
    "Provision protected asset, flip one byte, expect EPERM + dfim.integrity.failure or dfim.policy.deny in ${TELEMETRY_OUT}"
}

run_at_02_unprotected_availability() {
  log "AT-02: unprotected executable must not be denied by missing scope entry"
  record_case "AT-02" "manual" \
    "Launch unrelated binary while enforcement active; expect success without DFIM deny event for that inode"
}

run_at_03_metadata_removal() {
  log "AT-03: protected metadata removal keeps asset denied"
  record_case "AT-03" "manual" \
    "Delete sidecar/map without authorized unenroll; protected exec stays denied; unrelated assets run"
}

run_at_04_missing_config() {
  log "AT-04: malformed/missing DFIM_CONFIG denies protected only"
  record_case "AT-04" "manual" \
    "Clear DFIM_CONFIG slot with protected scope present; protected exec denied with DenyInvalidConfig; unprotected still runs"
}

main() {
  require_root
  require_linux_lab
  write_header
  run_at_01_post_enrollment_tamper
  run_at_02_unprotected_availability
  run_at_03_metadata_removal
  run_at_04_missing_config
  log "Wrote qualification planner to ${ARTIFACT_DIR}/qualify-at-summary.jsonl"
  log "Complete manual steps on lab host; attach JSONL + dmesg + audit.log to evidence bundle"
}

main "$@"
