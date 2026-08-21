#!/usr/bin/env bash
# AT-08 destructive qualification planner — power interruption during host recovery.
set -euo pipefail

if grep -q $'\r' "$0" 2>/dev/null; then
  sed -i 's/\r$//' "$0"
  exec bash "$0" "$@"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${DFIM_AT08_ARTIFACTS:-${ROOT_DIR}/artifacts/qualify-at08}"
COMMIT="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)"

log() { printf '[AT08-QUALIFY] %s\n' "$*"; }
fail() { printf '[AT08-QUALIFY] FAIL: %s\n' "$*" >&2; exit 1; }

write_planner() {
  mkdir -p "${ARTIFACT_DIR}"
  cat >"${ARTIFACT_DIR}/at08-power-loss-plan.md" <<EOF
# AT-08 Power-Loss Qualification Plan

Commit: ${COMMIT}

## Preconditions

- Disposable VM with snapshot restore between runs.
- Authorized recovery image + DFIMBOOT v2 sidecar prepared offline.
- Protected target pair enrolled at release floor N.

## Procedure

1. Start \`recover-v2\` against the protected target.
2. During sidecar commit or image commit, force power loss (QEMU \`system_powerdown\` or physical PDU).
3. Restore power and boot.
4. Record one of:
   - Old pair still present and verifies, or
   - New pair present and verifies, or
   - Mismatched pair denies execution until authorized recovery repeats.

## Evidence bundle

- Console log with interruption timestamp
- \`dfim-provisioner verify-v2\` output before/after
- JSONL audit from \`DFIM_TELEMETRY_OUT\`
- This planner and \`at08-evidence.jsonl\`

Never run on production hosts.
EOF

  cat >"${ARTIFACT_DIR}/at08-evidence.jsonl" <<EOF
{"qualify_case":"AT-08","outcome":"manual","commit":"${COMMIT}","note":"destructive power-loss during recover-v2; see at08-power-loss-plan.md"}
EOF
}

run_unit_safety_net() {
  if ! command -v cargo >/dev/null; then
    log "cargo unavailable — skipping recovery unit safety net"
    return
  fi
  (
    cd "${ROOT_DIR}"
    export DFIM_CRYPTO_KEY="${DFIM_CRYPTO_KEY:-ci-only-dfim-key-material-2026}"
    cargo test -p dfim_cli_provisioner recovery::tests::recovery_rejects_rollback_without_touching_target -- --exact
  )
}

main() {
  write_planner
  run_unit_safety_net
  log "Planner written to ${ARTIFACT_DIR}"
  log "Complete destructive steps on lab hardware; attach evidence bundle"
}

main "$@"
