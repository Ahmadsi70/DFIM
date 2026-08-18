#!/usr/bin/env bash
# Run DFIM Kani formal verification harness (IEC 62443 parser memory-safety proofs).
set -euo pipefail

if grep -q $'\r' "$0" 2>/dev/null; then
    sed -i 's/\r$//' "$0"
    exec bash "$0" "$@"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [[ -z "${DFIM_CRYPTO_KEY:-}" ]]; then
    echo "[FAIL] DFIM_CRYPTO_KEY must be set" >&2
    exit 1
fi

if ! command -v cargo-kani >/dev/null 2>&1; then
    echo "[INFO] Installing kani-verifier..."
    cargo install --locked kani-verifier
    cargo kani setup
fi

HARNESSES=(
    proof_integrity_gates_memory_safe
    proof_image_bounds_rejects_above_64k
    proof_parse_block_stream_memory_safe
    proof_parse_uefi_variable_memory_safe
    proof_layer0_parsers_unified_memory_safe
)

fail=0
for h in "${HARNESSES[@]}"; do
    echo "[INFO] Kani harness: $h"
    if cargo kani -p dfim_kani_proofs --harness "$h"; then
        echo "[PASS] $h"
    else
        echo "[FAIL] $h" >&2
        fail=1
    fi
done

exit "$fail"
