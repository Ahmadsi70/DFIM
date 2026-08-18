#!/usr/bin/env bash
# Install native libraries required to compile dfim-provisioner with --features tpm on Linux.
set -euo pipefail

if grep -q $'\r' "$0" 2>/dev/null; then
    sed -i 's/\r$//' "$0"
    exec bash "$0" "$@"
fi

if [[ "$(id -u)" -ne 0 ]]; then
    exec sudo bash "$0" "$@"
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq pkg-config libtss2-dev

echo "[PASS] TPM build dependencies installed (libtss2-dev, pkg-config)"
