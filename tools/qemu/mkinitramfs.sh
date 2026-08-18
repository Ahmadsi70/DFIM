#!/usr/bin/env bash
# Builds a minimal initramfs containing the static musl provisioner + guest runner.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${1:?work directory}"
PROVISIONER="${2:?path to dfim-provisioner musl binary}"
OUT_INITRD="${3:?output initramfs path}"

STAGING="${WORK}/initramfs_root"
rm -rf "${STAGING}"
mkdir -p "${STAGING}/dfim" "${STAGING}/host" "${STAGING}/bin" "${STAGING}/dev" "${STAGING}/proc" "${STAGING}/sys"

cp "${PROVISIONER}" "${STAGING}/dfim/dfim-provisioner"
chmod +x "${STAGING}/dfim/dfim-provisioner"
cp "${ROOT}/tools/qemu/guest_dfim_runner.sh" "${STAGING}/init"
chmod +x "${STAGING}/init"

# Minimal device nodes for init.
mknod -m 622 "${STAGING}/dev/console" c 5 1 2>/dev/null || true
mknod -m 666 "${STAGING}/dev/null" c 1 3 2>/dev/null || true

(
  cd "${STAGING}"
  find . | cpio -o -H newc 2>/dev/null | gzip -9 >"${OUT_INITRD}"
)

echo "initramfs -> ${OUT_INITRD} ($(wc -c <"${OUT_INITRD}") bytes)"
